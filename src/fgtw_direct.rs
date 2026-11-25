//! Fleet direct paths: every way to reach a fleet peer WITHOUT the fgtw.org relay, tried before it.
//!
//! fgtw.org is the last rung. A dial races, best first:
//!
//! 0. **TCP to every published address** of the peer's direct server: its interface IPv4s (the LAN) and its IPv6 addresses (global IPv6 has no NAT, so it needs no punch).
//! 1. **KCP over UDP** to the peer's fleet UDP socket: the published addresses (interfaces, plus the router-mapped public port — `fgtw_portmap`), and a hole punch. The two ends trade [`CandidateOffer`]s over the relay pipe (a few hundred bytes; the one channel that works before any direct path exists) and fire signed probes at each other's addresses at once, so each NAT and stateful firewall opens toward the other. A probe's ack carries the address it arrived from.
//!
//! Only when nothing answers does the session ride the relay (`fgtw_pipe`). Every direct path runs the same fleet handshake (`Client::secure_connection_fleet`) as the relay: an address is never trusted.
//!
//! # Wire
//!
//! The host keeps ONE dual-stack UDP socket on the direct-server port number — the port the router maps and the fleet publishes. Two kinds of datagram arrive on it: signed probes (complete VSF files, `rd_probe` / `rd_probe_ack`, signed by the sender's device key, bound to the recipient and stamped) and KCP packets (rustdesk's own session, encrypted inside, opaque here like the relay's stream frames). A KCP session is opened only for a source address a current fleet member has just proven itself from with a probe.
//!
//! Published addresses ride the fleet's sealed device-settings map as `fgtw::phonebook` address sets (typed `ni`/`nj`/`np` sections), one per transport, in a `vb` value: `rustdesk.tcp` and `rustdesk.udp`.

#![cfg(feature = "fgtw")]

use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use fgtw::keys::Keypair;
use fgtw::phonebook::{AddrKind, SetAddr, ADDRESS_SET_MAX};
use fgtw::pipe::CandidateOffer;
use fgtw::traverse::gather::{classify_path, PathTier};
use hbb_common::{
    anyhow::anyhow,
    bail,
    bytes::BytesMut,
    config::Config,
    futures::{stream::FuturesUnordered, StreamExt},
    log,
    tokio::{self, net::UdpSocket, sync::mpsc},
    ResultType, Stream,
};
use vsf::VsfType;

use crate::client::Client;
use crate::kcp_stream::KcpStream;
use crate::server::{ConnectionMeta, ServerPtr};

/// Settings key: this device's direct-server (TCP) addresses, an address set.
pub const SETTING_TCP: &str = "rustdesk.tcp";
/// Settings key: this device's fleet UDP addresses, an address set.
pub const SETTING_UDP: &str = "rustdesk.udp";

/// A probe: "I am this device, reaching for that one".
const PROBE: &str = "rd_probe";
/// The answer to a probe: who answered, and the address the probe arrived from.
const ACK: &str = "rd_probe_ack";
/// How far a probe's stamp may sit from our clock, and how long a proven source stays vouched for: a replayed probe opens nothing for longer than this.
const VOUCH_SECS: u64 = 1 << 5;
/// Sources vouched for at once. A real host sees one per dialling peer; the oldest gives way.
const VOUCH_MAX: usize = 1 << 6;
/// Datagrams queued for one KCP session before the demux drops (KCP retransmits).
const SESSION_QUEUE: usize = 1 << 8;
/// Receive buffer: one datagram. A probe is a few hundred bytes, a KCP packet under the path MTU.
const DATAGRAM_MAX: usize = 1 << 11;

/// One TCP candidate's whole budget: connect plus the fleet handshake, which on the host fetches the chain. Generous because candidates race — a dead one costs nothing but its own slot.
const TCP_DIAL_MS: u64 = 1 << 12;
/// How long the punch fires before giving up, and its cadence.
const PUNCH_WINDOW_MS: u64 = 1 << 12;
const PUNCH_TICK_MS: u64 = 1 << 7;
/// How many rounds the host fires at a guest's offer, at the same cadence.
const SPRAY_ROUNDS: usize = 1 << 5;
/// KCP's connect / accept budget once a path is chosen.
const KCP_MS: u64 = 1 << 12;
/// Candidates start this far apart, best first, so on one LAN the LAN path wins before a WAN handshake even begins and the host does not see a needless second login race.
const STAGGER_MS: u64 = 1 << 8;

/// Where a peer said it can be reached directly.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PeerPaths {
    pub tcp: Vec<SocketAddr>,
    pub udp: Vec<SocketAddr>,
}

// ── this device's addresses ──

/// An IPv6 a peer could dial: router-assigned (global or ULA). Link-local needs a scope id no peer holds.
fn usable_v6(ip: Ipv6Addr) -> bool {
    !(ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() || (ip.segments()[0] & 0xffc0) == 0xfe80)
}

/// Every interface address a fleet peer could dial us at: IPv6 first (no NAT in the way), then each usable IPv4 (the LAN, or a public one an interface holds).
pub fn interface_ips() -> Vec<IpAddr> {
    let mut v6: Vec<IpAddr> = Vec::new();
    let mut v4: Vec<IpAddr> = Vec::new();
    for iface in default_net::get_interfaces() {
        for n in &iface.ipv6 {
            let ip = IpAddr::V6(n.addr);
            if usable_v6(n.addr) && !v6.contains(&ip) {
                v6.push(ip);
            }
        }
        for n in &iface.ipv4 {
            let ip = IpAddr::V4(n.addr);
            if fgtw::traverse::gather::is_usable_lan_ipv4(n.addr) && !v4.contains(&ip) {
                v4.push(ip);
            }
        }
    }
    v6.extend(v4);
    v6
}

/// This device's published paths, or `None` outside the hosting process: only the process that holds the fleet UDP socket (and its router mapping) knows the truth, so only it publishes — a UI process writing its partial view would erase the mapping.
pub fn own_paths() -> Option<PeerPaths> {
    let hub = HUB.get()?;
    let port = hub.port;
    let ips = interface_ips();
    let direct_off = Config::get_option(hbb_common::config::keys::OPTION_DIRECT_SERVER) == "N";
    let tcp_port = crate::rendezvous_mediator::get_direct_port() as u16;
    let tcp = if direct_off { Vec::new() } else { ips.iter().map(|ip| SocketAddr::new(*ip, tcp_port)).collect() };
    let mut udp: Vec<SocketAddr> = ips.iter().map(|ip| SocketAddr::new(*ip, port)).collect();
    if let Some(m) = crate::fgtw_portmap::current() {
        // Right after the IPv6s: the mapped port is the v4 path most peers can use.
        let at = udp.iter().take_while(|a| a.is_ipv6()).count();
        udp.insert(at, SocketAddr::V4(m));
    }
    Some(PeerPaths { tcp: capped(tcp), udp: capped(udp) })
}

/// WHY/PROOF: a machine's interface count is its own (containers, bridges, rotating IPv6 privacy addresses) and unbounded, while every reader refuses a set over `ADDRESS_SET_MAX` and `address_set_blob` panics on one. The best-first order means the cut drops the least useful.
fn capped(mut addrs: Vec<SocketAddr>) -> Vec<SocketAddr> {
    addrs.truncate(ADDRESS_SET_MAX);
    addrs
}

/// An address set as a settings value: the phonebook's typed set document, carried whole as a binary blob.
pub fn set_value(addrs: &[SocketAddr]) -> VsfType {
    let now = vsf::eagle_time_oscillations();
    let entries: Vec<SetAddr> = addrs
        .iter()
        .map(|a| SetAddr {
            addr: *a,
            kind: if crate::fgtw_portmap::current().map(SocketAddr::V4) == Some(*a) { AddrKind::Reflexive } else { AddrKind::Interface },
            seen: now,
        })
        .collect();
    VsfType::v(b'b', fgtw::phonebook::address_set_blob(&entries, now))
}

/// A settings value back to its addresses; `None` for anything that is not a verifying set.
pub fn set_from_value(v: &VsfType) -> Option<Vec<SocketAddr>> {
    match v {
        VsfType::v(b'b', blob) => Some(fgtw::phonebook::address_set_entries(blob)?.into_iter().map(|e| e.addr).collect()),
        _ => None,
    }
}

// ── addresses on a dual-stack socket ──

/// A dual-stack socket sees IPv4 peers as `::ffff:a.b.c.d`; the rest of the fork (sets, tiers, logs) speaks plain IPv4.
fn canon(a: SocketAddr) -> SocketAddr {
    match a {
        SocketAddr::V6(v6) => match v6.ip().to_ipv4_mapped() {
            Some(v4) => SocketAddr::new(IpAddr::V4(v4), v6.port()),
            None => a,
        },
        _ => a,
    }
}

/// The form a socket sends to and receives from: v4-mapped on an IPv6 socket.
fn wire(socket: &UdpSocket, a: SocketAddr) -> SocketAddr {
    match (socket.local_addr().map(|l| l.is_ipv6()).unwrap_or(false), a) {
        (true, SocketAddr::V4(v4)) => SocketAddr::new(IpAddr::V6(v4.ip().to_ipv6_mapped()), v4.port()),
        _ => a,
    }
}

/// One UDP socket for both families: IPv6 with v6-only off, else plain IPv4 when the host has no IPv6 stack at all.
fn bind_dual(port: u16) -> std::io::Result<std::net::UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};
    let s = match Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP)) {
        Ok(s) => {
            s.set_only_v6(false)?;
            s.bind(&SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port).into())?;
            s
        }
        Err(_) => {
            let s = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
            s.bind(&SocketAddr::from(([0, 0, 0, 0], port)).into())?;
            s
        }
    };
    s.set_nonblocking(true)?;
    Ok(s.into())
}

/// The connection label a path carries to the UI strip, on the shared fgtw ladder.
fn path_label(addr: &SocketAddr) -> &'static str {
    match classify_path(&canon(*addr), crate::fgtw_auth::our_lan_v4()) {
        PathTier::NoRouter => "FGTW-P2P",
        PathTier::Lan => "FGTW-LAN",
        _ => "FGTW-WAN",
    }
}

// ── signed probes ──

/// Is this datagram a signed VSF file (a probe or an ack) rather than a KCP packet? The header's magic decides; a KCP packet opens with its conversation id and never decodes as one.
pub fn is_signed_datagram(bytes: &[u8]) -> bool {
    vsf::file_format::VsfHeader::decode(bytes).is_ok()
}

fn probe(key: &Keypair, to: &[u8; 32]) -> Option<Vec<u8>> {
    let mut s = vsf::VsfSection::new(PROBE);
    s.add_field("to", VsfType::ke(to.to_vec()));
    fgtw::pq::signed_frame(s, key, vsf::eagle_time_oscillations()).ok()
}

fn ack(key: &Keypair, to: &[u8; 32], observed: SocketAddr) -> Option<Vec<u8>> {
    let mut s = vsf::VsfSection::new(ACK);
    s.add_field("to", VsfType::ke(to.to_vec()));
    s.add_field(
        "ip",
        match observed.ip() {
            IpAddr::V4(v4) => VsfType::ni(v4.octets()),
            IpAddr::V6(v6) => VsfType::nj(v6.octets()),
        },
    );
    s.add_field("port", VsfType::np(observed.port()));
    fgtw::pq::signed_frame(s, key, vsf::eagle_time_oscillations()).ok()
}

/// A probe or ack we heard: from which fleet device, and (an ack) where it saw us.
struct Heard {
    from: [u8; 32],
    is_probe: bool,
    observed: Option<SocketAddr>,
}

/// Read a probe or ack addressed to `me`: [`read_signal`], from a current member of our fleet.
fn hear(bytes: &[u8], me: &[u8; 32]) -> Option<Heard> {
    read_signal(bytes, me).filter(|h| is_member(&h.from))
}

/// A probe or ack addressed to `me`, whoever signed it. `None` unless it verifies under its signer's own key, is stamped within [`VOUCH_SECS`] of our clock, and names us.
/// The probe vouches for an ADDRESS only — the session that follows is held to the fleet's full handshake and floor — so the Ed25519 anchor is the check here, as for the pipe's open answer.
fn read_signal(bytes: &[u8], me: &[u8; 32]) -> Option<Heard> {
    let (header, _) = vsf::file_format::VsfHeader::decode(bytes).ok()?;
    let stamp = match &header.creation_time {
        Some(VsfType::e(et)) => fgtw::fleet::try_et_to_osc(et)?,
        _ => return None,
    };
    // WHY/PROOF: the stamp is peer-written; compared against a window around our clock (never subtracted from it), so an i64::MIN stamp cannot overflow.
    let skew = (VOUCH_SECS * vsf::OSCILLATIONS_PER_SECOND) as i64;
    let now = vsf::eagle_time_oscillations();
    if stamp < now - skew || stamp > now + skew {
        return None;
    }
    let (section, signer) = fgtw::pq::open_frame(bytes).ok()?;
    let is_probe = match section.name.as_str() {
        PROBE => true,
        ACK => false,
        _ => return None,
    };
    match section.get_field("to").and_then(|f| f.values.first()) {
        Some(VsfType::ke(k)) if k.as_slice() == me.as_slice() => {}
        _ => return None,
    }
    let observed = if is_probe {
        None
    } else {
        let ip = match section.get_field("ip").and_then(|f| f.values.first()) {
            Some(VsfType::ni(b)) => IpAddr::from(*b),
            Some(VsfType::nj(b)) => IpAddr::from(*b),
            _ => return None,
        };
        match section.get_field("port").and_then(|f| f.values.first()) {
            Some(VsfType::np(p)) => Some(SocketAddr::new(ip, *p)),
            _ => return None,
        }
    };
    Some(Heard { from: signer, is_probe, observed })
}

/// The fleet's members as the cached chain names them, re-read at most every [`VOUCH_SECS`]. WHY: anyone can mint a validly signed probe under a key of their own, so the membership check runs on attacker-chosen datagrams — folding the chain (every egg verified) per datagram would hand them our CPU.
fn is_member(device: &[u8; 32]) -> bool {
    static MEMBERS: Mutex<Option<(Instant, Vec<[u8; 32]>)>> = Mutex::new(None);
    let mut m = MEMBERS.lock().unwrap();
    if m.as_ref().map_or(true, |(at, _)| at.elapsed() >= Duration::from_secs(VOUCH_SECS)) {
        *m = Some((Instant::now(), crate::fgtw_auth::cached_members().unwrap_or_default()));
    }
    m.as_ref().is_some_and(|(_, members)| members.contains(device))
}

// ── the host's hub ──

/// The hosting process's fleet UDP socket and its demux.
struct Hub {
    socket: Arc<UdpSocket>,
    port: u16,
    key: Keypair,
    me: [u8; 32],
    /// Sources a fleet member just proved itself from, oldest first: the only addresses a KCP session opens for.
    vouched: Mutex<Vec<(SocketAddr, Instant)>>,
    /// Live KCP sessions, by source.
    sessions: Mutex<Vec<(SocketAddr, mpsc::Sender<BytesMut>)>>,
}

static HUB: OnceLock<Arc<Hub>> = OnceLock::new();

impl Hub {
    fn vouch(&self, from: SocketAddr) {
        let mut v = self.vouched.lock().unwrap();
        v.retain(|(a, at)| *a != from && at.elapsed() < Duration::from_secs(VOUCH_SECS));
        if v.len() >= VOUCH_MAX {
            v.remove(0);
        }
        v.push((from, Instant::now()));
    }

    fn is_vouched(&self, from: &SocketAddr) -> bool {
        self.vouched
            .lock()
            .unwrap()
            .iter()
            .any(|(a, at)| a == from && at.elapsed() < Duration::from_secs(VOUCH_SECS))
    }

    fn session(&self, from: &SocketAddr) -> Option<mpsc::Sender<BytesMut>> {
        self.sessions.lock().unwrap().iter().find(|(a, _)| a == from).map(|(_, tx)| tx.clone())
    }

    /// Fire probes at a dialling peer's offered addresses: our NAT and firewall open toward each, so its probes and its KCP get in, and our probes tell it which of our addresses work.
    async fn spray(self: Arc<Self>, to: [u8; 32], addrs: Vec<SocketAddr>) {
        let Some(p) = probe(&self.key, &to) else { return };
        for _ in 0..SPRAY_ROUNDS {
            for a in &addrs {
                let _ = self.socket.send_to(&p, wire(&self.socket, *a)).await;
            }
            tokio::time::sleep(Duration::from_millis(PUNCH_TICK_MS)).await;
        }
    }

    async fn pump(self: Arc<Self>, server: ServerPtr) {
        let mut buf = vec![0u8; DATAGRAM_MAX];
        loop {
            let (n, from) = match self.socket.recv_from(&mut buf).await {
                Ok(r) => r,
                Err(e) => {
                    // A UDP socket reports a peer's ICMP unreachable as a receive error on some platforms; the socket itself is fine.
                    log::debug!("fgtw direct: recv: {e}");
                    continue;
                }
            };
            let datagram = &buf[..n];
            if is_signed_datagram(datagram) {
                if let Some(h) = hear(datagram, &self.me) {
                    self.vouch(from);
                    if h.is_probe {
                        if let Some(a) = ack(&self.key, &h.from, canon(from)) {
                            let _ = self.socket.send_to(&a, from).await;
                        }
                    }
                }
                continue;
            }
            if let Some(tx) = self.session(&from) {
                let _ = tx.try_send(BytesMut::from(datagram));
                continue;
            }
            if !self.is_vouched(&from) {
                continue;
            }
            let (tx, rx) = mpsc::channel(SESSION_QUEUE);
            let _ = tx.try_send(BytesMut::from(datagram));
            self.sessions.lock().unwrap().push((from, tx));
            let hub = self.clone();
            let server = server.clone();
            tokio::spawn(async move {
                match KcpStream::accept_via(hub.socket.clone(), from, rx, Duration::from_millis(KCP_MS)).await {
                    Ok((guard, stream)) => {
                        log::info!("fgtw direct: fleet peer over UDP from {}", canon(from));
                        if let Err(e) = crate::server::create_tcp_connection(server, stream, canon(from), true, ConnectionMeta::default()).await {
                            log::warn!("fgtw direct: UDP session from {} failed: {e}", canon(from));
                        }
                        drop(guard);
                    }
                    Err(e) => log::info!("fgtw direct: no KCP session from {}: {e}", canon(from)),
                }
                hub.sessions.lock().unwrap().retain(|(a, _)| *a != from);
            });
        }
    }
}

/// Host side: the fleet UDP socket, beside the direct server and the relay accept loop. Binds the direct-server port number, holds a router mapping for it, and accepts KCP sessions from fleet members that proved their address.
pub async fn serve(server: ServerPtr) {
    while !crate::fgtw_pipe::enabled() {
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
    let port = crate::rendezvous_mediator::get_direct_port() as u16;
    // A server restarting while its predecessor still holds the port is the usual reason a bind fails; it frees within moments, so keep asking.
    let mut said = false;
    let socket = loop {
        match bind_dual(port).and_then(UdpSocket::from_std) {
            Ok(s) => break Arc::new(s),
            Err(e) => {
                if !said {
                    log::warn!("fgtw direct: cannot bind the fleet UDP socket on {port}: {e} — peers reach this host over TCP and the relay until it binds");
                    said = true;
                }
                tokio::time::sleep(Duration::from_secs(1 << 4)).await;
            }
        }
    };
    let key = match crate::fgtw_auth::device_keypair() {
        Ok(k) => k,
        Err(e) => {
            log::warn!("fgtw direct: no device key ({e}); the fleet UDP socket stays closed");
            return;
        }
    };
    let me = key.public.to_bytes();
    let hub = Arc::new(Hub { socket, port, key, me, vouched: Mutex::new(Vec::new()), sessions: Mutex::new(Vec::new()) });
    if HUB.set(hub.clone()).is_err() {
        return;
    }
    log::info!("fgtw direct: fleet UDP on {:?}", hub.socket.local_addr());
    // The paths exist now; publish them (a no-op until the session is adopted, which publishes them itself).
    crate::fgtw_auth::republish_own_id();
    std::thread::spawn(move || crate::fgtw_portmap::run(port, crate::fgtw_auth::republish_own_id));
    hub.pump(server).await;
}

// ── punch signalling (over the relay pipe) ──

/// Dials of ours waiting on the host's offer, by punch id.
static WAITERS: Mutex<Vec<([u8; 16], mpsc::UnboundedSender<Vec<SocketAddr>>)>> = Mutex::new(Vec::new());

struct Waiter([u8; 16]);

impl Waiter {
    fn register(id: [u8; 16]) -> (Self, mpsc::UnboundedReceiver<Vec<SocketAddr>>) {
        let (tx, rx) = mpsc::unbounded_channel();
        WAITERS.lock().unwrap().push((id, tx));
        (Self(id), rx)
    }
}

impl Drop for Waiter {
    fn drop(&mut self) {
        WAITERS.lock().unwrap().retain(|(id, _)| *id != self.0);
    }
}

/// An offer arrived over the pipe from fleet device `from` (the pipe verified the sender), which listens on its `peer_hub`. On our host hub it is a peer dialling us: answer with our own addresses and punch toward theirs. On our dialler hub it is a host answering a dial of ours.
pub fn on_offer(from: [u8; 32], peer_hub: &str, id: [u8; 16], offer: CandidateOffer, on_host_hub: bool) {
    if !on_host_hub {
        let waiting = WAITERS.lock().unwrap().iter().find(|(w, _)| *w == id).map(|(_, tx)| tx.clone());
        if let Some(tx) = waiting {
            let _ = tx.send(offer.addrs);
        }
        return;
    }
    let Some(hub) = HUB.get().cloned() else { return };
    if let (Ok(pipe), Some(paths)) = (crate::fgtw_pipe::host_client(), own_paths()) {
        pipe.send_offer(&from, peer_hub, id, &CandidateOffer { addrs: paths.udp });
    }
    tokio::spawn(hub.spray(from, offer.addrs));
}

// ── the guest's dial ──

type Dialled = (Stream, Option<Vec<u8>>, Option<KcpStream>, &'static str);

/// TCP to one published address of the peer's direct server, then the fleet handshake.
async fn dial_tcp(addr: SocketAddr, peer_id: &str) -> ResultType<Dialled> {
    let mut conn = hbb_common::socket_client::connect_tcp(addr, TCP_DIAL_MS).await?;
    let pk = Client::secure_connection_fleet(Some(peer_id), &mut conn).await?;
    Ok((conn, pk, None, path_label(&addr)))
}

/// KCP over UDP: probe the peer's published addresses and punch with the ones it offers over the pipe; the first fleet-signed answer names the path.
async fn dial_udp(peer_id: &str, device: [u8; 32], published: Vec<SocketAddr>) -> ResultType<Dialled> {
    let socket = Arc::new(UdpSocket::from_std(bind_dual(0)?)?);
    let port = socket.local_addr()?.port();
    let key = crate::fgtw_auth::device_keypair()?;
    let me = key.public.to_bytes();
    let id: [u8; 16] = hbb_common::rand::random();
    let (_waiter, mut answers) = Waiter::register(id);
    let mut targets = published;
    let mut offer = CandidateOffer { addrs: interface_ips().into_iter().map(|ip| SocketAddr::new(ip, port)).collect() };
    let pipe = crate::fgtw_pipe::client().ok();
    if let Some(p) = &pipe {
        p.send_offer(&device, fgtw::pipe::SVC_RUSTDESK, id, &offer);
    }
    // A v4-only guest behind its own NAT has no public address to offer until its router maps one; asked beside the punch, offered again if it answers.
    let mut mapping = tokio::task::spawn_blocking(move || crate::fgtw_portmap::map_once(port));
    let mut mapping_done = false;
    let p = probe(&key, &device).ok_or_else(|| anyhow!("probe build"))?;
    let deadline = tokio::time::Instant::now() + Duration::from_millis(PUNCH_WINDOW_MS);
    let mut tick = tokio::time::interval(Duration::from_millis(PUNCH_TICK_MS));
    let mut buf = vec![0u8; DATAGRAM_MAX];
    let chosen = loop {
        tokio::select! {
            _ = tokio::time::sleep_until(deadline) => bail!("no UDP path answered"),
            _ = tick.tick() => {
                for t in &targets {
                    let _ = socket.send_to(&p, wire(&socket, *t)).await;
                }
            }
            Some(addrs) = answers.recv() => {
                for a in addrs {
                    if !targets.contains(&a) {
                        targets.push(a);
                    }
                }
            }
            m = &mut mapping, if !mapping_done => {
                mapping_done = true;
                if let (Ok(Some(ext)), Some(pipe)) = (m, &pipe) {
                    offer.addrs.push(SocketAddr::V4(ext));
                    pipe.send_offer(&device, fgtw::pipe::SVC_RUSTDESK, id, &offer);
                }
            }
            r = socket.recv_from(&mut buf) => {
                let Ok((n, from)) = r else { continue };
                let Some(h) = hear(&buf[..n], &me) else { continue };
                if h.from != device {
                    continue;
                }
                if h.is_probe {
                    if let Some(a) = ack(&key, &device, canon(from)) {
                        let _ = socket.send_to(&a, from).await;
                    }
                }
                if let Some(seen) = h.observed {
                    log::debug!("fgtw direct: {peer_id} sees us at {seen}");
                }
                break from;
            }
        }
    };
    let (guard, mut stream) = KcpStream::connect_to(socket, chosen, Duration::from_millis(KCP_MS)).await?;
    let pk = Client::secure_connection_fleet(Some(peer_id), &mut stream).await?;
    Ok((stream, pk, Some(guard), path_label(&chosen)))
}

/// Every direct path to `device`, raced best first. `None` when none answered — then, and only then, the caller relays.
pub async fn dial(peer_id: &str, device: [u8; 32], paths: PeerPaths) -> Option<(Stream, bool, Option<Vec<u8>>, Option<KcpStream>, &'static str)> {
    let ours = crate::fgtw_auth::our_lan_v4();
    let mut tcp = paths.tcp;
    // Best first on the shared ladder: no router, then this LAN, then across the internet.
    tcp.sort_by_key(|a| classify_path(a, ours));
    // With no published UDP address the punch still has the pipe to trade offers over.
    let udp_worth_trying = !paths.udp.is_empty() || crate::fgtw_pipe::client().is_ok();
    if tcp.is_empty() && !udp_worth_trying {
        return None;
    }
    log::info!("fgtw: dialling {peer_id} directly — TCP {:?}, UDP {:?}", tcp, paths.udp);
    let mut racers: FuturesUnordered<std::pin::Pin<Box<dyn std::future::Future<Output = (String, ResultType<Dialled>)> + Send + '_>>> = FuturesUnordered::new();
    let mut slot = 0u64;
    for addr in tcp {
        let wait = Duration::from_millis(slot * STAGGER_MS);
        slot += 1;
        racers.push(Box::pin(async move {
            tokio::time::sleep(wait).await;
            let r = match tokio::time::timeout(Duration::from_millis(TCP_DIAL_MS), dial_tcp(addr, peer_id)).await {
                Ok(r) => r,
                Err(_) => Err(anyhow!("timed out")),
            };
            (format!("TCP {addr}"), r)
        }));
    }
    if udp_worth_trying {
        let wait = Duration::from_millis(slot * STAGGER_MS);
        let udp = paths.udp;
        racers.push(Box::pin(async move {
            tokio::time::sleep(wait).await;
            ("UDP".to_owned(), dial_udp(peer_id, device, udp).await)
        }));
    }
    while let Some((what, r)) = racers.next().await {
        match r {
            Ok((stream, pk, kcp, label)) => {
                log::info!("fgtw: connected to {peer_id} directly ({what}, {label})");
                return Some((stream, true, pk, kcp, label));
            }
            Err(e) => log::info!("fgtw: direct {what} to {peer_id}: {e}"),
        }
    }
    None
}

// ── the fleet tile's probe ──

fn keep_best(best: &mut Option<PathTier>, t: PathTier) {
    if best.map_or(true, |b| t < b) {
        *best = Some(t);
    }
}

/// The best direct path to `device` that answers right now, for the tile's colour: a TCP connect to each published direct-server address and a signed probe to the published UDP addresses (answered only by a host whose NAT lets it, which is exactly the question), all at once. Blocking for about half a second; the tile pings off-thread.
pub fn probe_tier(device: &[u8; 32], paths: &PeerPaths) -> Option<PathTier> {
    let ours = crate::fgtw_auth::our_lan_v4();
    std::thread::scope(|s| {
        let tcp: Vec<_> = paths
            .tcp
            .iter()
            .map(|a| s.spawn(move || std::net::TcpStream::connect_timeout(a, Duration::from_millis(1 << 8)).is_ok().then(|| classify_path(a, ours))))
            .collect();
        let udp = s.spawn(|| probe_udp_tier(device, &paths.udp, ours));
        let mut best: Option<PathTier> = None;
        for t in tcp.into_iter().filter_map(|h| h.join().ok().flatten()) {
            keep_best(&mut best, t);
        }
        if let Ok(Some(t)) = udp.join() {
            keep_best(&mut best, t);
        }
        best
    })
}

/// The UDP half of [`probe_tier`]: one signed probe to each address, then every fleet-signed answer from `device` inside half a second, best path kept.
fn probe_udp_tier(device: &[u8; 32], udp: &[SocketAddr], ours: Option<std::net::Ipv4Addr>) -> Option<PathTier> {
    if udp.is_empty() {
        return None;
    }
    let key = crate::fgtw_auth::device_keypair().ok()?;
    let me = key.public.to_bytes();
    let p = probe(&key, device)?;
    let socket = bind_dual(0).ok()?;
    socket.set_nonblocking(false).ok()?;
    let v6 = socket.local_addr().map(|l| l.is_ipv6()).unwrap_or(false);
    for a in udp {
        let to = match (v6, *a) {
            (true, SocketAddr::V4(v4)) => SocketAddr::new(IpAddr::V6(v4.ip().to_ipv6_mapped()), v4.port()),
            (_, a) => a,
        };
        let _ = socket.send_to(&p, to);
    }
    let deadline = Instant::now() + Duration::from_millis(1 << 9);
    let mut buf = vec![0u8; DATAGRAM_MAX];
    let mut best: Option<PathTier> = None;
    while let Some(left) = deadline.checked_duration_since(Instant::now()).filter(|d| !d.is_zero()) {
        socket.set_read_timeout(Some(left)).ok()?;
        let Ok((n, from)) = socket.recv_from(&mut buf) else { break };
        if hear(&buf[..n], &me).is_some_and(|h| h.from == *device) {
            keep_best(&mut best, classify_path(&canon(from), ours));
        }
    }
    best
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kp(tag: u8) -> Keypair {
        fgtw::keys::derive_device_keypair(&[tag; 16])
    }

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    /// An address set survives the settings value whole and in order, both families.
    #[test]
    fn an_address_set_round_trips_through_its_settings_value() {
        let addrs = vec![sa("[2600:100f:a022:4238::e52]:21118"), sa("203.0.113.7:21118"), sa("192.168.1.100:21118")];
        assert_eq!(set_from_value(&set_value(&addrs)), Some(addrs));
        assert_eq!(set_from_value(&set_value(&[])), Some(Vec::new()));
        assert_eq!(set_from_value(&VsfType::x("192.168.1.100:21118".to_string())), None, "the retired text form is never read");
    }

    /// A probe reads back as a probe from its signer, an ack carries the address it saw, and both are for the named device only.
    #[test]
    fn probes_and_acks_read_back_for_their_recipient_only() {
        let (guest, host) = (kp(1), kp(2));
        let (g, h) = (guest.public.to_bytes(), host.public.to_bytes());
        let p = probe(&guest, &h).unwrap();
        assert!(is_signed_datagram(&p));
        let heard = read_signal(&p, &h).expect("the host reads the guest's probe");
        assert!(heard.is_probe && heard.from == g && heard.observed.is_none());
        assert!(read_signal(&p, &g).is_none(), "a probe for the host is nobody else's");

        let seen = sa("198.51.100.4:40000");
        let a = ack(&host, &g, seen).unwrap();
        let heard = read_signal(&a, &g).expect("the guest reads the host's ack");
        assert!(!heard.is_probe && heard.from == h && heard.observed == Some(seen));
    }

    /// A probe stamped outside the window, or tampered with, vouches for nothing.
    #[test]
    fn a_stale_or_tampered_probe_is_refused() {
        let (guest, host) = (kp(3), kp(4));
        let h = host.public.to_bytes();
        let mut s = vsf::VsfSection::new(PROBE);
        s.add_field("to", VsfType::ke(h.to_vec()));
        let old = vsf::eagle_time_oscillations() - ((VOUCH_SECS << 1) * vsf::OSCILLATIONS_PER_SECOND) as i64;
        let stale = fgtw::pq::signed_frame(s, &guest, old).unwrap();
        assert!(read_signal(&stale, &h).is_none(), "a replay from outside the window");
        let mut bent = probe(&guest, &h).unwrap();
        let last = bent.len() - 1;
        bent[last] ^= 1;
        assert!(read_signal(&bent, &h).is_none(), "a tampered probe");
    }

    /// A KCP packet is never taken for a signed probe (the demux on the shared socket depends on it).
    #[test]
    fn a_kcp_packet_is_not_a_signed_datagram() {
        let mut kcp = vec![0u8; std::mem::size_of::<kcp_sys::packet_def::KcpPacketHeader>()];
        kcp[12] = 1; // SYN
        assert!(!is_signed_datagram(&kcp));
        assert!(!is_signed_datagram(&[]));
    }

    /// A dual-stack socket's v4-mapped view of an IPv4 peer reads back as plain IPv4, and anything else passes untouched.
    #[test]
    fn canon_unmaps_v4_and_leaves_v6() {
        assert_eq!(canon(sa("[::ffff:192.168.1.5]:21118")), sa("192.168.1.5:21118"));
        assert_eq!(canon(sa("[2600::1]:21118")), sa("[2600::1]:21118"));
        assert_eq!(canon(sa("10.0.0.2:1")), sa("10.0.0.2:1"));
    }

    /// Only router-assigned IPv6 is dialable; link-local needs a scope id no peer holds.
    #[test]
    fn link_local_v6_is_not_published() {
        assert!(usable_v6("2600:100f::1".parse().unwrap()));
        assert!(usable_v6("fd00::1".parse().unwrap()));
        assert!(!usable_v6("fe80::1".parse().unwrap()));
        assert!(!usable_v6(Ipv6Addr::LOCALHOST));
        assert!(!usable_v6(Ipv6Addr::UNSPECIFIED));
    }
}
