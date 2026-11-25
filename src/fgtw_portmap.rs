//! Port mapping on the home router for the fleet UDP socket — NAT-PMP (RFC 6886), PCP MAP (RFC 6887) and UPnP IGD, in that order.
//!
//! Photon's `network/traverse/portmap.rs`, carried to the fork: a host behind a home NAT that holds a mapped public port is directly reachable by every fleet peer with no punch and no relay. The mapping is `external:port → us:our UDP port`; the external address joins this device's published UDP candidates, and it is also how a host learns its public IPv4 at all (fgtw.org's only echo of a caller's address is Photon's announce, which RustDesk must not send). Renewed at half its lifetime; a router that answers none of the three costs one round of short timeouts and is not asked again until the network changes.
//!
//! Plain std sockets and a few hundred bytes of protocol; UPnP's HTTP goes through `reqwest::blocking`, which the fork already carries.

#![cfg(feature = "fgtw")]

use std::net::{IpAddr, Ipv4Addr, SocketAddrV4, UdpSocket};
use std::sync::Mutex;
use std::time::Duration;

use hbb_common::log;

/// What we ask the router for. Two hours, renewed at half-life.
const ASK: Duration = Duration::from_secs(1 << 13);

/// A mapping the router granted: where the world reaches us, for how long, and which protocol said so.
#[derive(Debug, Clone)]
pub struct Mapping {
    pub external: SocketAddrV4,
    pub lifetime: Duration,
    pub via: &'static str,
}

/// The mapping held right now, if any. Read by the address gather that publishes this device's UDP candidates.
static CURRENT: Mutex<Option<SocketAddrV4>> = Mutex::new(None);

/// The router-mapped public address of the fleet UDP socket, while the mapping holds.
pub fn current() -> Option<SocketAddrV4> {
    *CURRENT.lock().unwrap()
}

/// The default gateway's IPv4 address — the router that owns our NAT. Read from the routing table (Photon's lookup), not `default_net`, which fires a packet at 1.1.1.1 on every call to learn the gateway's MAC we have no use for — once a minute from every host.
fn default_gateway() -> Option<Ipv4Addr> {
    #[cfg(target_os = "linux")]
    {
        // /proc/net/route: Iface Destination Gateway Flags … — hex little-endian, the default route has destination 00000000.
        let text = std::fs::read_to_string("/proc/net/route").ok()?;
        for line in text.lines().skip(1) {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() >= 3 && f[1] == "00000000" {
                let g = u32::from_str_radix(f[2], 16).ok()?;
                let ip = Ipv4Addr::from(g.swap_bytes());
                if !ip.is_unspecified() {
                    return Some(ip);
                }
            }
        }
        None
    }
    #[cfg(target_os = "macos")]
    {
        let out = std::process::Command::new("route").args(["-n", "get", "default"]).output().ok()?;
        let text = String::from_utf8_lossy(&out.stdout);
        text.lines()
            .find_map(|l| l.trim().strip_prefix("gateway:"))
            .and_then(|g| g.trim().parse::<Ipv4Addr>().ok())
    }
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        // CREATE_NO_WINDOW: a GUI process spawning a console tool would flash a window.
        let out = std::process::Command::new("route").args(["print", "0.0.0.0"]).creation_flags(0x0800_0000).output().ok()?;
        let text = String::from_utf8_lossy(&out.stdout);
        text.lines()
            .filter_map(|l| {
                let f: Vec<&str> = l.split_whitespace().collect();
                (f.len() >= 3 && f[0] == "0.0.0.0" && f[1] == "0.0.0.0").then(|| f[2].parse::<Ipv4Addr>().ok()).flatten()
            })
            .next()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        None
    }
}

/// Our own address on the gateway's network: the source the OS picks toward it. A routing lookup only; `connect` on UDP sends nothing.
fn local_ip_toward(gateway: Ipv4Addr) -> Option<Ipv4Addr> {
    let s = UdpSocket::bind("0.0.0.0:0").ok()?;
    s.connect((gateway, 5351)).ok()?;
    match s.local_addr().ok()?.ip() {
        IpAddr::V4(ip) => Some(ip),
        IpAddr::V6(_) => None,
    }
}

/// Ask the gateway for a mapping of our UDP `port`, trying NAT-PMP, then PCP, then UPnP. The reply's lifetime is the truth, not the ask.
fn request(gateway: Ipv4Addr, port: u16, lifetime: Duration) -> Option<Mapping> {
    natpmp(gateway, port, lifetime).or_else(|| pcp(gateway, port, lifetime)).or_else(|| upnp(gateway, port, lifetime))
}

fn udp_to_gateway(gateway: Ipv4Addr, timeout: Duration) -> Option<UdpSocket> {
    let s = UdpSocket::bind("0.0.0.0:0").ok()?;
    s.set_read_timeout(Some(timeout)).ok()?;
    s.connect((gateway, 5351)).ok()?;
    Some(s)
}

/// A granted lifetime as we act on it. WHY/PROOF: the seconds come from the router (external input); a zero grant would make the half-life renewal below spin, so anything under a minute is renewed as if it were a minute.
fn granted(secs: u32) -> Duration {
    Duration::from_secs(secs.max(60) as u64)
}

/// NAT-PMP (RFC 6886): op 0 = external address, op 1 = map UDP. Two round trips, ~30 bytes each.
fn natpmp(gateway: Ipv4Addr, port: u16, lifetime: Duration) -> Option<Mapping> {
    let s = udp_to_gateway(gateway, Duration::from_millis(500))?;
    s.send(&[0, 0]).ok()?;
    let mut buf = [0u8; 64];
    let n = s.recv(&mut buf).ok()?;
    if n < 12 || buf[0] != 0 || buf[1] != 128 || u16::from_be_bytes([buf[2], buf[3]]) != 0 {
        return None;
    }
    let ext_ip = Ipv4Addr::new(buf[8], buf[9], buf[10], buf[11]);
    // Map UDP: [0, 1, 0, 0, internal port, suggested external port, lifetime].
    let mut req = vec![0u8, 1, 0, 0];
    req.extend_from_slice(&port.to_be_bytes());
    req.extend_from_slice(&port.to_be_bytes());
    req.extend_from_slice(&(lifetime.as_secs() as u32).to_be_bytes());
    s.send(&req).ok()?;
    let n = s.recv(&mut buf).ok()?;
    if n < 16 || buf[0] != 0 || buf[1] != 129 || u16::from_be_bytes([buf[2], buf[3]]) != 0 {
        return None;
    }
    let ext_port = u16::from_be_bytes([buf[10], buf[11]]);
    let secs = u32::from_be_bytes([buf[12], buf[13], buf[14], buf[15]]);
    if ext_port == 0 || !globally_routable(ext_ip) {
        return None;
    }
    Some(Mapping { external: SocketAddrV4::new(ext_ip, ext_port), lifetime: granted(secs), via: "NAT-PMP" })
}

/// PCP (RFC 6887) MAP, version 2, UDP, our local address as the client address, a random nonce, the external address left to the router.
fn pcp(gateway: Ipv4Addr, port: u16, lifetime: Duration) -> Option<Mapping> {
    let local = local_ip_toward(gateway)?;
    let s = udp_to_gateway(gateway, Duration::from_millis(500))?;
    let mut req = Vec::with_capacity(60);
    req.extend_from_slice(&[2u8, 1, 0, 0]); // version 2, opcode MAP, reserved
    req.extend_from_slice(&(lifetime.as_secs() as u32).to_be_bytes());
    req.extend_from_slice(&[0u8; 10]);
    req.extend_from_slice(&[0xff, 0xff]);
    req.extend_from_slice(&local.octets()); // client address, v4-mapped v6
    let nonce: [u8; 12] = hbb_common::rand::random();
    req.extend_from_slice(&nonce);
    req.extend_from_slice(&[17, 0, 0, 0]); // UDP, reserved
    req.extend_from_slice(&port.to_be_bytes());
    req.extend_from_slice(&port.to_be_bytes());
    req.extend_from_slice(&[0u8; 16]); // suggested external address: any
    s.send(&req).ok()?;
    let mut buf = [0u8; 128];
    let n = s.recv(&mut buf).ok()?;
    if n < 60 || buf[0] != 2 || buf[1] != 0x81 || buf[3] != 0 {
        return None;
    }
    let secs = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
    let ext_port = u16::from_be_bytes([buf[42], buf[43]]);
    let ext_ip = Ipv4Addr::new(buf[56], buf[57], buf[58], buf[59]);
    if ext_port == 0 || !globally_routable(ext_ip) || buf[54] != 0xff || buf[55] != 0xff {
        return None;
    }
    Some(Mapping { external: SocketAddrV4::new(ext_ip, ext_port), lifetime: granted(secs), via: "PCP" })
}

/// Is `url` a plain-http URL whose host is exactly `gateway`? Every URL UPnP hands us must be (Photon security audit NET-08): else a neighbour on the LAN steers our GET and POSTs at any host it likes, loopback and metadata addresses included.
fn url_host_is(url: &str, gateway: Ipv4Addr) -> bool {
    let Some(rest) = url.strip_prefix("http://") else {
        return false;
    };
    let authority = rest.split('/').next().unwrap_or("");
    let host = authority.rsplit_once(':').map_or(authority, |(h, _)| h);
    host.parse::<Ipv4Addr>().ok() == Some(gateway)
}

/// Globally routable, or a lie (NET-08): the mapped address is published to the fleet, so loopback, link-local, CGNAT, multicast, reserved and documentation space are refused along with RFC 1918.
fn globally_routable(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    !(ip.is_unspecified()
        || ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_broadcast()
        || ip.is_documentation()
        || o[0] == 0
        // 100.64.0.0/10, carrier-grade NAT.
        || (o[0] == 100 && (o[1] & 0xC0) == 64)
        // 192.0.0.0/24, IETF protocol assignments.
        || (o[0] == 192 && o[1] == 0 && o[2] == 0)
        // 198.18.0.0/15, benchmarking.
        || (o[0] == 198 && (o[1] & 0xFE) == 18)
        // 240.0.0.0/4, reserved.
        || o[0] >= 240)
}

/// The most of a gateway's HTTP reply we read: a device description is a few KB and a SOAP answer under one (NET-08).
const UPNP_REPLY_LIMIT: u64 = 1 << 16;

fn upnp_reply_text(resp: reqwest::blocking::Response) -> Option<String> {
    use std::io::Read;
    let mut buf = Vec::new();
    resp.take(UPNP_REPLY_LIMIT).read_to_end(&mut buf).ok()?;
    Some(String::from_utf8_lossy(&buf).into_owned())
}

/// The HTTP client for the gateway: a short deadline and NO redirects (NET-08), so a description that answers 302 cannot send the SOAP POSTs elsewhere.
fn upnp_client() -> Option<&'static reqwest::blocking::Client> {
    static C: std::sync::OnceLock<Option<reqwest::blocking::Client>> = std::sync::OnceLock::new();
    C.get_or_init(|| {
        reqwest::blocking::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(3))
            .build()
            .ok()
    })
    .as_ref()
}

/// UPnP IGD: SSDP discovery, the device description for the WANIPConnection control URL, one SOAP AddPortMapping and one GetExternalIPAddress. String-parsed on purpose, as in Photon: the three fields are unambiguous and an XML crate is a dependency the doctrine does not want.
fn upnp(gateway: Ipv4Addr, port: u16, lifetime: Duration) -> Option<Mapping> {
    let s = UdpSocket::bind("0.0.0.0:0").ok()?;
    let msearch = "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: urn:schemas-upnp-org:service:WANIPConnection:1\r\n\r\n";
    s.send_to(msearch.as_bytes(), "239.255.255.250:1900").ok()?;
    // Only the gateway's own answer counts (NET-08): any host on the LAN may answer a multicast first.
    let deadline = std::time::Instant::now() + Duration::from_millis(1500);
    let mut buf = [0u8; 2048];
    let reply = loop {
        let now = std::time::Instant::now();
        if now >= deadline {
            return None;
        }
        s.set_read_timeout(Some(deadline - now)).ok()?;
        let (n, src) = s.recv_from(&mut buf).ok()?;
        if src.ip() != IpAddr::V4(gateway) {
            continue;
        }
        break String::from_utf8_lossy(&buf[..n]).into_owned();
    };
    let location = reply
        .lines()
        .find_map(|l| l.get(..9).filter(|h| h.eq_ignore_ascii_case("location:")).map(|_| l[9..].trim().to_string()))?;
    if !url_host_is(&location, gateway) {
        log::warn!("fgtw portmap: UPnP description URL is not on the gateway — refused");
        return None;
    }
    let http = upnp_client()?;
    let desc = upnp_reply_text(http.get(&location).send().ok()?)?;
    let service_type = if desc.contains("WANIPConnection:2") { "urn:schemas-upnp-org:service:WANIPConnection:2" } else { "urn:schemas-upnp-org:service:WANIPConnection:1" };
    let control = {
        let at = desc.find(service_type)?;
        let tail = &desc[at..];
        let c0 = tail.find("<controlURL>")? + "<controlURL>".len();
        let c1 = tail[c0..].find("</controlURL>")? + c0;
        tail[c0..c1].trim().to_string()
    };
    let base = {
        let after = location.find("://").map(|i| i + 3).unwrap_or(0);
        let end = location[after..].find('/').map(|i| after + i).unwrap_or(location.len());
        location[..end].to_string()
    };
    let control_url = if control.starts_with("http") { control } else { format!("{base}{control}") };
    if !url_host_is(&control_url, gateway) {
        log::warn!("fgtw portmap: UPnP control URL is not on the gateway — refused");
        return None;
    }
    let local = local_ip_toward(gateway)?;
    let secs = lifetime.as_secs();
    let add = format!(
        "<?xml version=\"1.0\"?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body><u:AddPortMapping xmlns:u=\"{service_type}\"><NewRemoteHost></NewRemoteHost><NewExternalPort>{port}</NewExternalPort><NewProtocol>UDP</NewProtocol><NewInternalPort>{port}</NewInternalPort><NewInternalClient>{local}</NewInternalClient><NewEnabled>1</NewEnabled><NewPortMappingDescription>rustdesk</NewPortMappingDescription><NewLeaseDuration>{secs}</NewLeaseDuration></u:AddPortMapping></s:Body></s:Envelope>"
    );
    let ok = http
        .post(&control_url)
        .header("Content-Type", "text/xml; charset=\"utf-8\"")
        .header("SOAPAction", format!("\"{service_type}#AddPortMapping\""))
        .body(add)
        .send()
        .ok()?
        .status()
        .is_success();
    if !ok {
        return None;
    }
    let get_ext = format!(
        "<?xml version=\"1.0\"?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body><u:GetExternalIPAddress xmlns:u=\"{service_type}\"></u:GetExternalIPAddress></s:Body></s:Envelope>"
    );
    let text = http
        .post(&control_url)
        .header("Content-Type", "text/xml; charset=\"utf-8\"")
        .header("SOAPAction", format!("\"{service_type}#GetExternalIPAddress\""))
        .body(get_ext)
        .send()
        .ok()?;
    let text = upnp_reply_text(text)?;
    let e0 = text.find("<NewExternalIPAddress>")? + "<NewExternalIPAddress>".len();
    let e1 = text[e0..].find("</NewExternalIPAddress>")? + e0;
    let ext_ip: Ipv4Addr = text[e0..e1].trim().parse().ok()?;
    if !globally_routable(ext_ip) {
        return None;
    }
    Some(Mapping { external: SocketAddrV4::new(ext_ip, port), lifetime, via: "UPnP" })
}

/// One short-lived mapping for a guest's dial socket: the public address a v4-only guest behind its own NAT can offer the host to punch toward. Blocking — a router that answers nothing costs about two and a half seconds of timeouts, so the caller runs it beside the punch, not before it.
pub fn map_once(port: u16) -> Option<SocketAddrV4> {
    request(default_gateway()?, port, Duration::from_secs(1 << 9)).map(|m| m.external)
}

/// The mapping worker for the fleet UDP `port`, for the life of the process: ask, hold, renew at half-life; when the router answers nothing, wait for the gateway to change (a move to another network) and ask that one. `on_change` runs whenever the held mapping appears, moves or lapses, so the published candidates follow it.
pub fn run(port: u16, on_change: impl Fn()) {
    // How often a held mapping looks for a network move while it waits out its half-life.
    let glance = Duration::from_secs(1 << 6);
    let mut asked: Option<Ipv4Addr> = None;
    loop {
        if let Some(gw) = default_gateway().filter(|g| Some(*g) != asked) {
            asked = Some(gw);
            'held: loop {
                match request(gw, port, ASK) {
                    Some(m) => {
                        let moved = current() != Some(m.external);
                        *CURRENT.lock().unwrap() = Some(m.external);
                        if moved {
                            log::info!("fgtw portmap: {} mapped {} → our UDP {port} for {}s via {gw}", m.via, m.external, m.lifetime.as_secs());
                            on_change();
                        }
                        let renew_at = std::time::Instant::now() + m.lifetime / 2;
                        while std::time::Instant::now() < renew_at {
                            std::thread::sleep(glance);
                            if default_gateway() != Some(gw) {
                                break 'held;
                            }
                        }
                    }
                    None => {
                        log::info!("fgtw portmap: gateway {gw} answered none of NAT-PMP / PCP / UPnP — no mapping on this network");
                        break;
                    }
                }
            }
            if CURRENT.lock().unwrap().take().is_some() {
                on_change();
            }
        }
        std::thread::sleep(glance);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// NET-08: only a plain-http URL on the gateway itself passes.
    #[test]
    fn upnp_urls_must_sit_on_the_gateway() {
        let gw = Ipv4Addr::new(192, 168, 1, 1);
        assert!(url_host_is("http://192.168.1.1:5000/rootDesc.xml", gw));
        assert!(url_host_is("http://192.168.1.1/ctl", gw));
        assert!(!url_host_is("http://192.168.1.77:5000/rootDesc.xml", gw));
        assert!(!url_host_is("http://127.0.0.1:8080/", gw));
        assert!(!url_host_is("http://169.254.169.254/latest/meta-data/", gw));
        assert!(!url_host_is("https://192.168.1.1/", gw));
        assert!(!url_host_is("/relative", gw));
    }

    /// NET-08: an external address a router hands back is published, so only globally routable space is accepted.
    #[test]
    fn external_address_must_be_globally_routable() {
        assert!(globally_routable(Ipv4Addr::new(203, 0, 112, 7)));
        for bad in [
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::LOCALHOST,
            Ipv4Addr::new(10, 1, 2, 3),
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(100, 64, 0, 1),
            Ipv4Addr::new(169, 254, 169, 254),
            Ipv4Addr::new(224, 0, 0, 1),
            Ipv4Addr::new(240, 0, 0, 1),
            Ipv4Addr::new(192, 0, 2, 1),
        ] {
            assert!(!globally_routable(bad), "{bad} must be refused");
        }
    }
}
