//! Fleet-native transport: RustDesk's byte stream over the fgtw relay pipe.
//!
//! For a fleet pair that can't hole-punch (asymmetric NAT, different LANs — the common case,
//! and the exact case rs-ny now refuses to broker), this replaces the rendezvous server AND the rustdesk relay with the fgtw seed's live WebSocket pipe. We address the peer by its fleet **device pubkey**, not an IP, so nothing has to introduce us.
//!
//! # Shape
//!
//! One [`PipeClient`] per process holds the `wss://<seed>/pipe?dev=<self>&svc=rd` socket. The
//! `svc=rd` tag gives the fork its own hub on the seed, separate from photon's pipe on the same device key — so photon restarting (e.g. being updated *by* a rustdesk session) never drops our pipe. Each logical connection is a [`RelayStream`] keyed by a random 16-byte
//! `conn` id: it implements `AsyncRead + AsyncWrite`, so it wraps into `hbb_common::Stream`
//! exactly like the KCP path (`kcp_stream.rs`), and every layer above — rustdesk's own encryption, the fgtw passless handshake — rides on top unchanged.
//!
//! Outbound bytes are chunked into [`fgtw::pipe::RdFrame`]s, each sealed in a signed relay envelope addressed to the peer device, pushed up the pipe. Inbound envelopes are peeled,
//! demuxed by `conn`, and their bytes served to the matching `RelayStream`'s reader.

#![cfg(feature = "fgtw")]

use std::collections::HashMap;
use std::pin::Pin;
use std::sync::{Arc, Mutex, OnceLock};
use std::task::{Context, Poll};

use hbb_common::{
    anyhow::anyhow,
    bytes::BytesMut,
    log,
    tokio::{
        self,
        io::{AsyncRead, AsyncWrite, ReadBuf},
        sync::mpsc,
    },
    ResultType,
};

use fgtw::pipe::{
    build_relay_envelope, peel_relay_envelope_eggs, CandidateOffer, RdFrame, RD_FLAG_DIALLER, RD_FLAG_FIN, RD_FLAG_NACK,
    RD_FLAG_PUNCH, RD_FLAG_SYN, SVC_RUSTDESK, SVC_RUSTDESK_DIALLER,
};

/// Max stream bytes per relay frame. Well under the worker's 1 MiB envelope cap, small enough to keep per-frame latency low on the video path.
const CHUNK: usize = 60 * 1024;
/// How long to wait for a missing frame before declaring the stream lost. Long enough for a NACK to be answered twice over, short enough that an unrecoverable feed becomes a reconnect instead of a black screen.
const GAP_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(2000);
/// How often to re-ask for a missing frame while the gap persists.
const NACK_INTERVAL: std::time::Duration = std::time::Duration::from_millis(150);
/// Frames kept for retransmission. The pipe only loses frames while a peer's socket is reconnecting, so this needs to cover that blip, not a real network backlog.
const RESEND_WINDOW: usize = 512;

/// Seed host (no scheme). Derived from the same `fgtw-url` option the rest of the fork uses.
fn seed_host() -> String {
    crate::fgtw_auth::fgtw_url()
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .trim_end_matches('/')
        .to_string()
}

// ── the per-process pipe ──

type ConnId = [u8; 16];

/// Routes inbound frames to the right stream, and (host side) surfaces new connections.
struct Router {
    /// conn id → the reader half of that live stream.
    streams: Mutex<HashMap<ConnId, mpsc::UnboundedSender<RdFrame>>>,
    /// Host side: SYN for an unknown conn produces a freshly-accepted `RelayStream` here.
    accept_tx: Mutex<Option<mpsc::UnboundedSender<(RelayStream, [u8; 32])>>>,
}

/// Which end of a session a pipe serves. A machine is both at once — the hosting process and a process dialling out share one device key — and the seed binds one proven pipe per hub, so each side has its own: the host listens on [`SVC_RUSTDESK`], the dialler on [`SVC_RUSTDESK_DIALLER`].
#[derive(Clone, Copy, PartialEq, Eq)]
enum Side {
    Host,
    Dialler,
}

impl Side {
    /// The hub this side's own pipe listens on.
    fn hub(self) -> &'static str {
        match self {
            Side::Host => SVC_RUSTDESK,
            Side::Dialler => SVC_RUSTDESK_DIALLER,
        }
    }
}

/// The live pipe, one per side per process, lazily built.
pub struct PipeClient {
    side: Side,
    /// Everything this device signs relay frames with — the full bundle when the fingerprint yielded one, else the bare keypair. Frames carry Ed25519 + Falcon (the envelope tier); a peer holds them to its chain's floor.
    signer: Arc<dyn fgtw::pq::FleetSigner + Send + Sync>,
    /// Sink: already-built envelope bytes to push up the WebSocket.
    out_tx: mpsc::UnboundedSender<Vec<u8>>,
    router: Arc<Router>,
}

static HOST: OnceLock<ResultType<Arc<PipeClient>>> = OnceLock::new();
static DIALLER: OnceLock<ResultType<Arc<PipeClient>>> = OnceLock::new();
/// Is the host's relay pipe up right now? Its pump flips this on connect and on drop, so the UI can
/// report reachability instead of the rendezvous heartbeat this fork no longer has.
static PIPE_UP: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// True while the host's seed pipe is connected.
pub fn pipe_connected() -> bool {
    PIPE_UP.load(std::sync::atomic::Ordering::Relaxed)
}

fn get(cell: &OnceLock<ResultType<Arc<PipeClient>>>, side: Side) -> ResultType<Arc<PipeClient>> {
    // OnceLock can't hold a retryable Result cleanly; keep it simple — one attempt per process,
    // the connection task self-heals with reconnect once it exists.
    match cell.get_or_init(|| PipeClient::connect(side)) {
        Ok(c) => Ok(c.clone()),
        Err(e) => Err(anyhow!("fgtw pipe unavailable: {e}")),
    }
}

/// The dialling side's pipe, connecting on first use: what a session we start rides, and where a host's punch offer reaches us.
pub fn client() -> ResultType<Arc<PipeClient>> {
    get(&DIALLER, Side::Dialler)
}

/// The hosting side's pipe, connecting on first use: where peers dial us and send their punch offers.
pub fn host_client() -> ResultType<Arc<PipeClient>> {
    get(&HOST, Side::Host)
}

impl PipeClient {
    fn connect(side: Side) -> ResultType<Arc<Self>> {
        let kp = crate::fgtw_auth::device_keypair()?;
        let self_pk = kp.public.to_bytes();
        let signer: Arc<dyn fgtw::pq::FleetSigner + Send + Sync> = match crate::fgtw_auth::signing_bundle() {
            Some(b) => Arc::new(b.clone()),
            None => Arc::new(kp),
        };
        let (out_tx, out_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let router = Arc::new(Router {
            streams: Mutex::new(HashMap::new()),
            accept_tx: Mutex::new(None),
        });
        let host = seed_host();
        let router2 = router.clone();
        // The pump lives on rustdesk's tokio runtime. spawn requires being inside it; the connect callers (Client::_start, fleet_server) are async, so a handle exists.
        let signer2 = signer.clone();
        tokio::spawn(async move {
            pump(host, side, self_pk, signer2, out_rx, router2).await;
        });
        Ok(Arc::new(Self {
            side,
            signer,
            out_tx,
            router,
        }))
    }

    /// Register a stream's reader under `conn`.
    fn register(&self, conn: ConnId, tx: mpsc::UnboundedSender<RdFrame>) {
        self.router.streams.lock().unwrap().insert(conn, tx);
    }

    fn unregister(&self, conn: &ConnId) {
        self.router.streams.lock().unwrap().remove(conn);
    }

    /// Seal one frame to `peer`'s `hub` and push it up the pipe.
    fn send_frame(&self, peer: &[u8; 32], hub: &str, frame: &RdFrame) -> ResultType<()> {
        let env = build_relay_envelope(&*self.signer, peer, Some(hub), &frame.encode())
            .map_err(|e| anyhow!("relay envelope: {e}"))?;
        self.out_tx
            .send(env)
            .map_err(|_| anyhow!("pipe writer gone"))?;
        Ok(())
    }

    /// The flag bits that tell a peer which of our hubs answers this frame.
    fn reply_flag(&self) -> u8 {
        match self.side {
            Side::Host => 0,
            Side::Dialler => RD_FLAG_DIALLER,
        }
    }

    /// Open an outbound stream to a fleet peer device (guest side), on its host hub.
    /// Fires an opening SYN immediately: the guest's first protocol act is to READ (wait for the host's SignedId), so without this the host would never learn a connection had started and never send it — an 18s deadlock.
    pub fn open(self: &Arc<Self>, peer: [u8; 32]) -> RelayStream {
        let conn = new_conn_id(&peer);
        let (in_tx, in_rx) = mpsc::unbounded_channel::<RdFrame>();
        self.register(conn, in_tx);
        let syn = RdFrame { conn, seq: 0, flags: RD_FLAG_SYN | self.reply_flag(), data: Vec::new() };
        let _ = self.send_frame(&peer, SVC_RUSTDESK, &syn);
        // tx_seq starts at 1 — the SYN above took seq 0.
        RelayStream::new(self.clone(), peer, SVC_RUSTDESK, conn, in_rx, 1)
    }

    /// Tell `peer` (on its `hub`) where to aim a hole punch: `offer` under punch id `id` (`fgtw_direct`). The only thing a direct path asks of the relay.
    pub fn send_offer(&self, peer: &[u8; 32], hub: &str, id: ConnId, offer: &CandidateOffer) {
        let frame = RdFrame { conn: id, seq: 0, flags: RD_FLAG_PUNCH | self.reply_flag(), data: offer.encode() };
        if let Err(e) = self.send_frame(peer, hub, &frame) {
            log::debug!("fgtw pipe: punch offer not sent: {e}");
        }
    }

    /// Host side: yield inbound connections as peers dial us. One receiver per process.
    pub fn accept_channel(&self) -> mpsc::UnboundedReceiver<(RelayStream, [u8; 32])> {
        let (tx, rx) = mpsc::unbounded_channel();
        *self.router.accept_tx.lock().unwrap() = Some(tx);
        rx
    }
}

/// A per-connection id. Random, but the socket entropy varies it by peer so two dials never collide even without an RNG dependency here (peer key + a monotonic salt).
fn new_conn_id(peer: &[u8; 32]) -> ConnId {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SALT: AtomicU64 = AtomicU64::new(0);
    let salt = SALT.fetch_add(1, Ordering::Relaxed);
    let t = vsf::eagle_time_oscillations() as u64;
    let mut h = blake3::Hasher::new();
    h.update(peer);
    h.update(&salt.to_le_bytes());
    h.update(&t.to_le_bytes());
    let mut id = [0u8; 16];
    id.copy_from_slice(&h.finalize().as_bytes()[..16]);
    id
}

/// This device's answer to the seed's pipe challenge (fgtw's open handshake), signed with the same key every envelope is. `None` when `frame` is not a challenge the seed signed (an ordinary relay frame); `Some(Err)` for a seed challenge we will not answer — one issued for another device or another service's hub.
fn open_answer_for(
    frame: &[u8],
    side: Side,
    self_pk: &[u8; 32],
    signer: &(dyn fgtw::pq::FleetSigner + Send + Sync),
) -> Option<Result<Vec<u8>, String>> {
    let challenge = fgtw::pipe::read_challenge(frame, &crate::fgtw_auth::FGTW_SEED_PUBLIC)?;
    if challenge.dev != *self_pk {
        return Some(Err("the challenge names another device".to_owned()));
    }
    if challenge.svc.as_deref() != Some(side.hub()) {
        return Some(Err("the challenge is for another service's hub".to_owned()));
    }
    Some(fgtw::pipe::open_answer(frame, signer, vsf::eagle_time_oscillations()))
}

/// The socket pump: owns the WebSocket, reconnects with backoff, moves envelopes both ways.
async fn pump(
    host: String,
    side: Side,
    self_pk: [u8; 32],
    signer: Arc<dyn fgtw::pq::FleetSigner + Send + Sync>,
    mut out_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    router: Arc<Router>,
) {
    use futures_util::{SinkExt, StreamExt};
    use hbb_common::futures_util;
    use tokio_tungstenite::tungstenite::Message as Ws;

    let url = fgtw::pipe::pipe_url(&host, &self_pk, Some(side.hub()));
    // Only the host pipe speaks for this machine's reachability.
    let up = |v: bool| {
        if side == Side::Host {
            PIPE_UP.store(v, std::sync::atomic::Ordering::Relaxed);
        }
    };
    let mut backoff = 1u64;
    loop {
        match tokio_tungstenite::connect_async(&url).await {
            Ok((ws, _)) => {
                backoff = 1;
                up(true);
                log::info!("fgtw pipe: connected ({url})");
                let (mut sink, mut stream) = ws.split();
                // Keepalive: Cloudflare silently closes an idle WebSocket, and a host that sits
                // hours between connections would go dark without ever noticing — its next
                // inbound SYN lands on a dead hub and vanishes (the 18s deadlock we hit).
                // A ping every 20s (under the common idle window, matching photon's interval)
                // holds the socket open, and a failed send trips the reconnect.
                let mut keepalive = tokio::time::interval(std::time::Duration::from_secs(20));
                keepalive.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                loop {
                    tokio::select! {
                        // Outbound: envelope → WS binary frame.
                        out = out_rx.recv() => match out {
                            Some(bytes) => {
                                if sink.send(Ws::Binary(bytes.into())).await.is_err() {
                                    log::warn!("fgtw pipe: send failed, reconnecting");
                                    break;
                                }
                            }
                            None => return, // client dropped; stop the pump
                        },
                        // Inbound: WS binary → peel → route.
                        msg = stream.next() => match msg {
                            Some(Ok(Ws::Binary(data))) => match open_answer_for(&data, side, &self_pk, &*signer) {
                                // The seed opens every pipe with a challenge; until this device answers it with its own key, the pipe is unproven: the worker reports it offline and, once its unsigned window closes, hands it nothing.
                                Some(Ok(answer)) => {
                                    if sink.send(Ws::Binary(answer.into())).await.is_err() {
                                        log::warn!("fgtw pipe: answer send failed, reconnecting");
                                        break;
                                    }
                                    log::info!("fgtw pipe: answered the seed's challenge with this device's key");
                                }
                                Some(Err(e)) => log::warn!("fgtw pipe: seed challenge left unanswered: {e}"),
                                None => route_inbound(side, &router, &data),
                            },
                            Some(Ok(Ws::Ping(_))) | Some(Ok(Ws::Pong(_))) => {}
                            Some(Ok(_)) => {} // text/other: ignore
                            Some(Err(e)) => { log::warn!("fgtw pipe: recv error {e}, reconnecting"); break; }
                            None => { log::warn!("fgtw pipe: closed, reconnecting"); break; }
                        },
                        // Keepalive tick: ping to hold the socket open and detect a silent drop.
                        _ = keepalive.tick() => {
                            if sink.send(Ws::Ping(Vec::new().into())).await.is_err() {
                                log::warn!("fgtw pipe: keepalive ping failed, reconnecting");
                                break;
                            }
                        },
                    }
                }
            }
            Err(e) => log::warn!("fgtw pipe: connect failed {e}, retrying in {backoff}s"),
        }
        // Either the socket dropped out of the select loop or the connect failed — down either way.
        up(false);
        tokio::time::sleep(std::time::Duration::from_secs(backoff)).await;
        backoff = (backoff * 2).min(30);
    }
}

/// Peel one inbound envelope and hand its frame to the right stream (or accept a new one).
fn route_inbound(side: Side, router: &Arc<Router>, data: &[u8]) {
    // Structural peel first (vsf anchors the Ed25519 egg); that tells us WHO sent it, and only then can the frame be held to what the chain says that sender holds.
    let Some((sender_device, inner, eggs, file_hash)) = peel_relay_envelope_eggs(data) else {
        return; // unverifiable/garbage — drop, never fault
    };
    let Some((bundle, required)) = crate::fgtw_auth::peer_envelope_policy(&sender_device) else {
        return; // not a member of our fleet as far as our chain knows — drop
    };
    if !fgtw::pq::verify_eggs_declared(&eggs, &bundle, &file_hash, required) {
        return; // Ed25519 alone from a fleet that has reached Falcon is a stripped frame — drop
    };
    let Some(frame) = RdFrame::decode(&inner) else {
        return;
    };
    // Where this peer listens for our answers: its dialler hub when it says so, else (a rustdesk from before the split) its host hub.
    let peer_hub = if frame.flags & RD_FLAG_DIALLER != 0 { SVC_RUSTDESK_DIALLER } else { SVC_RUSTDESK };
    // A punch offer is signalling for a direct path, never stream bytes. On the host hub it is a peer dialling us; on the dialler hub, a host answering a dial of ours.
    if frame.flags & RD_FLAG_PUNCH != 0 {
        if let Some(offer) = CandidateOffer::decode(&frame.data) {
            crate::fgtw_direct::on_offer(sender_device, peer_hub, frame.conn, offer, side == Side::Host);
        }
        return;
    }
    let conn = frame.conn;
    // Existing stream? deliver.
    if let Some(tx) = router.streams.lock().unwrap().get(&conn) {
        let _ = tx.send(frame);
        return;
    }
    // Unknown conn + SYN → a peer is dialing us (host side).
    if frame.flags & RD_FLAG_SYN != 0 {
        let accept = router.accept_tx.lock().unwrap().clone();
        if let Some(accept_tx) = accept {
            let (in_tx, in_rx) = mpsc::unbounded_channel::<RdFrame>();
            let _ = in_tx.send(frame); // the SYN carries the first bytes
            router.streams.lock().unwrap().insert(conn, in_tx);
            // The accepted stream needs a client handle to send replies; fetch the process's host one.
            if let Ok(client) = host_client() {
                let stream = RelayStream::new(client, sender_device, peer_hub, conn, in_rx, 0);
                let _ = accept_tx.send((stream, sender_device));
            } else {
                router.streams.lock().unwrap().remove(&conn);
            }
        }
    }
    // Unknown conn, not SYN: a straggler for a closed stream — drop.
}

// ── the stream ──

/// A logical byte stream over the pipe. `AsyncRead + AsyncWrite`, so it wraps into
/// `hbb_common::Stream` like any socket.
pub struct RelayStream {
    client: Arc<PipeClient>,
    peer: [u8; 32],
    /// The peer's hub this stream's frames go to: its host hub when we dialled it, the hub its SYN named when it dialled us.
    peer_hub: &'static str,
    conn: ConnId,
    in_rx: mpsc::UnboundedReceiver<RdFrame>,
    /// Leftover payload from a partially-read frame.
    read_buf: BytesMut,
    /// Outbound sequence (monotonic per connection).
    tx_seq: u64,
    /// Next inbound seq we will serve. Frames arrive out of order because a frame hops through two Durable Objects and the cross-DO deliver is an async race; the encrypted stream needs strict order, so we reassemble on seq here.
    rx_next: u64,
    /// Inbound frames that arrived ahead of `rx_next`, held until the gap fills.
    reorder: std::collections::BTreeMap<u64, RdFrame>,
    /// Recently sent frames, kept so a peer that missed one can ask for it again.
    sent_window: std::collections::BTreeMap<u64, RdFrame>,
    /// When we last asked for the frame we are stuck on.
    last_nack: Option<std::time::Instant>,
    /// When the current gap first blocked delivery. The relay has NO retransmission — a frame lost while a pipe reconnects is gone for good — so a gap that never fills would stall this stream forever (video simply hangs). The encrypted stream cannot skip a message either, because its nonce is a strict counter, so the only honest move is to fail the connection and let rustdesk reconnect.
    gap_since: Option<std::time::Instant>,
    /// Peer sent FIN — reads drain then EOF.
    peer_finished: bool,
}

impl RelayStream {
    fn new(
        client: Arc<PipeClient>,
        peer: [u8; 32],
        peer_hub: &'static str,
        conn: ConnId,
        in_rx: mpsc::UnboundedReceiver<RdFrame>,
        start_seq: u64,
    ) -> Self {
        Self {
            client,
            peer,
            peer_hub,
            conn,
            in_rx,
            read_buf: BytesMut::new(),
            tx_seq: start_seq,
            rx_next: 0,
            reorder: std::collections::BTreeMap::new(),
            sent_window: std::collections::BTreeMap::new(),
            last_nack: None,
            gap_since: None,
            peer_finished: false,
        }
    }

    /// Fold one in-order frame into the read buffer and advance `rx_next`.
    fn consume(&mut self, frame: RdFrame) {
        if frame.flags & RD_FLAG_FIN != 0 {
            self.peer_finished = true;
        }
        if !frame.data.is_empty() {
            self.read_buf.extend_from_slice(&frame.data);
        }
        self.rx_next += 1;
        self.gap_since = None;
        self.last_nack = None;
    }
}

impl Drop for RelayStream {
    fn drop(&mut self) {
        self.client.unregister(&self.conn);
    }
}

impl AsyncRead for RelayStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        loop {
            // Serve leftover first.
            if !self.read_buf.is_empty() {
                let n = self.read_buf.len().min(buf.remaining());
                let chunk = self.read_buf.split_to(n);
                buf.put_slice(&chunk);
                return Poll::Ready(Ok(()));
            }
            if self.peer_finished {
                return Poll::Ready(Ok(())); // EOF
            }
            // An earlier-arrived frame that fills the current gap? serve it in order.
            let next = self.rx_next;
            if let Some(frame) = self.reorder.remove(&next) {
                self.consume(frame);
                continue;
            }
            // Stuck behind a missing frame: ask the peer to send it again. The relay drops
            // anything in flight while a socket reconnects, and that is the only loss we see,
            // so a re-ask almost always fills the gap within a round trip.
            if !self.reorder.is_empty() {
                let waited = self
                    .gap_since
                    .get_or_insert_with(std::time::Instant::now)
                    .elapsed();
                let due = self.last_nack.map_or(true, |t| t.elapsed() >= NACK_INTERVAL);
                if due && waited <= GAP_TIMEOUT {
                    let (conn, peer, want) = (self.conn, self.peer, self.rx_next);
                    let nack = RdFrame { conn, seq: want, flags: RD_FLAG_NACK, data: Vec::new() };
                    let _ = self.client.send_frame(&peer, self.peer_hub, &nack);
                    self.last_nack = Some(std::time::Instant::now());
                }
                if waited > GAP_TIMEOUT {
                    log::warn!(
                        "fgtw pipe: frame {} never arrived ({} held behind it) — dropping the connection to reconnect",
                        self.rx_next,
                        self.reorder.len()
                    );
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::BrokenPipe,
                        "relay stream lost a frame",
                    )));
                }
            }
            match self.in_rx.poll_recv(cx) {
                Poll::Ready(Some(frame)) => {
                    // A retransmit request rides the same stream; answer it and keep reading.
                    if frame.flags & RD_FLAG_NACK != 0 {
                        let (peer, want) = (self.peer, frame.seq);
                        match self.sent_window.get(&want).cloned() {
                            Some(again) => {
                                log::info!("fgtw pipe: resending frame {want} on request");
                                let _ = self.client.send_frame(&peer, self.peer_hub, &again);
                            }
                            None => log::warn!(
                                "fgtw pipe: peer wants frame {want}, no longer in the resend window"
                            ),
                        }
                        continue;
                    }
                    use std::cmp::Ordering;
                    match frame.seq.cmp(&self.rx_next) {
                        // The frame we were waiting for — fold it, then the loop drains any
                        // now-contiguous frames from the reorder buffer.
                        Ordering::Equal => self.consume(frame),
                        // Arrived ahead of the gap — hold it until the missing seqs land.
                        Ordering::Greater => {
                            self.reorder.insert(frame.seq, frame);
                        }
                        // Already served (a duplicate) — drop.
                        Ordering::Less => {}
                    }
                }
                Poll::Ready(None) => return Poll::Ready(Ok(())), // pipe gone → EOF
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for RelayStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        // Chunk the write; each chunk is one sealed frame up the pipe. Unbounded sink, so this never blocks (relay bandwidth backpressure is a later concern).
        let mut sent = 0;
        while sent < buf.len() {
            let end = (sent + CHUNK).min(buf.len());
            let seq = self.tx_seq;
            let frame = RdFrame {
                conn: self.conn,
                seq,
                flags: 0,
                data: buf[sent..end].to_vec(),
            };
            if let Err(e) = self.client.send_frame(&self.peer, self.peer_hub, &frame) {
                return Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, e.to_string())));
            }
            // Hold it briefly in case the peer's socket was mid-reconnect and missed it.
            self.sent_window.insert(seq, frame);
            while self.sent_window.len() > RESEND_WINDOW {
                let oldest = *self.sent_window.keys().next().unwrap_or(&0);
                self.sent_window.remove(&oldest);
            }
            self.tx_seq += 1;
            sent = end;
        }
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(())) // frames leave immediately; nothing buffered
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        let seq = self.tx_seq;
        let conn = self.conn;
        let peer = self.peer;
        let fin = RdFrame { conn, seq, flags: RD_FLAG_FIN, data: Vec::new() };
        let _ = self.client.send_frame(&peer, self.peer_hub, &fin);
        self.tx_seq += 1;
        Poll::Ready(Ok(()))
    }
}

// ── connect seam (guest side) ──

use hbb_common::{
    bytes_codec::BytesCodec,
    config::Config,
    tcp::{DynTcpStream, FramedStream},
    tokio_util::codec::Framed,
    Stream,
};
use crate::client::Client;
use crate::kcp_stream::KcpStream;

/// True when the fleet-native path should be attempted: enrolled, and not disabled by option.
pub fn enabled() -> bool {
    crate::fgtw_auth::is_enrolled() && Config::get_option("enable-fgtw-native") != "N"
}

/// Debug switch: when `Y`, a fleet-native failure is fatal instead of falling back to rendezvous — so a broken native path is loud, not silently masked.
pub fn native_only() -> bool {
    Config::get_option("fgtw-native-only") == "Y"
}

/// Wrap a `RelayStream` (AsyncRead+AsyncWrite) into `hbb_common::Stream`, exactly the shape `kcp_stream::create_framed` produces — so the whole rustdesk protocol runs over it unchanged.
fn wrap(relay: RelayStream) -> Stream {
    Stream::Tcp(FramedStream(
        Framed::new(DynTcpStream(Box::new(relay)), BytesCodec::new()),
        Config::get_any_listen_addr(true),
        None,
        0,
    ))
}

/// Connect to a fleet peer and run the passless handshake: every direct path first (`fgtw_direct::dial` — TCP to its published addresses, KCP over UDP to its fleet socket with a hole punch), and the fgtw.org relay pipe only when none answers.
/// Returns `Client::start`'s tuple so the caller's contract is byte-identical: direct=true (no relay-server hop from rustdesk's point of view), the host's identity pk, the KCP guard when the path is UDP, and the path's label.
/// `Err` means "not a fleet peer" or every path and the handshake failed.
pub async fn connect(
    peer_id: &str,
    _key: &str,
) -> ResultType<(Stream, bool, Option<Vec<u8>>, Option<KcpStream>, &'static str)> {
    let id = peer_id.to_string();
    let (device, paths) = tokio::task::spawn_blocking(move || {
        crate::fgtw_auth::device_and_paths_for_rustdesk_id(&id)
    })
    .await
    .map_err(|e| anyhow!("fleet lookup join: {e}"))?
    .ok_or_else(|| anyhow!("{peer_id} is not a fleet peer with a published id"))?;

    if let Some(dialled) = crate::fgtw_direct::dial(peer_id, device, paths).await {
        return Ok(dialled);
    }
    log::info!("fgtw: no direct path to {peer_id} answered; using the fgtw.org relay");
    let client = client()?;
    let relay = client.open(device);
    let mut conn = wrap(relay);
    let pk = Client::secure_connection_fleet(Some(peer_id), &mut conn).await?;
    Ok((conn, true, pk, None, "FGTW"))
}

// ── accept seam (host side) ──

use crate::server::{ConnectionMeta, ServerPtr};

/// Host side: accept inbound fleet connections off the relay pipe and hand each to the normal connection path with `secure=true` — which makes the host send its `SignedId`, the basis of the passless handshake.
/// Spawned beside `direct_server`; re-acquires the accept channel if the pipe resets.
pub async fn fleet_server(server: ServerPtr) {
    loop {
        if !enabled() {
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            continue;
        }
        let client = match host_client() {
            Ok(c) => c,
            Err(e) => {
                log::warn!("fgtw fleet server: pipe unavailable ({e}); retrying");
                tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                continue;
            }
        };
        let mut rx = client.accept_channel();
        log::info!("fgtw fleet server: accepting relay connections");
        while let Some((relay, _peer_device)) = rx.recv().await {
            let server = server.clone();
            tokio::spawn(async move {
                let addr = Config::get_any_listen_addr(true);
                let stream = wrap(relay);
                if let Err(e) = crate::server::create_tcp_connection(
                    server,
                    stream,
                    addr,
                    true, // secure: the host must send its SignedId for the fleet handshake
                    ConnectionMeta::default(),
                )
                .await
                {
                    log::warn!("fgtw fleet accept failed: {e}");
                }
            });
        }
        log::warn!("fgtw fleet server: accept channel closed; re-acquiring");
    }
}
