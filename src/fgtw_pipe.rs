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

use fgtw::keys::Keypair;
use fgtw::pipe::{
    build_relay_envelope, peel_relay_envelope, RdFrame, RD_FLAG_FIN, RD_FLAG_SYN, SVC_RUSTDESK,
};

/// Max stream bytes per relay frame. Well under the worker's 1 MiB envelope cap, small enough to keep per-frame latency low on the video path.
const CHUNK: usize = 60 * 1024;

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

/// The live pipe. One per process, lazily built.
pub struct PipeClient {
    device_key: Arc<Keypair>,
    /// Sink: already-built envelope bytes to push up the WebSocket.
    out_tx: mpsc::UnboundedSender<Vec<u8>>,
    router: Arc<Router>,
}

static CLIENT: OnceLock<ResultType<Arc<PipeClient>>> = OnceLock::new();

/// The process-wide pipe client, connecting on first use. `Err` if we're not enrolled or the pipe can't be established — the caller falls back to the rendezvous path.
pub fn client() -> ResultType<Arc<PipeClient>> {
    // OnceLock can't hold a retryable Result cleanly; keep it simple — one attempt per process,
    // the connection task self-heals with reconnect once it exists.
    match CLIENT.get_or_init(PipeClient::connect) {
        Ok(c) => Ok(c.clone()),
        Err(e) => Err(anyhow!("fgtw pipe unavailable: {e}")),
    }
}

impl PipeClient {
    fn connect() -> ResultType<Arc<Self>> {
        let kp = crate::fgtw_auth::device_keypair()?;
        let device_key = Arc::new(kp);
        let (out_tx, out_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let router = Arc::new(Router {
            streams: Mutex::new(HashMap::new()),
            accept_tx: Mutex::new(None),
        });
        let self_pk = device_key.public.to_bytes();
        let host = seed_host();
        let router2 = router.clone();
        // The pump lives on rustdesk's tokio runtime. spawn requires being inside it; the connect callers (Client::_start, fleet_server) are async, so a handle exists.
        tokio::spawn(async move {
            pump(host, self_pk, out_rx, router2).await;
        });
        Ok(Arc::new(Self {
            device_key,
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

    /// Seal one frame to `peer` and push it up the pipe.
    fn send_frame(&self, peer: &[u8; 32], frame: &RdFrame) -> ResultType<()> {
        let env = build_relay_envelope(&self.device_key, peer, Some(SVC_RUSTDESK), &frame.encode())
            .map_err(|e| anyhow!("relay envelope: {e}"))?;
        self.out_tx
            .send(env)
            .map_err(|_| anyhow!("pipe writer gone"))?;
        Ok(())
    }

    /// Open an outbound stream to a fleet peer device (guest side).
    /// Fires an opening SYN immediately: the guest's first protocol act is to READ (wait for the host's SignedId), so without this the host would never learn a connection had started and never send it — an 18s deadlock.
    pub fn open(self: &Arc<Self>, peer: [u8; 32]) -> RelayStream {
        let conn = new_conn_id(&peer);
        let (in_tx, in_rx) = mpsc::unbounded_channel::<RdFrame>();
        self.register(conn, in_tx);
        let syn = RdFrame { conn, seq: 0, flags: RD_FLAG_SYN, data: Vec::new() };
        let _ = self.send_frame(&peer, &syn);
        // tx_seq starts at 1 — the SYN above took seq 0.
        RelayStream::new(self.clone(), peer, conn, in_rx, 1)
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

/// The socket pump: owns the WebSocket, reconnects with backoff, moves envelopes both ways.
async fn pump(
    host: String,
    self_pk: [u8; 32],
    mut out_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    router: Arc<Router>,
) {
    use futures_util::{SinkExt, StreamExt};
    use hbb_common::futures_util;
    use tokio_tungstenite::tungstenite::Message as Ws;

    let url = fgtw::pipe::pipe_url(&host, &self_pk, Some(SVC_RUSTDESK));
    let mut backoff = 1u64;
    loop {
        match tokio_tungstenite::connect_async(&url).await {
            Ok((ws, _)) => {
                backoff = 1;
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
                            Some(Ok(Ws::Binary(data))) => route_inbound(&router, &data),
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
        tokio::time::sleep(std::time::Duration::from_secs(backoff)).await;
        backoff = (backoff * 2).min(30);
    }
}

/// Peel one inbound envelope and hand its frame to the right stream (or accept a new one).
fn route_inbound(router: &Arc<Router>, data: &[u8]) {
    let Some((sender_device, inner)) = peel_relay_envelope(data) else {
        return; // unverifiable/garbage — drop, never fault
    };
    let Some(frame) = RdFrame::decode(&inner) else {
        return;
    };
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
            // The accepted stream needs a client handle to send replies; fetch the process one.
            if let Ok(client) = client() {
                let stream = RelayStream::new(client, sender_device, conn, in_rx, 0);
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
    /// Peer sent FIN — reads drain then EOF.
    peer_finished: bool,
}

impl RelayStream {
    fn new(
        client: Arc<PipeClient>,
        peer: [u8; 32],
        conn: ConnId,
        in_rx: mpsc::UnboundedReceiver<RdFrame>,
        start_seq: u64,
    ) -> Self {
        Self {
            client,
            peer,
            conn,
            in_rx,
            read_buf: BytesMut::new(),
            tx_seq: start_seq,
            rx_next: 0,
            reorder: std::collections::BTreeMap::new(),
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
            match self.in_rx.poll_recv(cx) {
                Poll::Ready(Some(frame)) => {
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
            if let Err(e) = self.client.send_frame(&self.peer, &frame) {
                return Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, e.to_string())));
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
        let _ = self.client.send_frame(&peer, &fin);
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

/// Connect to a fleet peer over the relay pipe and run the passless handshake.
/// Returns `Client::start`'s tuple so the caller's contract is byte-identical: direct=true (no relay-server hop from rustdesk's point of view), the host's identity pk, no KCP guard, label "FGTW".
/// `Err` means "not a fleet peer" or the pipe/handshake failed — the caller falls back to rendezvous.
pub async fn connect(
    peer_id: &str,
    _key: &str,
) -> ResultType<(Stream, bool, Option<Vec<u8>>, Option<KcpStream>, &'static str)> {
    let id = peer_id.to_string();
    let device = tokio::task::spawn_blocking(move || crate::fgtw_auth::device_for_rustdesk_id(&id))
        .await
        .map_err(|e| anyhow!("fleet lookup join: {e}"))?
        .ok_or_else(|| anyhow!("{peer_id} is not a fleet peer with a published id"))?;
    let client = client()?;
    let relay = client.open(device);
    let mut conn = wrap(relay);
    let pk = Client::secure_connection_fleet(peer_id, &mut conn).await?;
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
        let client = match client() {
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
