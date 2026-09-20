//! FGTW fleet authentication for RustDesk.
//!
//! Replaces the password/click trust layer for peers in the same FGTW fleet: both
//! sides use their fleet device key (Ed25519, derived from the machine fingerprint,
//! never stored) as their RustDesk identity keypair, and each verifies the other
//! against its own fleet membership fold. For fleet peers the rendezvous server drops
//! out of the trust path and login is authorized from channel state. Vanilla peers are
//! untouched — they never set the `PublicKey.fgtw` handshake field.
//!
//! This module owns three things: the HTTP transport binding fgtw's oracle to RustDesk's
//! reqwest stack, a PUBLIC chain cache (never a root), and the sign/verify halves of the
//! handshake. It is compiled only under the `fgtw` cargo feature.
//!
//! # Nothing secret touches disk
//!
//! The session roots (`handle_proof`, `identity_seed`) live in tohu's boot-locked session and
//! are read from there at every use — client-side only, since only a client acts on the fleet.
//! An earlier version copied them to `fgtw_auth.vsf` in plaintext at first adoption, which made
//! every device the "unattended reboot" case tohu refuses to make the default: a powered-off
//! stolen laptop came back as its owner, and the fleet's name sat readable on disk. That file is
//! scrubbed on sight.
//!
//! # The host is stateless
//!
//! A host holds one key — the device key, re-derived from the machine fingerprint — and needs no
//! session. The guest presents `handle_proof` in the handshake (verification-only material; it is
//! already the public registry slot key), the host fetches THAT fleet's chain, checks its own key
//! is in it (else a foreign fleet), then checks the guest's eggs against the bundle the chain
//! records for it, at the fleet's floor. Powered on ⇒ hosting; a locked or wiped device still
//! hosts, which is what lets the owner always reach it. The only thing cached is the chain's
//! public bytes, so hosting survives the fleet server being unreachable for a bounded time; a
//! reader of that cache learns which devices are in the fleet and nothing else.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use fgtw::client::{FgtwResponse, FgtwTransport};
use fgtw::fleet::{scheme, Egg, MembershipBlob};
use fgtw::keys::{derive_device_keypair, Keypair};
use fgtw::pq::{self, FleetSigner, KeyBundle, SigningBundle};
use hbb_common::config::Config;
use hbb_common::{log, ResultType};
use vsf::VsfType;

const FGTW_URL_DEFAULT: &str = "https://fgtw.org";
/// Domain separator for the handshake signature — binds the signed bytes to this
/// exact protocol so a signature can never be lifted into another context.
const HS_DOMAIN: &[u8] = b"fgtw-rustdesk-hs-v1";
/// The retired plaintext-roots file. Deleted whenever it is seen — it held `handle_proof` and `identity_seed` in the clear.
const LEGACY_STATE_FILE: &str = "fgtw_auth.vsf";
/// The public chain cache: the last verified membership chain's bytes and when they were fetched. Public data only.
const CHAIN_CACHE_FILE: &str = "fgtw_chain.vsf";
/// The schemes a per-connection epoch proof carries: Ed25519 + Falcon-512. SPHINCS+ is left to the chain, where an op is rare and archival — at 7.8 KB a signature it has no place on every handshake.
const EPOCH_TIER: scheme::Mask = scheme::MASK_BASE | (1 << scheme::FALCON512);
/// Default max age (seconds) of a cached member set used when the fleet server is
/// unreachable. Beyond this, an incoming fleet auth is denied rather than trusted stale.
const CACHE_MAX_AGE_DEFAULT: u64 = 3600;
const AUTH_TIMEOUT_SECS: u64 = 3;
const ENROLL_TIMEOUT_SECS: u64 = 15;

// ── transport ──

/// RustDesk's HTTP reach to FGTW: a blocking POST over the app's configured reqwest
/// client (proxy + TLS settings honored), handing fgtw back `{status, body}` so the
/// crate owns all `error`-frame / success interpretation.
pub struct RdTransport {
    timeout: std::time::Duration,
}

impl RdTransport {
    pub fn auth() -> Self {
        Self { timeout: std::time::Duration::from_secs(AUTH_TIMEOUT_SECS) }
    }
    pub fn enroll() -> Self {
        Self { timeout: std::time::Duration::from_secs(ENROLL_TIMEOUT_SECS) }
    }
    fn url() -> String {
        let u = Config::get_option("fgtw-url");
        if u.is_empty() { FGTW_URL_DEFAULT.to_owned() } else { u }
    }
}

impl FgtwTransport for RdTransport {
    fn post(&self, body: Vec<u8>) -> Result<FgtwResponse, String> {
        let url = Self::url();
        let client = crate::hbbs_http::create_http_client_with_url(&url);
        let resp = client
            .post(&url)
            .timeout(self.timeout)
            .header("Content-Type", "application/octet-stream")
            .body(body)
            .send()
            .map_err(|e| format!("reach FGTW: {e}"))?;
        let status = resp.status().as_u16();
        let body = resp.bytes().map_err(|e| format!("reach FGTW: {e}"))?.to_vec();
        Ok(FgtwResponse { status, body })
    }
}

// ── device identity ──

/// The machine fingerprint. Delegates to tohu's per-platform oracle; a dev-only env
/// override lets a second instance masquerade as a different device for local testing.
pub fn machine_fingerprint() -> ResultType<Vec<u8>> {
    #[cfg(debug_assertions)]
    if let Ok(fp) = std::env::var("RUSTDESK_FGTW_FINGERPRINT") {
        if !fp.is_empty() {
            return Ok(fp.into_bytes());
        }
    }
    Ok(tohu::device::machine_fingerprint()?)
}

/// The fgtw seed URL for this fork — the `fgtw-url` option, defaulting to fgtw.org. Public so
/// the relay-pipe transport derives its WebSocket host from the same source as everything else.
pub fn fgtw_url() -> String {
    let u = Config::get_option("fgtw-url");
    if u.is_empty() { FGTW_URL_DEFAULT.to_owned() } else { u }
}

/// The fleet device keypair for this machine — the same keypair photon derives, because
/// both hash the same oracle bytes into the same Ed25519 seed.
pub fn device_keypair() -> ResultType<Keypair> {
    Ok(derive_device_keypair(&machine_fingerprint()?))
}

// ── roots: read from the session, never from disk ──

/// The fleet identity this device acts under, from tohu's boot-locked session: `(handle_proof, identity_seed)`. `None` when nobody is logged in on this machine — and then this device can HOST but cannot act as a client, because nothing on disk stands in for the session.
fn session_roots() -> Option<([u8; 32], [u8; 32])> {
    let s = tohu::session()?;
    Some((s.handle_proof, s.identity_seed))
}

/// This device's full signing bundle — Ed25519 plus Falcon-512 and SPHINCS+, all derived from the machine fingerprint — computed once per process. Derivation costs about a second of SLH-DSA keygen, which is far too much per handshake and exactly right per launch.
fn signing_bundle() -> Option<&'static SigningBundle> {
    static B: OnceLock<Option<SigningBundle>> = OnceLock::new();
    B.get_or_init(|| machine_fingerprint().ok().map(|fp| SigningBundle::derive(&fp))).as_ref()
}

// ── the public chain cache ──

/// The last verified membership chain, kept so a host can verify guests while the fleet server is unreachable (within `fgtw-cache-max-age`). PUBLIC data: the worker serves these bytes to anyone holding the slot key. Holds no root — the fleet it belongs to is named by the chain's own genesis, and this device's membership by the fold.
#[derive(Clone)]
pub struct ChainCache {
    pub blob: Vec<u8>,
    /// The last verified fan-out DOCUMENT (the signed `fanout_put` the worker stored), so a host can re-run the provenance check and read the epoch public bundle while the fleet server is unreachable. Public: the worker serves it to anyone holding the slot key.
    pub fanout_doc: Option<Vec<u8>>,
    pub fetched_at: u64,
}

fn cache_path() -> PathBuf {
    Config::path(CHAIN_CACHE_FILE)
}

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

impl ChainCache {
    pub fn to_bytes(&self) -> Result<Vec<u8>, String> {
        let mut section = vsf::VsfSection::new("fgtw_chain");
        section.add_field("cb", VsfType::ge(self.blob.clone()));
        if let Some(fd) = &self.fanout_doc {
            section.add_field("fd", VsfType::ge(fd.clone()));
        }
        // Fixed 8-byte LE, not VSF's auto-sized int: the `i`/`u` variants re-type on decode, so raw bytes round-trip cleanly.
        section.add_field("at", VsfType::hR(self.fetched_at.to_le_bytes().to_vec()));
        vsf::VsfBuilder::new()
            .creation_time_oscillations(vsf::eagle_time_oscillations())
            .add_section_direct(section)
            .build()
            .map_err(|e| format!("encode chain cache: {e}"))
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        let (_, header_end) = vsf::verification::read_verified(bytes, None).map_err(|e| format!("chain cache: {e}"))?;
        let mut ptr = header_end;
        let section = vsf::VsfSection::parse(bytes, &mut ptr).map_err(|e| format!("chain cache section: {e}"))?;
        let blob = match section.get_field("cb").and_then(|f| f.values.first()) {
            Some(VsfType::ge(b)) if !b.is_empty() => b.clone(),
            _ => return Err("chain cache: missing chain bytes".into()),
        };
        let fetched_at = match section.get_field("at").and_then(|f| f.values.first()) {
            Some(VsfType::hR(b)) if b.len() == 8 => u64::from_le_bytes(b.as_slice().try_into().unwrap()),
            _ => 0,
        };
        let fanout_doc = match section.get_field("fd").and_then(|f| f.values.first()) {
            Some(VsfType::ge(b)) if !b.is_empty() => Some(b.clone()),
            _ => None,
        };
        Ok(Self { blob, fanout_doc, fetched_at })
    }

    pub fn load() -> Option<Self> {
        scrub_legacy_state();
        let bytes = std::fs::read(cache_path()).ok()?;
        match Self::from_bytes(&bytes) {
            Ok(c) => Some(c),
            Err(e) => {
                log::warn!("fgtw chain cache unreadable: {e}");
                None
            }
        }
    }

    pub fn save(&self) -> Result<(), String> {
        let bytes = self.to_bytes()?;
        let path = cache_path();
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| format!("create fgtw cache dir: {e}"))?;
        }
        std::fs::write(&path, bytes).map_err(|e| format!("write fgtw chain cache: {e}"))
    }

    /// The chain this cache holds, if it still parses.
    fn chain(&self) -> Option<MembershipBlob> {
        MembershipBlob::from_vsf_bytes(&self.blob).ok()
    }
}

/// Delete the retired plaintext-roots file if it is still here. It held `handle_proof` and `identity_seed` in the clear, which is the one thing this module must never leave on disk again.
fn scrub_legacy_state() {
    let legacy = Config::path(LEGACY_STATE_FILE);
    if legacy.exists() {
        match std::fs::remove_file(&legacy) {
            Ok(()) => log::warn!("fgtw: removed legacy plaintext enroll state {}", legacy.display()),
            Err(e) => log::error!("fgtw: could not remove legacy plaintext enroll state {}: {e}", legacy.display()),
        }
    }
}

/// Can this machine act in a fleet at all? A logged-in session makes it a client; a cached chain makes it a host that can verify guests offline. Neither implies the other.
pub fn is_enrolled() -> bool {
    scrub_legacy_state();
    session_roots().is_some() || cache_path().exists()
}

// ── pending handshake auth ──
//
// The handshake is verified in the TCP-accept path (server.rs), where the client's box key
// and our identity key are both in hand, but the login decision happens later in the
// Connection state machine (connection.rs). We bridge the two by connection id rather than
// threading a new field through ConnectionMeta / Connection::start — one insert at handshake,
// one take at first login. Entries are created only on a VALID fleet handshake.

fn pending() -> &'static Mutex<HashMap<i32, [u8; 32]>> {
    static P: OnceLock<Mutex<HashMap<i32, [u8; 32]>>> = OnceLock::new();
    P.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Record that connection `id` completed a valid fleet handshake as `device_pk`.
pub fn remember_authed(id: i32, device_pk: [u8; 32]) {
    if let Ok(mut m) = pending().lock() {
        m.insert(id, device_pk);
    }
}

/// Take (and clear) the fleet-authenticated device pubkey for connection `id`, if any.
pub fn take_authed(id: i32) -> Option<[u8; 32]> {
    pending().lock().ok().and_then(|mut m| m.remove(&id))
}

/// Drop any pending entry for `id` (connection closed before login).
pub fn forget_authed(id: i32) {
    if let Ok(mut m) = pending().lock() {
        m.remove(&id);
    }
}

// ── membership freshness ──

fn cache_max_age() -> u64 {
    let v = Config::get_option("fgtw-cache-max-age");
    v.parse().unwrap_or(CACHE_MAX_AGE_DEFAULT)
}

/// The membership chain for `handle_proof`, fetched from FGTW when reachable, else the cached chain within the staleness bound. Adopts a fresh chain only when its tip is `>=` the cached tip (monotonic guard against a stale read overwriting a post-removal set). Updates the cache on a successful refresh. `Err` when neither a fresh nor a fresh-enough cached chain is available.
///
/// The cache is only ever written with a chain THIS device is a member of, so it always names this device's own fleet. A guest naming a foreign fleet gets a live fetch and, on failure, no fallback — there is nothing legitimate to fall back to.
fn current_chain(handle_proof: &[u8; 32]) -> Result<MembershipBlob, String> {
    let cached = ChainCache::load();
    let cached_chain = cached.as_ref().and_then(|c| c.chain());
    let cached_is_this_fleet = cached_chain.as_ref().and_then(|c| c.genesis_handle_proof()) == Some(*handle_proof);
    let cached_tip = cached_chain.as_ref().and_then(|c| c.fold_with_ts().ok()).map(|(_, t)| t).unwrap_or(i64::MIN);
    match fgtw::client::fetch(&RdTransport::auth(), handle_proof) {
        Ok(Some(fresh)) => {
            let (members, tip) = fresh.fold_with_ts().map_err(|e| format!("fetched fleet does not fold: {e:?}"))?;
            if cached_is_this_fleet && tip < cached_tip {
                // Fresh fetch is older than what we hold (eventual-consistency lag) — keep cached.
                return Ok(cached_chain.unwrap());
            }
            // Cache only our own fleet: a chain we are a member of.
            if let Ok(me) = device_keypair() {
                if members.contains(&me.public.to_bytes()) {
                    // Keep the fan-out document we already hold; the epoch check refreshes it separately.
                    let fanout_doc = cached.as_ref().and_then(|c| c.fanout_doc.clone());
                    if let Err(e) = (ChainCache { blob: fresh.to_vsf_bytes().map_err(|e| format!("{e}"))?, fanout_doc, fetched_at: now_secs() }).save() {
                        log::warn!("fgtw cache update failed: {e}");
                    }
                }
            }
            Ok(fresh)
        }
        Ok(None) => Err("no fleet chain exists for that identity".into()),
        Err(e) => {
            let Some(c) = cached else { return Err(format!("fgtw unreachable and no cached chain: {e}")) };
            if !cached_is_this_fleet {
                return Err(format!("fgtw unreachable and the cached chain is for a different fleet: {e}"));
            }
            let age = now_secs().saturating_sub(c.fetched_at);
            if age <= cache_max_age() {
                log::info!("fgtw offline ({e}); using cached fleet chain ({age}s old)");
                cached_chain.ok_or_else(|| "cached chain unreadable".to_string())
            } else {
                Err(format!("fgtw unreachable and cache stale ({age}s): {e}"))
            }
        }
    }
}

/// The fleet's current fan-out with its provenance verified from public data — the envelope signature, its signer being the rotator, the rotator being in `members` — so a stateless host can read the epoch public bundle it checks a guest's proof against. Cached alongside the chain; offline, the cached document is re-verified against the (cached) member set within the same staleness bound.
fn current_fanout(handle_proof: &[u8; 32], members: &[[u8; 32]]) -> Result<fgtw::fanout::Fanout, String> {
    match fgtw::client::fetch_fanout_verified(&RdTransport::auth(), handle_proof, members) {
        Ok(Some((f, doc))) => {
            if let Some(mut c) = ChainCache::load() {
                c.fanout_doc = Some(doc);
                if let Err(e) = c.save() {
                    log::warn!("fgtw fan-out cache update failed: {e}");
                }
            }
            Ok(f)
        }
        Ok(None) => Err("no fan-out published for this fleet".into()),
        Err(e) => {
            let c = ChainCache::load().ok_or_else(|| format!("fgtw unreachable and no cached fan-out: {e}"))?;
            let age = now_secs().saturating_sub(c.fetched_at);
            if age > cache_max_age() {
                return Err(format!("fgtw unreachable and cache stale ({age}s): {e}"));
            }
            let doc = c.fanout_doc.ok_or_else(|| format!("fgtw unreachable and no cached fan-out: {e}"))?;
            log::info!("fgtw offline ({e}); using cached fan-out ({age}s old)");
            fgtw::client::verify_fanout_doc(&doc, members)
        }
    }
}

// ── fleet-shared state (device chooser) ──
//
// Each device publishes its own RustDesk ID into the fleet's sealed device-settings map
// (fgtw::fstate DeviceSettings — per-device, single-writer, CRDT-merged), and the chooser
// reads the map back to render "My Fleet": every member pubkey named by device_name_default
// plus the RustDesk ID to hand to the ordinary rendezvous connect path. The rendezvous
// server keeps doing discovery + NAT traversal only; trust stays with the FGTW handshake.
// The map is sealed under the fan-out fleet key, so a revoked device (absent from the next
// epoch's fan-out) can't even read the roster.

/// Settings key under which a device publishes its RustDesk ID in its own device map.
const SETTING_RUSTDESK_ID: &str = "rustdesk.id";
/// This device's LAN address (`ip:port`) for its direct server, published so a fleet peer on
/// the same network dials it directly instead of paying a WAN round trip through the relay.
const SETTING_RUSTDESK_LAN: &str = "rustdesk.lan";

/// EVERY address a peer on our network could dial us at, as `ip:port`, comma-joined.
///
/// Publishing one address is not enough: the routing lookup only ever names the interface that
/// reaches the internet, so a machine wired AND wireless publishes exactly one of the two — and
/// if a peer cannot use that one, the direct path is invisible even though a working address
/// existed the whole time (field: a host published its wifi address while its ethernet was the
/// reachable one, and every session fell back to the relay). Photon solved this by gathering a
/// candidate SET and racing it; this is the same idea at the publish end.
fn own_lan_addrs() -> Vec<String> {
    let port = crate::rendezvous_mediator::get_direct_port();
    let mut out = Vec::new();
    for iface in default_net::get_interfaces() {
        for v4 in &iface.ipv4 {
            let ip = v4.addr;
            // Loopback is not reachable from anywhere else; link-local 169.254 means DHCP never
            // answered, so nothing is listening for us on it either.
            if ip.is_loopback() || ip.is_unspecified() || ip.is_link_local() {
                continue;
            }
            let addr = format!("{ip}:{port}");
            if !out.contains(&addr) {
                out.push(addr);
            }
        }
    }
    out
}
/// Photon's per-device display name, keyed `fleet.name.<pubkey hex>` in the fleet-global layer.
const SETTING_NAME_PREFIX: &str = "fleet.name.";

/// 64 hex chars back to a device pubkey; `None` for anything malformed.
fn decode_pubkey_hex(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(hex.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

/// Fleet-state AEAD, wire-compatible with photon's `kete`: `random 24-byte nonce ‖
/// XChaCha20-Poly1305 ct` since the 2026-08-18 stack-wide migration, so rustdesk and photon
/// devices share one fleet-state blob. `open` read-boths the legacy 12-byte ChaCha20 form,
/// mirroring `fgtw::scoped_blob::open_content`, so pre-migration blobs still open.
struct RdSealer;

impl fgtw::client::FleetSealer for RdSealer {
    fn seal(&self, plaintext: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, String> {
        use chacha20poly1305::aead::{Aead, KeyInit};
        use chacha20poly1305::{XChaCha20Poly1305, XNonce};
        use hbb_common::rand::RngCore;
        let cipher = XChaCha20Poly1305::new(key.into());
        let mut nonce_bytes = [0u8; 24];
        hbb_common::rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let ct = cipher
            .encrypt(&XNonce::from(nonce_bytes), plaintext)
            .map_err(|e| format!("fgtw seal: {e}"))?;
        let mut out = Vec::with_capacity(24 + ct.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    fn open(&self, sealed: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, String> {
        use chacha20poly1305::aead::{Aead, KeyInit};
        use chacha20poly1305::{ChaCha20Poly1305, Nonce, XChaCha20Poly1305, XNonce};
        // Read-both: current XChaCha20 ([nonce:24][ct]), then legacy ChaCha20 ([nonce:12][ct]).
        if sealed.len() >= 24 + 16 {
            if let Ok(n) = XNonce::try_from(&sealed[..24]) {
                if let Ok(pt) = XChaCha20Poly1305::new(key.into()).decrypt(&n, &sealed[24..]) {
                    return Ok(pt);
                }
            }
        }
        if sealed.len() < 12 + 16 {
            return Err(format!("fgtw open: blob too short ({} bytes)", sealed.len()));
        }
        let (nonce_bytes, ct) = sealed.split_at(12);
        let nonce = Nonce::try_from(nonce_bytes).map_err(|_| "fgtw open: bad nonce".to_string())?;
        ChaCha20Poly1305::new(key.into())
            .decrypt(&nonce, ct)
            .map_err(|e| format!("fgtw open: {e}"))
    }
}

/// The fleet key for this device, or why we can't have it right now. `recover_or_establish`
/// mints epoch 1 when this device is the genesis founder; a freshly-paired device whose wrap
/// hasn't been rotated in yet gets `None` — that's the two-phase gate, not an error.
fn fleet_key(t: &RdTransport, handle_proof: &[u8; 32], identity_seed: &[u8; 32]) -> Result<[u8; 32], String> {
    let kp = device_keypair().map_err(|e| e.to_string())?;
    fgtw::client::recover_or_establish_fleet_key(t, handle_proof, &kp, identity_seed)?
        .ok_or_else(|| "no fleet-key wrap for this device yet (awaiting sponsor rotation)".into())
}

/// Publish this device's RustDesk ID into its own fleet device-settings map.
/// Pull-merge-push (like photon's push_roster) so sibling maps and the roster ride along
/// untouched. Best-effort: chooser data, not auth — failure is logged, never fatal, and the
/// next enroll/ID-change retries.
pub fn publish_own_id(handle_proof: &[u8; 32], identity_seed: &[u8; 32], device_key: &Keypair) {
    match publish_own_id_inner(handle_proof, identity_seed, device_key) {
        Ok(()) => log::info!("fgtw: published this device's rustdesk id ({}) to the fleet", Config::get_id()),
        Err(e) => log::warn!("fgtw: publishing rustdesk id to fleet failed (will retry later): {e}"),
    }
}

fn publish_own_id_inner(handle_proof: &[u8; 32], identity_seed: &[u8; 32], device_key: &Keypair) -> Result<(), String> {
    use fgtw::fstate::{DeviceSetting, DeviceSettings};
    let t = RdTransport::enroll();
    let key = fleet_key(&t, handle_proof, identity_seed)?;
    let mut fs = fgtw::client::pull_fstate(&t, &RdSealer, handle_proof, &key)?
        .unwrap_or_default();
    let me = device_key.public.to_bytes();
    let now = vsf::eagle_time_oscillations();
    // The id, plus our LAN address when we have one — both per-device, never fleet-linked.
    let mut entries = vec![DeviceSetting {
        key: SETTING_RUSTDESK_ID.to_owned(),
        // fstate v7: setting values are typed VSF now. The RustDesk id is text → VsfType::x.
        value: VsfType::x(Config::get_id()),
        updated: now,
        linked: false, // per-device by nature; never follows a fleet-global value
    }];
    let lan = own_lan_addrs();
    if !lan.is_empty() {
        entries.push(DeviceSetting {
            key: SETTING_RUSTDESK_LAN.to_owned(),
            value: VsfType::x(lan.join(",")),
            updated: now,
            linked: false,
        });
    }
    match fs.device_settings.iter_mut().find(|d| d.device_pubkey == me) {
        Some(map) => {
            for entry in entries {
                match map.entries.iter_mut().find(|e| e.key == entry.key) {
                    Some(e) => *e = entry,
                    None => map.entries.push(entry),
                }
            }
            map.updated = now;
        }
        None => fs.device_settings.push(DeviceSettings {
            device_pubkey: me,
            updated: now,
            entries,
        }),
    }
    fgtw::client::push_fstate(&t, &RdSealer, handle_proof, device_key, &key, &fs)
}

/// Re-publish this device's RustDesk ID after it changed (e.g. the rendezvous server forced
/// a new one on UUID mismatch), so the fleet's chooser map tracks it. Off-thread — callers
/// sit in async/networking paths and publish_own_id blocks on HTTP. No-op when not enrolled.
pub fn republish_own_id() {
    // Publishing needs the fleet key, and the fleet key needs the session — a host alone has nothing to publish with.
    let Some((hp, seed)) = session_roots() else { return };
    std::thread::spawn(move || {
        let Ok(kp) = device_keypair() else { return };
        publish_own_id(&hp, &seed, &kp);
    });
}

/// This machine's own fleet-scoped name — the label every other fleet device shows for
/// us in its chooser (device_name_default over our pubkey + the identity seed). Pure
/// local derivation; `None` when not enrolled.
pub fn self_fleet_name() -> Option<String> {
    let (_, seed) = session_roots()?;
    let kp = device_keypair().ok()?;
    Some(fgtw::pair::device_name_default(&kp.public.to_bytes(), &seed))
}

/// Is this device's rustdesk relay pipe open right now? The seed answers with one bit.
/// `None` when the seed can't be reached — the caller shows "unknown" rather than guessing,
/// because calling a live device offline is worse than admitting we don't know.
pub fn pipe_alive(device_pubkey: &[u8; 32]) -> Option<bool> {
    let hex: String = device_pubkey.iter().map(|b| format!("{b:02x}")).collect();
    let url = format!(
        "{}/pipe-alive?dev={hex}&svc={}",
        fgtw_url(),
        fgtw::pipe::SVC_RUSTDESK
    );
    let client = crate::hbbs_http::create_http_client_with_url(&url);
    let resp = client
        .get(&url)
        .timeout(std::time::Duration::from_secs(AUTH_TIMEOUT_SECS))
        .send()
        .ok()?;
    if !resp.status().is_success() {
        return None;
    }
    Some(resp.text().ok()?.trim() == "1")
}

/// One fleet device as the chooser renders it.
pub struct FleetDevice {
    pub pubkey: [u8; 32],
    /// Fleet-scoped two-word default name (`device_name_default`); the roster petname
    /// supersedes this once roster sync lands.
    pub name: String,
    /// The device's RustDesk ID for the rendezvous connect path; `None` until that device
    /// has published it (older build, or publish still pending).
    pub rustdesk_id: Option<String>,
    /// True for this machine's own entry (the chooser greys it out).
    pub is_self: bool,
    /// Pipe open right now? `None` = the seed didn't answer, so reachability is unknown.
    pub online: Option<bool>,
    /// The device's published LAN address (`ip:port`), if it published one.
    pub lan_addr: Option<String>,
    /// The best direct path that answered a probe, if any — what the tile colours by.
    pub direct_tier: Option<fgtw::traverse::gather::PathTier>,
}

/// The current fleet as a chooser list: every member (fresh fold, cache fallback within
/// bound) with its fleet-scoped name and, where published, its RustDesk ID. Liveness is the
/// rendezvous server's job — hand `rustdesk_id` to the normal connect path.
/// Reverse-map a peer's RustDesk id to its fleet device pubkey, for the relay-pipe transport.
/// Blocking (folds the fleet + pulls the id map); the caller runs it off the async runtime.
/// `None` when we're not enrolled, the peer isn't in the fleet, or hasn't published an id yet.
pub fn device_for_rustdesk_id(id: &str) -> Option<[u8; 32]> {
    device_and_lan_for_rustdesk_id(id).map(|(pk, _)| pk)
}

/// Our own LAN v4, for the same-subnet judgment the tier classifier needs.
pub fn our_lan_v4() -> Option<std::net::Ipv4Addr> {
    let sock = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.connect("1.1.1.1:80").ok()?; // routing lookup only, sends nothing
    match sock.local_addr().ok()?.ip() {
        std::net::IpAddr::V4(ip) => Some(ip),
        _ => None,
    }
}

/// Does any of a device's published LAN addresses answer right now?
/// A tile that only knows "the relay pipe is open" cannot tell a peer in the same room from one
/// on another continent — both are merely reachable. One short connect per candidate is what
/// separates them, and it is the same probe the dialler would make anyway.
pub fn probe_lan_tier(lan: &Option<String>) -> Option<fgtw::traverse::gather::PathTier> {
    use fgtw::traverse::gather::PathTier;
    let list = lan.as_ref()?;
    let ours = our_lan_v4();
    let mut best: Option<PathTier> = None;
    for addr in list.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()) {
        let Ok(addrs) = std::net::ToSocketAddrs::to_socket_addrs(&addr) else { continue };
        for sa in addrs {
            // Short: a peer on our own network answers in single-digit ms, and a dead address
            // must not stall the roster the fleet page is waiting on.
            if std::net::TcpStream::connect_timeout(&sa, std::time::Duration::from_millis(250))
                .is_ok()
            {
                let tier = fgtw::traverse::gather::classify_path(&sa, ours);
                // Probe EVERY address and keep the best. Stopping at the first hit would report
                // whichever answered soonest, which is not the same as the best path available —
                // a router-free link can easily answer after a LAN one.
                if best.map_or(true, |b| tier < b) {
                    best = Some(tier);
                }
            }
        }
    }
    best
}

/// Ping every way we know of reaching a device and report the BEST tier that answers.
///
/// Direct addresses first, then the relay as the floor: a device that answers nothing directly
/// but whose pipe is open is reachable, just expensively. `None` means genuinely nothing
/// answered — offline.
pub fn probe_best_tier(
    device: &[u8; 32],
    lan: &Option<String>,
) -> Option<fgtw::traverse::gather::PathTier> {
    use fgtw::traverse::gather::PathTier;
    if let Some(t) = probe_lan_tier(lan) {
        return Some(t);
    }
    match pipe_alive(device) {
        Some(true) => Some(PathTier::Relay),
        _ => None,
    }
}

/// The fleet device behind a RustDesk id, plus its published LAN address if it has one.
/// One roster pull serves both, so trying the LAN path costs no extra round trip.
pub fn device_and_lan_for_rustdesk_id(id: &str) -> Option<([u8; 32], Option<String>)> {
    fleet_roster()
        .ok()?
        .into_iter()
        .find(|d| !d.is_self && d.rustdesk_id.as_deref() == Some(id))
        .map(|d| (d.pubkey, d.lan_addr))
}

pub fn fleet_roster() -> Result<Vec<FleetDevice>, String> {
    let (hp, seed) = session_roots().ok_or("not logged in on this machine")?;
    let members = current_chain(&hp)?.fold().map_err(|e| format!("fleet does not fold: {e:?}"))?;
    let me = device_keypair().map(|k| k.public.to_bytes()).ok();
    // ID map is best-effort: an unreachable slot or missing wrap degrades to names-only.
    #[allow(clippy::type_complexity)]
    let ((ids, lans), names): ((HashMap<[u8; 32], String>, HashMap<[u8; 32], String>), HashMap<[u8; 32], String>) = (|| -> Result<_, String> {
        let t = RdTransport::auth();
        let key = fleet_key(&t, &hp, &seed)?;
        let fs = fgtw::client::pull_fstate(&t, &RdSealer, &hp, &key)?
            .unwrap_or_default();
        // Names the user set in photon's Fleet page. Photon writes `fleet.name.<pkhex>` as a
        // fleet-LINKED setting, so the value lives in the fleet-global layer, not the authoring
        // device's own map. Same blob we already fetched for the ids — no extra round trip.
        let names = fs
            .global_settings
            .iter()
            .filter_map(|e| {
                let hex = e.key.strip_prefix(SETTING_NAME_PREFIX)?;
                let raw = decode_pubkey_hex(hex)?;
                match &e.value {
                    VsfType::x(n) if !n.trim().is_empty() => Some((raw, n.trim().to_owned())),
                    _ => None,
                }
            })
            .collect();
        let mut ids = HashMap::new();
        let mut lans = HashMap::new();
        for d in fs.device_settings.into_iter() {
            for e in d.entries.into_iter() {
                // Both written as VsfType::x (text) by publish_own_id_inner above.
                let VsfType::x(v) = e.value else { continue };
                match e.key.as_str() {
                    SETTING_RUSTDESK_ID => {
                        ids.insert(d.device_pubkey, v);
                    }
                    SETTING_RUSTDESK_LAN => {
                        lans.insert(d.device_pubkey, v);
                    }
                    _ => {}
                }
            }
        }
        Ok(((ids, lans), names))
    })()
    .unwrap_or_else(|e| {
        log::warn!("fgtw: fleet id map unavailable ({e}); chooser degrades to names-only");
        ((HashMap::new(), HashMap::new()), HashMap::new())
    });
    Ok(members
        .iter()
        .map(|m| FleetDevice {
            pubkey: *m,
            // The name the user set in photon wins; the deterministic two-word default is the fallback.
            name: names
                .get(m)
                .cloned()
                .unwrap_or_else(|| fgtw::pair::device_name_default(m, &seed)),
            rustdesk_id: ids.get(m).cloned(),
            is_self: me == Some(*m),
            // Only probe peers: our own pipe's state is not interesting and would cost a round trip per refresh.
            online: if me == Some(*m) { None } else { pipe_alive(m) },
            direct_tier: if me == Some(*m) {
                None
            } else {
                probe_lan_tier(&lans.get(m).cloned())
            },
            lan_addr: lans.get(m).cloned(),
        })
        .collect())
}

// ── handshake payload ──

/// Why an incoming fleet handshake was rejected. `Ok` authorizes the connection.
#[derive(Debug, PartialEq, Eq)]
pub enum FgtwVerdict {
    Ok,
    /// This host has no device key to verify with — the machine fingerprint is unavailable.
    NotEnrolled,
    BadPayload,
    BadSignature,
    /// The guest is not a current member of the fleet it named.
    NotMember,
    /// The guest named a fleet THIS host is not a member of. A host only ever accepts its own fleet.
    ForeignFleet,
    /// The guest is in the chain but could not prove the CURRENT epoch — it holds no wrap under the re-minted fleet key. Lock-out, or a departed device, or a fresh bind awaiting its sponsor's grow. Membership is not enough; the epoch is what lock-out removes.
    LockedOut,
    StaleCache,
}

impl FgtwVerdict {
    pub fn is_ok(&self) -> bool {
        matches!(self, FgtwVerdict::Ok)
    }
}

/// The bytes both sides sign/verify: domain-tagged, binding the FLEET, the client's fresh per-connection box public key, and the host's stable identity key. A relayed signature is useless (the MITM lacks the box secret), it cannot be replayed against a different host, and it cannot be replayed into a different fleet.
fn hs_digest(handle_proof: &[u8; 32], client_box_pk: &[u8; 32], host_sign_pk: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(HS_DOMAIN);
    h.update(handle_proof);
    h.update(client_box_pk);
    h.update(host_sign_pk);
    *h.finalize().as_bytes()
}

/// Encode a handshake payload: VSF `{hp, dk, eggs, ee?}` — the fleet, the guest's device key, its device egg list over [`hs_digest`], and (when it holds the current fleet key) its EPOCH egg list over the same digest under the fleet's epoch bundle. Separated from [`build_hs_payload`] so tests can drive it with chosen signers and masks.
fn encode_hs_payload(handle_proof: &[u8; 32], device_pubkey: &[u8; 32], eggs: &[Egg], epoch_eggs: Option<&[Egg]>) -> Option<Vec<u8>> {
    let mut section = vsf::VsfSection::new("fgtw_hs");
    section.add_field("hp", VsfType::hP(handle_proof.to_vec()));
    section.add_field("dk", VsfType::ke(device_pubkey.to_vec()));
    section.add_field("eggs", VsfType::ge(pq::eggs_to_bytes(eggs)));
    if let Some(ee) = epoch_eggs {
        section.add_field("ee", VsfType::ge(pq::eggs_to_bytes(ee)));
    }
    vsf::VsfBuilder::new()
        .creation_time_oscillations(vsf::eagle_time_oscillations())
        .add_section_direct(section)
        .build()
        .ok()
}

/// Build the client's `PublicKey.fgtw` payload. `None` when nobody is logged in on this machine — a device without a session cannot act as a client, by construction: the fleet it would name lives only in the session.
///
/// Signs with every scheme the chain knows this device holds (its declared bundle, else Ed25519 alone). Emitting an egg the host has no key for would fail closed under the every-egg-must-verify rule, so the mask is read off the chain rather than assumed.
pub fn build_hs_payload(client_box_pk: &[u8; 32], host_sign_pk: &[u8; 32]) -> Option<Vec<u8>> {
    let (hp, seed) = session_roots()?;
    let kp = device_keypair().ok()?;
    let me = kp.public.to_bytes();
    let mask = current_chain(&hp).ok().map(|c| c.declared_mask(&me)).unwrap_or(scheme::MASK_BASE);
    let digest = hs_digest(&hp, client_box_pk, host_sign_pk);
    let eggs = match signing_bundle() {
        Some(b) => b.eggs(&digest, mask),
        None => kp.eggs(&digest, mask),
    };
    // The epoch proof: only a device holding the CURRENT fleet key — one with a wrap under it, i.e. an unlocked member of this epoch — can derive the epoch bundle. A locked device cannot, sends no `ee`, and the host refuses it as LockedOut. Nothing else in the handshake can stand in for this.
    let epoch_eggs = fgtw::client::recover_fleet_key(&RdTransport::auth(), &hp, &kp, &seed)
        .ok()
        .flatten()
        .map(|k| pq::epoch_bundle(&k).eggs(&digest, EPOCH_TIER));
    encode_hs_payload(&hp, &me, &eggs, epoch_eggs.as_deref())
}

/// `(handle_proof, device_pubkey, eggs, epoch_eggs)` from a payload, or `None` if it is not a well-formed handshake. `epoch_eggs` is `None` when the guest sent none — which the host treats as "cannot prove the current epoch".
fn parse_hs_payload(payload: &[u8]) -> Option<([u8; 32], [u8; 32], Vec<Egg>, Option<Vec<Egg>>)> {
    let (_, header_end) = vsf::verification::read_verified(payload, None).ok()?;
    let mut ptr = header_end;
    // Near-form sections are anonymous on the wire (the name lives in the header TOC and comes back empty here), so we gate on field presence, not section.name. The verified read above already rejects tampered/foreign bytes; the eggs are the real authenticity check.
    let section = vsf::VsfSection::parse(payload, &mut ptr).ok()?;
    let take32 = |name: &str| -> Option<[u8; 32]> {
        match section.get_field(name).and_then(|f| f.values.first()) {
            Some(VsfType::hP(b)) | Some(VsfType::ke(b)) if b.len() == 32 => {
                let mut a = [0u8; 32];
                a.copy_from_slice(b);
                Some(a)
            }
            _ => None,
        }
    };
    let hp = take32("hp")?;
    let dk = take32("dk")?;
    let eggs = match section.get_field("eggs").and_then(|f| f.values.first()) {
        Some(VsfType::ge(b)) => pq::eggs_from_bytes(b).ok()?,
        _ => return None,
    };
    let epoch_eggs = match section.get_field("ee").and_then(|f| f.values.first()) {
        Some(VsfType::ge(b)) => Some(pq::eggs_from_bytes(b).ok()?),
        _ => None,
    };
    Some((hp, dk, eggs, epoch_eggs))
}

/// Host side, STATELESS: verify an incoming `PublicKey.fgtw` payload holding nothing but our own device key.
///
/// The guest names the fleet. We fetch that fleet's chain (cache within bound when offline), require that WE are a current member of it — a host only ever accepts its own fleet — then that the guest is, then verify the guest's eggs against the bundle the chain records for it, at the fleet's scheme floor. Returns the verified device pubkey.
///
/// Then the EPOCH: lock-out is a fan-out fact (no wrap under the re-minted key), not a chain fact, so chain membership alone would accept a locked device. The guest must also sign the digest under the fleet's epoch bundle — derivable only from the current fleet key — and the host verifies that against the epoch public bundle in the fan-out header, whose provenance it checks from public data (`fetch_fanout_verified`). A guest that cannot is `LockedOut`.
pub fn verify_hs_payload(
    payload: &[u8],
    client_box_pk: &[u8; 32],
    our_sign_pk: &[u8; 32],
) -> Result<[u8; 32], FgtwVerdict> {
    let me = device_keypair().map_err(|_| FgtwVerdict::NotEnrolled)?.public.to_bytes();
    let (hp, device_pk, eggs, epoch_eggs) = parse_hs_payload(payload).ok_or(FgtwVerdict::BadPayload)?;
    let chain = current_chain(&hp).map_err(|e| {
        log::warn!("fgtw membership check failed: {e}");
        FgtwVerdict::StaleCache
    })?;
    let (members, floor) = chain.fold_full().map_err(|_| FgtwVerdict::StaleCache)?;
    if !members.contains(&me) {
        return Err(FgtwVerdict::ForeignFleet);
    }
    if !members.contains(&device_pk) {
        return Err(FgtwVerdict::NotMember);
    }
    let bundle = chain.declared_bundle(&device_pk).unwrap_or_else(|| KeyBundle::ed25519_only(&device_pk));
    let digest = hs_digest(&hp, client_box_pk, our_sign_pk);
    if !pq::verify_eggs(&eggs, &bundle, &digest, floor) {
        return Err(FgtwVerdict::BadSignature);
    }
    // Identity proved; now the epoch.
    let Some(ee) = epoch_eggs else { return Err(FgtwVerdict::LockedOut) };
    let fanout = current_fanout(&hp, &members).map_err(|e| {
        log::warn!("fgtw epoch check unavailable: {e}");
        FgtwVerdict::StaleCache
    })?;
    if !pq::verify_eggs(&ee, &fanout.epoch_pub, &digest, EPOCH_TIER) {
        return Err(FgtwVerdict::LockedOut);
    }
    Ok(device_pk)
}

/// Client side: is `signed_id` (the host's `SignedId.id` bytes) signed by a device in OUR fleet? Tries each member pubkey as the verifying key over the `IdPk` bytes. Returns `(rustdesk_id, host_box_pk, host_device_sign_pk)` on the first hit — the third element is the host's identity key (rustdesk sign key == fleet device key, `seed_rustdesk_identity`), which the fleet handshake binds the client's box key to. `None` when nobody is logged in or the host isn't a fleet member.
pub fn verify_host_signed_id(signed_id: &[u8]) -> Option<(String, [u8; 32], [u8; 32])> {
    use hbb_common::sodiumoxide::crypto::sign;
    let (hp, _) = session_roots()?;
    let members = current_chain(&hp).ok()?.fold().ok()?;
    for m in &members {
        // Reuse rustdesk's own IdPk decode (verify sig + parse) — same path secure_connection uses.
        if let Ok((id, box_pk)) = crate::common::decode_id_pk(signed_id, &sign::PublicKey(*m)) {
            return Some((id, box_pk, *m));
        }
    }
    None
}

// ── session adoption (the passless path) ──

/// Act on this machine's login: read the tohu session (set by whichever app the user attested in — e.g. Photon) and prove membership with the FLEET KEY — if this device's key opens a wrap in the fleet's fan-out, the machine is a current member; no handle typed, no ceremony. Caches the fleet's PUBLIC chain (so this host can verify guests offline), seeds the RustDesk identity from the device key, publishes our RustDesk ID to the fleet's chooser map, and declares our key bundle to the chain.
///
/// Persists no root. Every later use reads the session again; when the session is gone this device stops being a client and keeps being a host.
///
/// `Err` means "couldn't adopt right now", not "unauthorized": no session, no wrap yet (freshly-bound device awaiting its sponsor's confirm rotation), or the fleet server unreachable.
pub fn adopt_session() -> Result<String, String> {
    let (hp, seed) = session_roots().ok_or("no session on this machine — log in (e.g. Photon), or run --fgtw-enroll <handle>")?;
    let device_key = device_keypair().map_err(|e| e.to_string())?;
    let t = RdTransport::enroll();
    // The fleet-key gate: only current members hold a wrap in the fan-out.
    fgtw::client::recover_fleet_key(&t, &hp, &device_key, &seed)?
        .ok_or("this device has no fleet-key wrap yet (not a member, or awaiting sponsor rotation)")?;
    let chain = current_chain(&hp)?;
    let members = chain.fold().map_err(|e| format!("fleet does not fold: {e:?}"))?;
    seed_rustdesk_identity(&device_key);
    publish_own_id(&hp, &seed, &device_key);
    declare_own_bundle(&hp);
    Ok(format!("Adopted session: fleet member on this machine ({} member(s)).", members.len()))
}

/// Publish this device's key bundle to the chain, off-thread — what lifts this device to three eggs, and, when the last member does it, lifts the fleet's floor. Idempotent; no-op for a device with nothing beyond Ed25519.
fn declare_own_bundle(handle_proof: &[u8; 32]) {
    let Some(bundle) = signing_bundle() else { return };
    let hp = *handle_proof;
    std::thread::spawn(move || match fgtw::client::declare_device(&RdTransport::enroll(), bundle, &hp) {
        Ok(()) => log::info!("fgtw: key bundle declared (or already on the chain)"),
        Err(e) => log::warn!("fgtw: key-bundle declare failed (will retry next start): {e}"),
    });
}

/// Best-effort background fleet bootstrap for service/UI startup, off-thread, never blocks. With a session: adopt it (idempotent — re-publishes our id every start because the id is what the My Fleet chooser connects by, and re-declares our bundle). Without one: this machine hosts only, and says so.
pub fn try_adopt_session() {
    scrub_legacy_state();
    std::thread::spawn(|| match adopt_session() {
        Ok(msg) => log::info!("fgtw: {msg}"),
        Err(e) => log::info!("fgtw: session adoption not available (hosting only): {e}"),
    });
}

// ── enrollment (CLI) ──

/// Enroll this machine into the fleet for `handle_input`. Creates the fleet genesis if none
/// exists; otherwise, if this device isn't a member yet, runs the pair-words flow and waits
/// for an already-enrolled device (e.g. Photon) to approve. Persists the verified member set
/// on success. Blocking + prints progress — it's a CLI command.
pub fn enroll(handle_input: &str) -> Result<String, String> {
    // Handles are byte-precise now (fgtw deleted the fold/canonical step) — use the input as-is.
    let handle = handle_input.to_string();
    println!("Deriving identity for \"{handle}\" (memory-hard, ~1s)...");
    let identity_seed = *ihi::handle_to_hash(&handle).as_bytes();
    let handle_proof = *ihi::handle_to_proof(&handle).as_bytes();
    // On success this bootstrap IS the machine's login: park the derived roots in the tohu
    // session registers so every other app (and future rustdesk runs) adopts them instead of
    // re-prompting for the handle. The string itself is dropped here, never stored.
    let session_regs = tohu::SessionIdentity {
        identity_seed,
        vault_seed: tohu::handle_seed(&handle),
        handle_proof,
    };
    let park_session = move || {
        if let Err(e) = tohu::set_session(&session_regs) {
            log::warn!("fgtw: couldn't park session registers: {e}");
        }
    };
    let device_key = device_keypair().map_err(|e| e.to_string())?;
    let me = device_key.public.to_bytes();
    let t = RdTransport::enroll();

    // ensure_member publishes a genesis then re-fetches to adjudicate; the fleet server's
    // storage is read-after-write eventually consistent, so a fresh genesis can miss its own
    // immediate re-fetch. Retry a few times — a later fetch sees the persisted chain.
    let mut last_err = String::new();
    let mut established = false;
    for attempt in 0..4 {
        match fgtw::client::ensure_member(&t, &device_key, &handle_proof, &identity_seed) {
            Ok(()) => {
                established = true;
                break;
            }
            // Not a member and a fleet already exists → must be added from an existing device.
            Err(e) if e.contains("enroll it from an existing device") => {
                park_session();
                return pair_flow(&t, &device_key, &handle_proof, &identity_seed);
            }
            Err(e) => {
                last_err = e;
                if attempt < 3 {
                    println!("  establishing fleet... (retry {})", attempt + 1);
                    std::thread::sleep(std::time::Duration::from_secs(2));
                }
            }
        }
    }
    if !established {
        return Err(last_err);
    }
    // The session must be parked BEFORE anything that reads roots, since nothing else holds them now.
    park_session();
    let members = current_chain(&handle_proof)?.fold().map_err(|e| format!("fleet does not fold: {e:?}"))?;
    seed_rustdesk_identity(&device_key);
    publish_own_id(&handle_proof, &identity_seed, &device_key);
    declare_own_bundle(&handle_proof);
    Ok(format!(
        "Enrolled. This device ({:02x?}…) is one of {} fleet member(s).",
        &me[..4],
        members.len()
    ))
}

/// Make RustDesk's identity keypair BE the fleet device key, so the host signs its `SignedId`
/// with the fleet key and fleet peers verify it against the membership fold. sodiumoxide's
/// Ed25519 secret key is the 64-byte `seed || public`; ed25519-dalek's `to_bytes()` is the
/// 32-byte seed — same algorithm, so a signature made by one verifies with the other.
fn seed_rustdesk_identity(device_key: &Keypair) {
    let seed = device_key.secret.to_bytes();
    let pk = device_key.public.to_bytes();
    let mut sk = Vec::with_capacity(64);
    sk.extend_from_slice(&seed);
    sk.extend_from_slice(&pk);
    Config::set_key_pair((sk, pk.to_vec()));
}

fn pair_flow(
    t: &RdTransport,
    device_key: &Keypair,
    handle_proof: &[u8; 32],
    identity_seed: &[u8; 32],
) -> Result<String, String> {
    let me = device_key.public.to_bytes();
    // Post the binding request: consent with every scheme we hold plus our bundle (a promoted fleet refuses a bare Ed25519 join), co-signed by the identity key (the registry write gate). No NFC secret from a CLI enroll — all-zero = none offered.
    match signing_bundle() {
        Some(b) => fgtw::client::bindreq_put(t, b, identity_seed, handle_proof, &[0u8; 32])?,
        None => fgtw::client::bindreq_put(t, device_key, identity_seed, handle_proof, &[0u8; 32])?,
    };
    println!("\nThis device isn't in the fleet yet. On an already-enrolled device (e.g. Photon),");
    println!("approve pairing for these words:\n");
    println!("    {}\n", fgtw::pair::masked_device_words(&me, identity_seed));
    println!("Waiting up to 5 minutes for approval...");
    // The approving device runs bind_device, which folds our pubkey into the chain; we detect
    // completion by our pubkey appearing in the current member set. The request stamp lapses
    // at 5 min, so re-post at ~3.5 min in case the human is slow to pick up the other device.
    for i in 0..150 {
        std::thread::sleep(std::time::Duration::from_secs(2));
        if i == 105 {
            let _ = match signing_bundle() {
                Some(b) => fgtw::client::bindreq_put(t, b, identity_seed, handle_proof, &[0u8; 32]),
                None => fgtw::client::bindreq_put(t, device_key, identity_seed, handle_proof, &[0u8; 32]),
            };
        }
        let (members, tip) = match fgtw::client::current_members_with_ts(t, handle_proof) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if members.contains(&me) {
            // Best-effort: clear our own request now that we're bound (else the stamp lapses).
            let _ = fgtw::client::bindreq_withdraw(t, device_key, handle_proof);
            let _ = tip;
            // Refresh the public chain cache now that we are in it.
            let _ = current_chain(handle_proof);
            seed_rustdesk_identity(device_key);
            publish_own_id(handle_proof, identity_seed, device_key);
            declare_own_bundle(handle_proof);
            return Ok(format!(
                "Paired. This device ({:02x?}…) is now one of {} fleet member(s).",
                &me[..4],
                members.len()
            ));
        }
    }
    Err("timed out waiting for approval".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kp(seed: u8) -> Keypair {
        Keypair::from_seed(&[seed; 32])
    }

    #[test]
    fn payload_round_trips_and_verifies_binding() {
        let dev = kp(7);
        let hp = [0xAB; 32];
        let box_pk = [3u8; 32];
        let host_pk = [9u8; 32];
        let eggs = dev.eggs(&hs_digest(&hp, &box_pk, &host_pk), scheme::MASK_BASE);
        let payload = encode_hs_payload(&hp, &dev.public.to_bytes(), &eggs, None).unwrap();
        let (parsed_hp, parsed_dk, parsed_eggs, parsed_ee) = parse_hs_payload(&payload).unwrap();
        assert_eq!(parsed_hp, hp);
        assert_eq!(parsed_dk, dev.public.to_bytes());
        assert_eq!(parsed_eggs, eggs);
        assert!(parsed_ee.is_none(), "no fleet key ⇒ no epoch proof on the wire");

        let bundle = KeyBundle::ed25519_only(&parsed_dk);
        // Right binding verifies.
        assert!(pq::verify_eggs(&parsed_eggs, &bundle, &hs_digest(&hp, &box_pk, &host_pk), scheme::MASK_BASE));
        // Wrong box key does not — the signature is channel-bound.
        assert!(!pq::verify_eggs(&parsed_eggs, &bundle, &hs_digest(&hp, &[4u8; 32], &host_pk), scheme::MASK_BASE));
        // Wrong fleet does not — it is fleet-bound too.
        assert!(!pq::verify_eggs(&parsed_eggs, &bundle, &hs_digest(&[0xCD; 32], &box_pk, &host_pk), scheme::MASK_BASE));
    }

    /// Three-egg handshake against a real chain: the host verifies the guest's Falcon and SPHINCS+ eggs against the bundle the CHAIN holds for it, and a short handshake fails once the fleet's floor has risen.
    #[test]
    fn three_egg_handshake_verifies_against_the_declared_bundle() {
        let host = SigningBundle::derive(b"host-machine");
        let guest = SigningBundle::derive(b"guest-machine");
        let hp = [0xAB; 32];
        let seed = [0x11; 32];
        let mut chain = MembershipBlob::genesis(&host, hp, &seed, 100);
        let gpk = guest.keypair().public.to_bytes();
        let msg = fgtw::fleet::bindreq_signing_bytes(&hp, &gpk, 190);
        chain.add_declared(&host, gpk, 200, 190, guest.eggs(&msg, scheme::MASK_ALL), guest.public());
        chain.declare(&host, 300);
        let (members, floor) = chain.fold_full().unwrap();
        assert_eq!(floor, scheme::MASK_ALL);
        assert!(members.contains(&gpk));

        let box_pk = [3u8; 32];
        let host_pk = host.keypair().public.to_bytes();
        let digest = hs_digest(&hp, &box_pk, &host_pk);
        let bundle = chain.declared_bundle(&gpk).unwrap();

        // Full eggs: verifies at the floor. The epoch half rides beside them, signed under the bundle only a current-key holder can derive.
        let fleet_key = [0x77u8; 32];
        let epoch = pq::epoch_bundle(&fleet_key);
        let full = guest.eggs(&digest, chain.declared_mask(&gpk));
        let ee = epoch.eggs(&digest, EPOCH_TIER);
        let (_, dk, eggs, parsed_ee) = parse_hs_payload(&encode_hs_payload(&hp, &gpk, &full, Some(&ee)).unwrap()).unwrap();
        assert!(pq::verify_eggs(&eggs, &bundle, &digest, floor));
        assert_eq!(dk, gpk);
        // The epoch proof verifies against the header's public bundle — and only under THIS epoch's key. A device holding the previous epoch's key (locked out at the re-mint) produces eggs that fail.
        let header_pub = epoch.public();
        assert!(pq::verify_eggs(&parsed_ee.unwrap(), &header_pub, &digest, EPOCH_TIER));
        let stale = pq::epoch_bundle(&[0x66u8; 32]).eggs(&digest, EPOCH_TIER);
        assert!(!pq::verify_eggs(&stale, &header_pub, &digest, EPOCH_TIER), "a previous epoch's key proves nothing");
        // Ed25519 alone: short of the floor, refused — the payload cannot be stripped down.
        let short = guest.keypair().eggs(&digest, scheme::MASK_BASE);
        assert!(!pq::verify_eggs(&short, &bundle, &digest, floor));
        // A tampered Falcon egg is rejected.
        let mut bad = full.clone();
        bad.iter_mut().find(|e| e.scheme == scheme::FALCON512).unwrap().sig[5] ^= 1;
        assert!(!pq::verify_eggs(&bad, &bundle, &digest, floor));
    }

    #[test]
    fn sodiumoxide_and_dalek_sign_interop() {
        // Load-bearing: the host signs its SignedId with sodiumoxide using the seed||pk secret
        // key we seed from the fgtw device key; fleet peers verify with ed25519-dalek against
        // the fold. If these two libs disagreed on Ed25519, fleet auth would silently never work.
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
        use hbb_common::sodiumoxide::crypto::sign;

        let dev = kp(42);
        let seed = dev.secret.to_bytes();
        let pk = dev.public.to_bytes();
        let mut sk64 = [0u8; 64];
        sk64[..32].copy_from_slice(&seed);
        sk64[32..].copy_from_slice(&pk);
        let so_sk = sign::SecretKey(sk64);
        let so_pk = sign::PublicKey(pk);

        let msg = b"fleet identity attestation";
        // sodiumoxide signs -> dalek verifies
        let so_sig = sign::sign_detached(msg, &so_sk);
        let vk = VerifyingKey::from_bytes(&pk).unwrap();
        let dalek_sig = Signature::from_bytes(&so_sig.to_bytes());
        assert!(vk.verify(msg, &dalek_sig).is_ok(), "dalek must accept sodiumoxide's signature");

        // dalek signs -> sodiumoxide verifies
        let d_sig = dev.sign(msg);
        let so_sig2 = sign::Signature::new(d_sig.to_bytes());
        assert!(sign::verify_detached(&so_sig2, msg, &so_pk), "sodiumoxide must accept dalek's signature");
    }

    #[test]
    fn garbage_payload_is_bad_not_panic() {
        assert!(parse_hs_payload(&[]).is_none());
        assert!(parse_hs_payload(&[0u8; 8]).is_none());
        assert!(parse_hs_payload(b"not vsf at all").is_none());
    }

    #[test]
    fn sealer_round_trips_and_rejects_wrong_key() {
        use fgtw::client::FleetSealer;
        let key = [7u8; 32];
        let sealed = RdSealer.seal(b"fleet state bytes", &key).unwrap();
        // kete wire form: XChaCha20-Poly1305, 24-byte nonce ‖ ct(+16 tag). The old comment said 12 and the assert agreed with the comment rather than the code — this test had been failing since the sealer went XChaCha.
        assert_eq!(sealed.len(), 24 + 17 + 16);
        assert_eq!(RdSealer.open(&sealed, &key).unwrap(), b"fleet state bytes");
        assert!(RdSealer.open(&sealed, &[8u8; 32]).is_err());
        assert!(RdSealer.open(&sealed[..20], &key).is_err());
    }

    #[test]
    fn chain_cache_round_trips_and_holds_no_root() {
        let a = kp(1);
        let chain = MembershipBlob::genesis(&a, [5u8; 32], &[6u8; 32], 100);
        let c = ChainCache { blob: chain.to_vsf_bytes().unwrap(), fanout_doc: None, fetched_at: 99 };
        let back = ChainCache::from_bytes(&c.to_bytes().unwrap()).unwrap();
        assert_eq!(back.blob, c.blob);
        assert_eq!(back.fetched_at, 99);
        assert_eq!(back.chain().unwrap().fold().unwrap(), vec![a.public.to_bytes()]);
        // The identity seed is nowhere in the cache — only what the public chain already carries.
        assert!(!c.to_bytes().unwrap().windows(32).any(|w| w == [6u8; 32]));
    }
}
