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
//! reqwest stack, the on-disk enrollment state, and the sign/verify halves of the
//! handshake. It is compiled only under the `fgtw` cargo feature.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use fgtw::client::{FgtwResponse, FgtwTransport};
use fgtw::keys::{derive_device_keypair, Keypair};
use hbb_common::config::Config;
use hbb_common::{log, ResultType};
use vsf::VsfType;

const FGTW_URL_DEFAULT: &str = "https://fgtw.org";
/// Domain separator for the handshake signature — binds the signed bytes to this
/// exact protocol so a signature can never be lifted into another context.
const HS_DOMAIN: &[u8] = b"fgtw-rustdesk-hs-v0";
const STATE_FILE: &str = "fgtw_auth.vsf";
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

/// The fleet device keypair for this machine — the same keypair photon derives, because
/// both hash the same oracle bytes into the same Ed25519 seed.
pub fn device_keypair() -> ResultType<Keypair> {
    Ok(derive_device_keypair(&machine_fingerprint()?))
}

// ── enrollment state ──

/// What enrollment persists: the handle proof (identifies the fleet), the identity seed
/// (fleet-scoped device naming + fleet-state addressing — verification-only material, no
/// signing power, same at-rest exposure class as the proof), the last verified member set +
/// its chain-tip time (a monotonic freshness guard), and when it was fetched (staleness
/// bound for offline auth).
#[derive(Clone)]
pub struct EnrollState {
    pub handle_proof: [u8; 32],
    pub identity_seed: [u8; 32],
    pub members: Vec<[u8; 32]>,
    pub tip_osc: i64,
    pub fetched_at: u64,
}

fn state_path() -> PathBuf {
    Config::path(STATE_FILE)
}

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

impl EnrollState {
    fn to_bytes(&self) -> Result<Vec<u8>, String> {
        let mut section = vsf::VsfSection::new("fgtw_enroll");
        section.add_field("hp", VsfType::hP(self.handle_proof.to_vec()));
        section.add_field("is", VsfType::hP(self.identity_seed.to_vec()));
        // One multi-valued field: repeated same-name fields don't accumulate on read.
        section.add_field_multi(
            "m",
            self.members.iter().map(|m| VsfType::ke(m.to_vec())).collect(),
        );
        // Fixed 8-byte LE, not VSF's auto-sized int field: the `i`/`u` variants re-type on
        // decode (a positive `i` comes back as `u`), so raw bytes round-trip cleanly — the
        // same reason fgtw packs eagle_time as to_le_bytes().
        section.add_field("tip", VsfType::hR(self.tip_osc.to_le_bytes().to_vec()));
        section.add_field("at", VsfType::hR(self.fetched_at.to_le_bytes().to_vec()));
        vsf::VsfBuilder::new()
            .creation_time_oscillations(vsf::eagle_time_oscillations())
            .add_section_direct(section)
            .build()
            .map_err(|e| format!("fgtw state build: {e}"))
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        let (_, header_end) = vsf::verification::read_verified(bytes, None)
            .map_err(|e| format!("fgtw state verify: {e}"))?;
        let mut ptr = header_end;
        let section = vsf::VsfSection::parse(bytes, &mut ptr)
            .map_err(|e| format!("fgtw state section: {e}"))?;
        let hp = match section.get_field("hp").and_then(|f| f.values.first()) {
            Some(VsfType::hP(b)) if b.len() == 32 => {
                let mut a = [0u8; 32];
                a.copy_from_slice(b);
                a
            }
            _ => return Err("fgtw state: missing handle proof".into()),
        };
        // Pre-seed state files lack this field; a missing seed reads as unreadable state, which
        // load() surfaces as "not enrolled" — re-enroll to regenerate (dev-phase flag day).
        let identity_seed = match section.get_field("is").and_then(|f| f.values.first()) {
            Some(VsfType::hP(b)) if b.len() == 32 => {
                let mut a = [0u8; 32];
                a.copy_from_slice(b);
                a
            }
            _ => return Err("fgtw state: missing identity seed (re-enroll)".into()),
        };
        let members = section
            .get_field("m")
            .map(|f| {
                f.values
                    .iter()
                    .filter_map(|v| match v {
                        VsfType::ke(b) if b.len() == 32 => {
                            let mut a = [0u8; 32];
                            a.copy_from_slice(b);
                            Some(a)
                        }
                        _ => None,
                    })
                    .collect()
            })
            .unwrap_or_default();
        let tip_osc = match section.get_field("tip").and_then(|f| f.values.first()) {
            Some(VsfType::hR(b)) if b.len() == 8 => i64::from_le_bytes(b.as_slice().try_into().unwrap()),
            _ => 0,
        };
        let fetched_at = match section.get_field("at").and_then(|f| f.values.first()) {
            Some(VsfType::hR(b)) if b.len() == 8 => u64::from_le_bytes(b.as_slice().try_into().unwrap()),
            _ => 0,
        };
        Ok(Self { handle_proof: hp, identity_seed, members, tip_osc, fetched_at })
    }

    pub fn load() -> Option<Self> {
        let bytes = std::fs::read(state_path()).ok()?;
        match Self::from_bytes(&bytes) {
            Ok(s) => Some(s),
            Err(e) => {
                log::warn!("fgtw enroll state unreadable: {e}");
                None
            }
        }
    }

    pub fn save(&self) -> Result<(), String> {
        let bytes = self.to_bytes()?;
        let path = state_path();
        // The config dir may not exist yet on a first run (fresh install / scratch config).
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| format!("create fgtw state dir: {e}"))?;
        }
        std::fs::write(&path, bytes).map_err(|e| format!("write fgtw state: {e}"))
    }
}

/// True iff this machine is enrolled in a fleet.
pub fn is_enrolled() -> bool {
    state_path().exists()
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

/// The current fleet member set, refreshed from FGTW when reachable, else the cached set
/// within the staleness bound. Adopts a fresh fold only when its chain tip is `>=` the
/// cached tip (monotonic guard against a stale R2 read overwriting a post-revocation set).
/// Updates the cache file on a successful refresh. Returns `Err` when neither a fresh nor a
/// fresh-enough cached set is available.
fn current_fleet(state: &EnrollState) -> Result<Vec<[u8; 32]>, String> {
    match fgtw::client::current_members_with_ts(&RdTransport::auth(), &state.handle_proof) {
        Ok((members, tip)) if tip >= state.tip_osc => {
            let refreshed =
                EnrollState { members: members.clone(), tip_osc: tip, fetched_at: now_secs(), ..state.clone() };
            if let Err(e) = refreshed.save() {
                log::warn!("fgtw cache update failed: {e}");
            }
            Ok(members)
        }
        Ok(_) => {
            // Fresh fetch is older than what we hold (eventual-consistency lag) — keep cached.
            Ok(state.members.clone())
        }
        Err(e) => {
            let age = now_secs().saturating_sub(state.fetched_at);
            if age <= cache_max_age() {
                log::info!("fgtw offline ({e}); using cached fleet ({age}s old)");
                Ok(state.members.clone())
            } else {
                Err(format!("fgtw unreachable and cache stale ({age}s): {e}"))
            }
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

/// Fleet-state AEAD, wire-compatible with photon's `kete` (`random 12-byte nonce ‖
/// ChaCha20-Poly1305 ct`) so rustdesk and photon devices share one fleet-state blob.
struct RdSealer;

impl fgtw::client::FleetSealer for RdSealer {
    fn seal(&self, plaintext: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, String> {
        use chacha20poly1305::aead::{Aead, KeyInit};
        use chacha20poly1305::{ChaCha20Poly1305, Nonce};
        use hbb_common::rand::RngCore;
        let cipher = ChaCha20Poly1305::new(key.into());
        let mut nonce_bytes = [0u8; 12];
        hbb_common::rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let ct = cipher
            .encrypt(&Nonce::from(nonce_bytes), plaintext)
            .map_err(|e| format!("fgtw seal: {e}"))?;
        let mut out = Vec::with_capacity(12 + ct.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    fn open(&self, sealed: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, String> {
        use chacha20poly1305::aead::{Aead, KeyInit};
        use chacha20poly1305::{ChaCha20Poly1305, Nonce};
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
fn fleet_key(t: &RdTransport, state: &EnrollState) -> Result<[u8; 32], String> {
    let kp = device_keypair().map_err(|e| e.to_string())?;
    fgtw::client::recover_or_establish_fleet_key(t, &state.handle_proof, &kp, &state.identity_seed)?
        .ok_or_else(|| "no fleet-key wrap for this device yet (awaiting sponsor rotation)".into())
}

/// Publish this device's RustDesk ID into its own fleet device-settings map.
/// Pull-merge-push (like photon's push_roster) so sibling maps and the roster ride along
/// untouched. Best-effort: chooser data, not auth — failure is logged, never fatal, and the
/// next enroll/ID-change retries.
pub fn publish_own_id(state: &EnrollState, device_key: &Keypair) {
    match publish_own_id_inner(state, device_key) {
        Ok(()) => log::info!("fgtw: published this device's rustdesk id ({}) to the fleet", Config::get_id()),
        Err(e) => log::warn!("fgtw: publishing rustdesk id to fleet failed (will retry later): {e}"),
    }
}

fn publish_own_id_inner(state: &EnrollState, device_key: &Keypair) -> Result<(), String> {
    use fgtw::fstate::{DeviceSetting, DeviceSettings};
    let t = RdTransport::enroll();
    let key = fleet_key(&t, state)?;
    let mut fs = fgtw::client::pull_fstate(&t, &RdSealer, &state.handle_proof, &key)?
        .unwrap_or_default();
    let me = device_key.public.to_bytes();
    let now = vsf::eagle_time_oscillations();
    let entry = DeviceSetting {
        key: SETTING_RUSTDESK_ID.to_owned(),
        // fstate v7: setting values are typed VSF now. The RustDesk id is text → VsfType::x.
        value: VsfType::x(Config::get_id()),
        updated: now,
        linked: false, // per-device by nature; never follows a fleet-global value
    };
    match fs.device_settings.iter_mut().find(|d| d.device_pubkey == me) {
        Some(map) => {
            match map.entries.iter_mut().find(|e| e.key == SETTING_RUSTDESK_ID) {
                Some(e) => *e = entry,
                None => map.entries.push(entry),
            }
            map.updated = now;
        }
        None => fs.device_settings.push(DeviceSettings {
            device_pubkey: me,
            updated: now,
            entries: vec![entry],
        }),
    }
    fgtw::client::push_fstate(&t, &RdSealer, &state.handle_proof, device_key, &key, &fs)
}

/// Re-publish this device's RustDesk ID after it changed (e.g. the rendezvous server forced
/// a new one on UUID mismatch), so the fleet's chooser map tracks it. Off-thread — callers
/// sit in async/networking paths and publish_own_id blocks on HTTP. No-op when not enrolled.
pub fn republish_own_id() {
    if !is_enrolled() {
        return;
    }
    std::thread::spawn(|| {
        let (Some(state), Ok(kp)) = (EnrollState::load(), device_keypair()) else {
            return;
        };
        publish_own_id(&state, &kp);
    });
}

/// This machine's own fleet-scoped name — the label every other fleet device shows for
/// us in its chooser (device_name_default over our pubkey + the identity seed). Pure
/// local derivation; `None` when not enrolled.
pub fn self_fleet_name() -> Option<String> {
    let state = EnrollState::load()?;
    let kp = device_keypair().ok()?;
    Some(fgtw::pair::device_name_default(
        &kp.public.to_bytes(),
        &state.identity_seed,
    ))
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
}

/// The current fleet as a chooser list: every member (fresh fold, cache fallback within
/// bound) with its fleet-scoped name and, where published, its RustDesk ID. Liveness is the
/// rendezvous server's job — hand `rustdesk_id` to the normal connect path.
pub fn fleet_roster() -> Result<Vec<FleetDevice>, String> {
    let state = EnrollState::load().ok_or("not enrolled")?;
    let members = current_fleet(&state)?;
    let me = device_keypair().map(|k| k.public.to_bytes()).ok();
    // ID map is best-effort: an unreachable slot or missing wrap degrades to names-only.
    let ids: HashMap<[u8; 32], String> = (|| -> Result<_, String> {
        let t = RdTransport::auth();
        let key = fleet_key(&t, &state)?;
        let fs = fgtw::client::pull_fstate(&t, &RdSealer, &state.handle_proof, &key)?
            .unwrap_or_default();
        Ok(fs
            .device_settings
            .into_iter()
            .filter_map(|d| {
                d.entries
                    .into_iter()
                    .find(|e| e.key == SETTING_RUSTDESK_ID)
                    .and_then(|e| match e.value {
                        // Written as VsfType::x (text) by publish_own_id_inner above.
                        VsfType::x(s) => Some(s),
                        _ => None,
                    })
                    .map(|id| (d.device_pubkey, id))
            })
            .collect())
    })()
    .unwrap_or_else(|e| {
        log::warn!("fgtw: fleet id map unavailable ({e}); chooser degrades to names-only");
        HashMap::new()
    });
    Ok(members
        .iter()
        .map(|m| FleetDevice {
            pubkey: *m,
            name: fgtw::pair::device_name_default(m, &state.identity_seed),
            rustdesk_id: ids.get(m).cloned(),
            is_self: me == Some(*m),
        })
        .collect())
}

// ── handshake payload ──

/// Why an incoming fleet handshake was rejected. `Ok` authorizes the connection.
#[derive(Debug, PartialEq, Eq)]
pub enum FgtwVerdict {
    Ok,
    NotEnrolled,
    BadPayload,
    BadSignature,
    NotMember,
    StaleCache,
}

impl FgtwVerdict {
    pub fn is_ok(&self) -> bool {
        matches!(self, FgtwVerdict::Ok)
    }
}

/// The bytes both sides sign/verify: domain-tagged, binding the client's fresh per-connection
/// box public key to the host's stable identity key. A relayed signature is useless (the MITM
/// lacks the box secret) and cannot be replayed against a different host.
fn hs_digest(client_box_pk: &[u8; 32], host_sign_pk: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(HS_DOMAIN);
    h.update(client_box_pk);
    h.update(host_sign_pk);
    *h.finalize().as_bytes()
}

/// Build the client's `PublicKey.fgtw` payload: VSF `{device_pubkey, sig}`. `None` if this
/// machine isn't enrolled (caller falls back to the vanilla handshake).
pub fn build_hs_payload(client_box_pk: &[u8; 32], host_sign_pk: &[u8; 32]) -> Option<Vec<u8>> {
    if !is_enrolled() {
        return None;
    }
    let kp = device_keypair().ok()?;
    let sig = kp.sign(&hs_digest(client_box_pk, host_sign_pk)).to_bytes().to_vec();
    let mut section = vsf::VsfSection::new("fgtw_hs");
    section.add_field("dk", VsfType::ke(kp.public.to_bytes().to_vec()));
    section.add_field("sig", VsfType::ge(sig));
    vsf::VsfBuilder::new()
        .creation_time_oscillations(vsf::eagle_time_oscillations())
        .add_section_direct(section)
        .build()
        .ok()
}

fn parse_hs_payload(payload: &[u8]) -> Option<([u8; 32], Vec<u8>)> {
    let (_, header_end) = vsf::verification::read_verified(payload, None).ok()?;
    let mut ptr = header_end;
    // Near-form sections are anonymous on the wire (the name lives in the header TOC and
    // comes back empty here), so we gate on field presence, not section.name. The verified
    // read above already rejects tampered/foreign bytes; the handshake signature is the
    // real authenticity check.
    let section = vsf::VsfSection::parse(payload, &mut ptr).ok()?;
    let dk = match section.get_field("dk").and_then(|f| f.values.first()) {
        Some(VsfType::ke(b)) if b.len() == 32 => {
            let mut a = [0u8; 32];
            a.copy_from_slice(b);
            a
        }
        _ => return None,
    };
    let sig = match section.get_field("sig").and_then(|f| f.values.first()) {
        Some(VsfType::ge(b)) if b.len() == 64 => b.clone(),
        _ => return None,
    };
    Some((dk, sig))
}

/// Host side: verify an incoming `PublicKey.fgtw` payload. Checks the signature binds the
/// client's box key to our identity key, then that the signing device is a current member of
/// our own fleet (fresh fetch, cache fallback within bound). Returns the verified device
/// pubkey on success, or the reason it was rejected.
pub fn verify_hs_payload(
    payload: &[u8],
    client_box_pk: &[u8; 32],
    our_sign_pk: &[u8; 32],
) -> Result<[u8; 32], FgtwVerdict> {
    let state = EnrollState::load().ok_or(FgtwVerdict::NotEnrolled)?;
    let (device_pk, sig) = parse_hs_payload(payload).ok_or(FgtwVerdict::BadPayload)?;
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    let vk = VerifyingKey::from_bytes(&device_pk).map_err(|_| FgtwVerdict::BadPayload)?;
    let sig_arr = <[u8; 64]>::try_from(sig.as_slice()).map_err(|_| FgtwVerdict::BadPayload)?;
    vk.verify(&hs_digest(client_box_pk, our_sign_pk), &Signature::from_bytes(&sig_arr))
        .map_err(|_| FgtwVerdict::BadSignature)?;
    match current_fleet(&state) {
        Ok(members) if members.contains(&device_pk) => Ok(device_pk),
        Ok(_) => Err(FgtwVerdict::NotMember),
        Err(e) => {
            log::warn!("fgtw membership check failed: {e}");
            Err(FgtwVerdict::StaleCache)
        }
    }
}

/// Client side: is `signed_id` (the host's `SignedId.id` bytes) signed by a device in our own
/// fleet? Tries each member pubkey as the verifying key over the `IdPk` bytes. Returns the
/// decoded `(id, box_pk)` on the first hit, so the caller can proceed as it does for a
/// rendezvous-verified host. `None` when not enrolled or the host isn't a fleet member.
pub fn verify_host_signed_id(signed_id: &[u8]) -> Option<(String, [u8; 32])> {
    use hbb_common::sodiumoxide::crypto::sign;
    let state = EnrollState::load()?;
    let members = current_fleet(&state).ok()?;
    for m in &members {
        // Reuse rustdesk's own IdPk decode (verify sig + parse) — same path secure_connection uses.
        if let Ok(pair) = crate::common::decode_id_pk(signed_id, &sign::PublicKey(*m)) {
            return Some(pair);
        }
    }
    None
}

// ── session adoption (the passless path) ──

/// Adopt this machine's existing login: read the tohu session registers (set by whichever
/// app the user attested in — e.g. Photon) and prove membership with the FLEET KEY — if this
/// device's key opens a wrap in the fleet's fan-out, the machine is a current member; no
/// handle typed, no ceremony. Persists EnrollState, seeds the RustDesk identity from the
/// fleet key, and publishes our RustDesk ID to the fleet's chooser map.
///
/// `Err` means "couldn't adopt right now", not "unauthorized": no session (nobody logged in
/// on this machine), no wrap yet (freshly-bound device awaiting its sponsor's confirm
/// rotation), or the fleet server is unreachable. Callers retry later or fall back to
/// `--fgtw-enroll <handle>` bootstrap.
pub fn adopt_session() -> Result<String, String> {
    let s = tohu::session()
        .ok_or("no session on this machine — log in (e.g. Photon), or run --fgtw-enroll <handle>")?;
    let device_key = device_keypair().map_err(|e| e.to_string())?;
    let t = RdTransport::enroll();
    // The fleet-key gate: only current members hold a wrap in the fan-out.
    fgtw::client::recover_fleet_key(&t, &s.handle_proof, &device_key, &s.identity_seed)?
        .ok_or("this device has no fleet-key wrap yet (not a member, or awaiting sponsor rotation)")?;
    let (members, tip) = fgtw::client::current_members_with_ts(&t, &s.handle_proof)?;
    let state = EnrollState {
        handle_proof: s.handle_proof,
        identity_seed: s.identity_seed,
        members: members.clone(),
        tip_osc: tip,
        fetched_at: now_secs(),
    };
    state.save()?;
    seed_rustdesk_identity(&device_key);
    publish_own_id(&state, &device_key);
    Ok(format!(
        "Adopted session: fleet member on this machine ({} member(s)).",
        members.len()
    ))
}

/// Best-effort background fleet bootstrap for service/UI startup, off-thread, never blocks.
/// Not enrolled yet → adopt the machine's login. Already enrolled → (re)publish our rustdesk
/// id every start, because the id is what the My Fleet chooser connects by: the original
/// enroll-time publish can fail (offline, no fleet-key wrap yet) or go stale (id changed, map
/// reset), and without a re-publish the fleet tile stays unconnectable forever.
pub fn try_adopt_session() {
    if let Some(state) = EnrollState::load() {
        std::thread::spawn(move || {
            if let Ok(kp) = device_keypair() {
                publish_own_id(&state, &kp);
            }
        });
        return;
    }
    std::thread::spawn(|| match adopt_session() {
        Ok(msg) => log::info!("fgtw: {msg}"),
        Err(e) => log::info!("fgtw: session adoption not available: {e}"),
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
                return pair_flow(&t, &device_key, &handle_proof, &identity_seed).map(|msg| {
                    park_session();
                    msg
                });
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
    let (members, tip) = fgtw::client::current_members_with_ts(&t, &handle_proof)?;
    let state = EnrollState {
        handle_proof,
        identity_seed,
        members: members.clone(),
        tip_osc: tip,
        fetched_at: now_secs(),
    };
    state.save()?;
    seed_rustdesk_identity(&device_key);
    publish_own_id(&state, &device_key);
    park_session();
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
    // Post the binding request: device-signed consent, co-signed by the identity key (the
    // registry write gate). No NFC secret from a CLI enroll — all-zero = none offered.
    fgtw::client::bindreq_put(t, device_key, identity_seed, handle_proof, &[0u8; 32])?;
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
            let _ = fgtw::client::bindreq_put(t, device_key, identity_seed, handle_proof, &[0u8; 32]);
        }
        let (members, tip) = match fgtw::client::current_members_with_ts(t, handle_proof) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if members.contains(&me) {
            // Best-effort: clear our own request now that we're bound (else the stamp lapses).
            let _ = fgtw::client::bindreq_withdraw(t, device_key, handle_proof);
            let state = EnrollState {
                handle_proof: *handle_proof,
                identity_seed: *identity_seed,
                members: members.clone(),
                tip_osc: tip,
                fetched_at: now_secs(),
            };
            state.save()?;
            seed_rustdesk_identity(device_key);
            publish_own_id(&state, device_key);
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
        let box_pk = [3u8; 32];
        let host_pk = [9u8; 32];
        let sig = dev.sign(&hs_digest(&box_pk, &host_pk)).to_bytes().to_vec();
        let mut section = vsf::VsfSection::new("fgtw_hs");
        section.add_field("dk", VsfType::ke(dev.public.to_bytes().to_vec()));
        section.add_field("sig", VsfType::ge(sig));
        let payload = vsf::VsfBuilder::new()
            .creation_time_oscillations(vsf::eagle_time_oscillations())
            .add_section_direct(section)
            .build()
            .unwrap();
        let (parsed_dk, parsed_sig) = parse_hs_payload(&payload).unwrap();
        assert_eq!(parsed_dk, dev.public.to_bytes());
        assert_eq!(parsed_sig.len(), 64);

        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
        let vk = VerifyingKey::from_bytes(&parsed_dk).unwrap();
        let sig_arr = <[u8; 64]>::try_from(parsed_sig.as_slice()).unwrap();
        // Right binding verifies.
        assert!(vk
            .verify(&hs_digest(&box_pk, &host_pk), &Signature::from_bytes(&sig_arr))
            .is_ok());
        // Wrong box key does not — the signature is channel-bound.
        assert!(vk
            .verify(&hs_digest(&[4u8; 32], &host_pk), &Signature::from_bytes(&sig_arr))
            .is_err());
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
        // kete wire form: 12-byte nonce ‖ ct(+16 tag)
        assert_eq!(sealed.len(), 12 + 17 + 16);
        assert_eq!(RdSealer.open(&sealed, &key).unwrap(), b"fleet state bytes");
        assert!(RdSealer.open(&sealed, &[8u8; 32]).is_err());
        assert!(RdSealer.open(&sealed[..20], &key).is_err());
    }

    #[test]
    fn enroll_state_round_trips() {
        let s = EnrollState {
            handle_proof: [5u8; 32],
            identity_seed: [6u8; 32],
            members: vec![[1u8; 32], [2u8; 32]],
            tip_osc: 123456789,
            fetched_at: 99,
        };
        let bytes = s.to_bytes().unwrap();
        let back = EnrollState::from_bytes(&bytes).unwrap();
        assert_eq!(back.handle_proof, s.handle_proof);
        assert_eq!(back.identity_seed, s.identity_seed);
        assert_eq!(back.members, s.members);
        assert_eq!(back.tip_osc, s.tip_osc);
        assert_eq!(back.fetched_at, s.fetched_at);
    }
}
