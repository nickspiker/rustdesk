# FGTW fleet authentication (feature `fgtw`)

Passless remote access for devices in the same FGTW fleet. Two enrolled devices connect
with no password and no click-to-accept: the connecting client signs the host's login
challenge with its fleet device key, and the host authorizes it after verifying that key is
a current member of its own fleet. Non-fleet peers are unaffected — they get the normal
password/click flow.

The feature is **off by default**; vanilla builds are byte-identical and keep MSRV 1.75.

## How it works

RustDesk's identity keypair is NaCl `sign` = Ed25519, the same algorithm as an FGTW device
key. Enrollment seeds RustDesk's identity keypair from the fleet device key
(`BLAKE3(machine_fingerprint) → Ed25519 seed`), so the fleet key *is* the RustDesk key.

- **Host → client**: the existing `SignedId` is now signed with the fleet key; the client
  verifies it against its own membership fold.
- **Client → host**: a new optional `PublicKey.fgtw` field carries a signature binding the
  client's fresh session box key to the host's identity key. The host verifies the signature
  and fleet membership, then authorizes the login from channel state.

Membership is checked live against `fgtw.org` per connection, with a cached fallback bounded
by `fgtw-cache-max-age` (default 3600s) when offline. Revocation latency = that bound.

## Build

Requires the sibling TOKEN-stack checkout next to `rustdesk/`: `fgtw`, `tohu`, `ihi`, `vsf`.
System dev packages (Fedora names): `gstreamer1-devel gstreamer1-plugins-base-devel`
(Wayland capture), `pam-devel`, `libvpx-devel`. Under GCC 15 the vendored libwebm needs
`CXXFLAGS="-include cstdint"`. The `fgtw` feature pulls chacha20poly1305 0.11-rc, so an
fgtw build needs rustc ≥ 1.85 (feature-off builds still work on 1.75).

```
CXXFLAGS="-include cstdint" cargo build --release --features fgtw
```

## Enroll

```
rustdesk --fgtw-enroll <handle>
```

- First device on a fresh handle: claims the fleet genesis.
- Later device: prints pair-words; approve them from an already-enrolled device (e.g. Photon),
  and enrollment completes when the fleet chain folds in this device.

State is written to `<config>/fgtw_auth.vsf` (handle proof, verified member set, chain tip,
fetch time). Run enrollment with the same privilege as the running service.

## Options

- `enable-fgtw-auth=N` — host opt-out (disables passless fleet auth on this host).
- `fgtw-url` — override the fleet server (default `https://fgtw.org`; use for a dev worker).
- `fgtw-cache-max-age` — seconds a cached member set is trusted while offline (default 3600).

## Verification matrix (pending a build environment)

- fleet member connects → no password, no click; audit `primary_auth=5` (Fgtw)
- host offline, cache fresh → allow; cache stale → deny
- non-member / corrupted sig / sig bound to wrong box key → rejected at handshake (fail closed)
- revoked device (photon `unbind_device`) → denied after fresh fetch; ≤ cache bound otherwise
- replayed handshake payload → rejected (fresh per-connection box key)
- vanilla client → fgtw host: password AND click flows unchanged
- fgtw client → vanilla host: field ignored; normal flow
- 2FA host → fgtw auth then TOTP prompt

Rig: host = one machine (fgtw build, direct-IP access to skip the public rendezvous); second
device = a VM/LAN box with a distinct `/etc/machine-id`. In debug builds,
`RUSTDESK_FGTW_FINGERPRINT` overrides the device identity for local multi-device testing.
