# Building the FGTW-auth RustDesk fork on macOS

This fork depends on five sibling TOKEN-stack crates via **path deps** (`../fgtw`,
`../tohu`, `../ihi`, `../vsf`) plus a forked `hbb_common` submodule. They must sit side by
side in one parent directory. This mirrors the Linux dev layout — nothing here is Mac-only
except the Homebrew package names.

## 1. Clone the sibling checkout

```sh
mkdir -p ~/Code && cd ~/Code
git clone --recurse-submodules -b fgtw-auth https://github.com/nickspiker/rustdesk.git
git clone https://github.com/nickspiker/fgtw.git
git clone https://github.com/nickspiker/tohu.git
git clone https://github.com/nickspiker/ihi.git
git clone https://github.com/nickspiker/vsf.git
```

Layout must end up as:

```
~/Code/
  rustdesk/        (fgtw-auth branch; libs/hbb_common submodule → nickspiker fork)
  fgtw/  tohu/  ihi/  vsf/
```

`--recurse-submodules` pulls `libs/hbb_common` from **nickspiker/hbb_common@fgtw-auth**
(the `.gitmodules` URL is already re-pointed). Verify:

```sh
cd rustdesk
git -C libs/hbb_common remote get-url origin   # → nickspiker/hbb_common
git -C libs/hbb_common log --oneline -1         # → a1c9098 feat: fgtw handshake field...
```

If the submodule is empty (older git): `git submodule update --init --recursive`.

`spirix` is NOT needed — it's behind a vsf feature this build doesn't enable.

## 2. System libraries (Homebrew)

```sh
brew install opus libvpx libyuv aom pkg-config gstreamer gst-plugins-base
```

RustDesk's `build.py` expects vcpkg on macOS by default; the `linux-pkg-config` feature
(used below) routes the codecs through Homebrew's pkg-config instead, avoiding vcpkg. If
pkg-config can't find a keg-only lib, add it to `PKG_CONFIG_PATH` (e.g.
`export PKG_CONFIG_PATH="$(brew --prefix libyuv)/lib/pkgconfig:$PKG_CONFIG_PATH"`).

## 3. Build

```sh
cd ~/Code/rustdesk
cargo build --release --features fgtw,linux-pkg-config
```

Notes:
- The `fgtw` feature is off by default; a vanilla build is unaffected.
- On Linux/GCC the vendored libwebm needs `CXXFLAGS="-include cstdint"`; on macOS/clang
  this is usually unnecessary — add it only if libwebm fails on a missing `uint64_t`.
- The `fgtw` feature pulls chacha20poly1305 0.11-rc → needs rustc ≥ 1.85.

## 4. Enroll + test

```sh
./target/release/rustdesk --fgtw-enroll <your-handle>
```

- First device on a fresh handle claims the fleet genesis.
- A later device prints pair-words; approve them from an already-enrolled device (Photon)
  to fold this device into the fleet.

State: `~/Library/Application Support/RustDesk/fgtw_auth.vsf` (+ the identity keypair is
seeded into `RustDesk.toml`). Enrolling as the same machine already in your Photon fleet
means RustDesk derives the **same** device key — no separate enrollment needed if the
fingerprint matches.

For a two-device live test, see the matrix in [docs/fgtw.md](docs/fgtw.md). In debug builds
`RUSTDESK_FGTW_FINGERPRINT=<string>` overrides the device identity so one machine can play
two devices.

## Options

- `enable-fgtw-auth=N` — host opt-out.
- `fgtw-url` — override the fleet server (default `https://fgtw.org`).
- `fgtw-cache-max-age` — seconds a cached member set is trusted offline (default 3600).
