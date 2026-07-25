#!/bin/bash
# Release the passless RustDesk fork, photon-style: build + sign every artefact locally,
# publish bare binaries + install script + signed manifest to R2, mirror to GitHub,
# stamp the website. First cut: Linux x86_64 (native) + macOS arm64 (osxcross).
#
# Versioning: NO version-bump commits (upstream owns Cargo.toml's 1.4.9) — the release
# counter N comes from git tags `fgtw-v<N>`; the manifest stamps HEAD's SHA and 0.N.0
# (patch 0 = release marker, photon semantics). Nothing here mutates the tree, so there
# is no rollback trap: any failure before the first wrangler put simply aborts.
set -e

cd "$(dirname "$0")"
source scripts/lib/github.sh

if [ -n "$(git status --porcelain)" ]; then
    echo "ERROR: working tree is dirty — a release stamps HEAD into the signed manifest."
    echo "       Commit (or stash) first."
    git status --short | head -20
    exit 1
fi

for dep in fgtw tohu ihi vsf; do
    [ -d "../$dep" ] || { echo "ERROR: sibling ../$dep missing (path dep)"; exit 1; }
done
command -v wrangler >/dev/null || { echo "ERROR: wrangler not on PATH"; exit 1; }
command -v b3sum >/dev/null || { echo "ERROR: b3sum not on PATH"; exit 1; }

LAST_N=$(git tag -l 'fgtw-v*' | sed 's/fgtw-v//' | sort -n | tail -1)
N=$(( ${LAST_N:-0} + 1 ))
COMMIT=$(git rev-parse HEAD)
BASE_VERSION=$(grep -m1 '^version' Cargo.toml | sed -E 's/.*"([0-9]+\.[0-9]+\.[0-9]+)".*/\1/')
DEPLOY_DATE=$(date +%Y-%m-%d)
echo "Deploying rustdesk fgtw release $N (base $BASE_VERSION, $COMMIT)"

R2_BUCKET="holdmyoscilloscope"
R2_PATH="rustdesk"
R2_URL="https://brobdingnagian.holdmyoscilloscope.com/$R2_PATH"

OSX=/mnt/Octopus/Code/osxcross/target
SDK=$OSX/SDK/MacOSX14.5.sdk
XLIBS=$(pwd)/cross-libs/aarch64-apple-darwin
SIGNER=../photon/target/release/photon-signature-signer
MANIFEST_TOOL=../photon/target/release/photon-manifest

# ── Sciter runtimes: fetched once, content-checked, cached forever. ──
# After the first deploy they also live on R2, which becomes the durable origin.
SCITER_CACHE=".sciter-cache"
SCITER_LINUX="$SCITER_CACHE/libsciter-gtk.so"
SCITER_MAC="$SCITER_CACHE/libsciter.dylib"
# BLAKE3 pins recorded at first fetch (empty = trust-on-first-use, then pin the printed value).
SCITER_LINUX_B3="${SCITER_LINUX_B3:-}"
SCITER_MAC_B3="${SCITER_MAC_B3:-}"
mkdir -p "$SCITER_CACHE"
fetch_sciter() { # <url> <dest> <pin>
    if [ ! -f "$2" ]; then
        echo "Fetching $(basename "$2")..."
        curl -sfL "$1" -o "$2"
    fi
    local b3; b3=$(b3sum --no-names "$2")
    if [ -n "$3" ] && [ "$b3" != "$3" ]; then
        echo "ERROR: $(basename "$2") BLAKE3 mismatch: $b3 (pinned $3)"; exit 1
    fi
    [ -z "$3" ] && echo "  $(basename "$2") BLAKE3 (pin this): $b3"
}
fetch_sciter "https://raw.githubusercontent.com/c-smile/sciter-sdk/master/bin.lnx/x64/libsciter-gtk.so" "$SCITER_LINUX" "$SCITER_LINUX_B3"
fetch_sciter "https://raw.githubusercontent.com/c-smile/sciter-sdk/master/bin.osx/libsciter.dylib" "$SCITER_MAC" "$SCITER_MAC_B3"

# ════════════════════════════════════════════════════════════════════════════════════
# BUILD PHASE — nothing public until every artefact exists and is signed.
# ════════════════════════════════════════════════════════════════════════════════════

# Release tools first — photon's signer + manifest builder. PHOTON_ALLOW_RELEASE unblocks
# photon's build.rs release-guard (same as photon's own deploy.sh does).
echo "Building release tools (signer + manifest)..."
( cd ../photon && PHOTON_ALLOW_RELEASE=1 cargo build --release --bin photon-signature-signer --bin photon-manifest )

# Inline the sciter UI — without this an installed binary shows a blank window
# (non-inline builds load UI pages from file:// relative to cwd).
python3 res/inline-sciter.py >/dev/null

# Source freeze (reflink snapshot) so live-tree edits can't tear the multi-target build.
source scripts/lib/snapbuild.sh
SNAP_DIR="."
if snapbuild_take; then
    SNAP_DIR="$SNAPBUILD_ROOT/rustdesk"
    export CARGO_TARGET_DIR="$(pwd)/target"
    echo "Source frozen (reflink snapshot) — edit away, this deploy builds from the frozen tree"
fi
snap_cargo() { ( cd "$SNAP_DIR" && cargo "$@" ); }

echo ""
echo "Building Linux x86_64 release..."
CXXFLAGS="-include cstdint" \
snap_cargo build --release --features inline,fgtw,linux-pkg-config

echo ""
echo "Building macOS arm64 release (osxcross)..."
CXXFLAGS="-include cstdint" \
CC_aarch64_apple_darwin=$OSX/bin/aarch64-apple-darwin-clang-wrapper \
CXX_aarch64_apple_darwin=$OSX/bin/aarch64-apple-darwin-clangxx-wrapper \
AR_aarch64_apple_darwin=$OSX/bin/aarch64-apple-darwin23.5-ar \
CARGO_TARGET_AARCH64_APPLE_DARWIN_LINKER=$OSX/bin/aarch64-apple-darwin-clang-wrapper \
MACOSX_DEPLOYMENT_TARGET=11.0 \
COREAUDIO_SDK_PATH=$SDK \
BINDGEN_EXTRA_CLANG_ARGS_aarch64_apple_darwin="--target=arm64-apple-darwin -isysroot $SDK -I$XLIBS/include" \
PKG_CONFIG_ALLOW_CROSS=1 \
PKG_CONFIG_PATH_aarch64_apple_darwin=$XLIBS/lib/pkgconfig \
PKG_CONFIG_LIBDIR_aarch64_apple_darwin=$XLIBS/lib/pkgconfig \
PKG_CONFIG_SYSROOT_DIR_aarch64_apple_darwin=/ \
snap_cargo build --release --target aarch64-apple-darwin --features inline,fgtw,linux-pkg-config

LINUX_BIN=target/release/rustdesk
MAC_BIN=target/aarch64-apple-darwin/release/rustdesk

echo ""
echo "Signing binaries (Ed25519, in place)..."
"$SIGNER" "$LINUX_BIN"
"$SIGNER" "$MAC_BIN"

# .sha256 sidecars — the installer's integrity gate (rustdesk has no self-verify command).
# Written AFTER signing so they cover the signed bytes.
sidecar() { sha256sum "$1" | awk '{print $1}' > "$1.sha256"; }
sidecar "$LINUX_BIN"; sidecar "$MAC_BIN"; sidecar "$SCITER_LINUX"; sidecar "$SCITER_MAC"

echo ""
echo "Building signed release manifest..."
b3() { b3sum --no-names "$1"; }
"$MANIFEST_TOOL" --channel release --out /tmp/rustdesk-manifest-release.vsf \
    --artefact Linux x86_64 "0.$N.0" "$COMMIT" "$R2_URL/rustdesk-linux-x86_64-release" "$(b3 $LINUX_BIN)" "$(stat -c %s $LINUX_BIN)" \
    --artefact macOS arm64  "0.$N.0" "$COMMIT" "$R2_URL/rustdesk-macos-arm64-release"  "$(b3 $MAC_BIN)"  "$(stat -c %s $MAC_BIN)"

echo ""
echo "BUILD PHASE complete — Linux + macOS binaries signed, manifest built. Nothing public yet."

# ════════════════════════════════════════════════════════════════════════════════════
# PUBLISH PHASE — first wrangler put is the first irreversible outward step.
# ════════════════════════════════════════════════════════════════════════════════════

echo ""
echo "Uploading to R2 ($R2_BUCKET/$R2_PATH)..."
put() { wrangler r2 object put "$R2_BUCKET/$R2_PATH/$1" --file "$2" ${3:+--content-type "$3"} --remote; }
put rustdesk-linux-x86_64-release "$LINUX_BIN"
put rustdesk-linux-x86_64-release.sha256 "$LINUX_BIN.sha256" text/plain
put rustdesk-macos-arm64-release "$MAC_BIN"
put rustdesk-macos-arm64-release.sha256 "$MAC_BIN.sha256" text/plain
put libsciter-gtk-linux-x86_64-release.so "$SCITER_LINUX"
put libsciter-gtk-linux-x86_64-release.so.sha256 "$SCITER_LINUX.sha256" text/plain
put libsciter-macos-release.dylib "$SCITER_MAC"
put libsciter-macos-release.dylib.sha256 "$SCITER_MAC.sha256" text/plain
put install-release.sh installers/install-release.sh text/plain
put icon-1024.png res/icon.png image/png
put app.png res/128x128@2x.png image/png
# Manifest LAST: only after every binary it references is live.
put manifest-release.vsf /tmp/rustdesk-manifest-release.vsf application/octet-stream

echo ""
echo "R2 live: release $N"

# Tag the release (the counter's source of truth) and push.
git tag -a "fgtw-v$N" -m "fgtw release $N (base $BASE_VERSION)"
git push origin fgtw-auth --tags 2>/dev/null || git push fork fgtw-auth --tags

# GitHub mirror — BEST-EFFORT once R2 is live (photon rule: a GitHub 502 must not
# strand an already-shipped release).
GH_TAG="fgtw-v$N"
mirror() {
    publish_github "$GH_TAG" "$1" "$2" || echo "WARNING: GitHub mirror of $1 failed — continuing (R2 is authoritative and live)"
}
echo ""
echo "Mirroring release to GitHub ($GH_TAG)..."
if ensure_release "$GH_TAG" false; then
    mirror rustdesk-linux-x86_64-release "$LINUX_BIN"
    mirror rustdesk-macos-arm64-release "$MAC_BIN"
    mirror libsciter-gtk-linux-x86_64-release.so "$SCITER_LINUX"
    mirror libsciter-macos-release.dylib "$SCITER_MAC"
else
    echo "WARNING: GitHub release creation failed — skipping mirror (R2 is authoritative and live)"
fi

# Website stamp + deploy (best-effort).
WEBSITE_DIR="/mnt/Chiton/MEGA/holdmyoscilloscope/rustdesk"
if [ -f "$WEBSITE_DIR/index.html" ]; then
    sed -i "s/Version: [^·]*· Updated: [^<]*/Version: Release $N (base $BASE_VERSION) · Updated: $DEPLOY_DATE/" "$WEBSITE_DIR/index.html"
    echo "Updated website stamp: Release $N · $DEPLOY_DATE"
    ( cd /mnt/Chiton/MEGA/holdmyoscilloscope && ./deploy.sh ) || echo "WARNING: website deploy failed (non-fatal)"
fi

echo ""
echo "Release $N shipped. Install with:"
echo "  curl -sSfL $R2_URL/install-release.sh | sh"
