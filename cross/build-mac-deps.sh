#!/bin/bash
# One-time cross-build of rustdesk's native codec deps for aarch64-apple-darwin,
# staged into cross-libs/aarch64-apple-darwin/ (committed, like photon's cross-libs/).
# Idempotent: a lib is skipped when its staged .pc exists; --force rebuilds everything.
#
# scrap needs (pkg-config names): vpx, aom, libyuv; magnum-opus needs opus.
# All static — the mac binary must be self-contained next to libsciter.dylib.
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$(pwd)

OSX=/mnt/Octopus/Code/osxcross/target
SDK=$OSX/SDK/MacOSX14.5.sdk
STAGE=$ROOT/cross-libs/aarch64-apple-darwin
BUILD=$ROOT/cross/build
CC_W=$OSX/bin/aarch64-apple-darwin-clang-wrapper
CXX_W=$OSX/bin/aarch64-apple-darwin-clangxx-wrapper
AR_D=$OSX/bin/aarch64-apple-darwin23.5-ar
RANLIB_D=$OSX/bin/aarch64-apple-darwin23.5-ranlib
STRIP_D=$OSX/bin/aarch64-apple-darwin23.5-strip
export MACOSX_DEPLOYMENT_TARGET=11.0
export PATH="$OSX/bin:$PATH"

# Pins — match the versions the working Linux build links against.
OPUS_V=1.5.2
VPX_V=v1.15.0
AOM_V=v3.13.3
YUV_COMMIT=stable  # resolved to a concrete commit on first fetch; recorded below

FORCE=${1:-}
mkdir -p "$STAGE"/{lib/pkgconfig,include} "$BUILD"

# osxcross ships only a C-driver wrapper; make the C++ twin it if missing.
if [ ! -x "$CXX_W" ]; then
    sed 's/exec clang /exec clang++ /' "$CC_W" > "$CXX_W".tmp
    chmod +x "$CXX_W".tmp && mv "$CXX_W".tmp "$CXX_W"
    echo "created $CXX_W"
fi

have() { [ -z "$FORCE" ] && [ -f "$STAGE/lib/pkgconfig/$1.pc" ]; }

fetch() { # fetch <url> <dest-file>
    [ -f "$2" ] || curl -sfL "$1" -o "$2"
}

# ── opus (autotools) ──
if have opus; then echo "opus: staged, skipping"; else
    echo "=== opus $OPUS_V ==="
    fetch "https://downloads.xiph.org/releases/opus/opus-$OPUS_V.tar.gz" "$BUILD/opus.tar.gz"
    rm -rf "$BUILD/opus-$OPUS_V"; tar -C "$BUILD" -xzf "$BUILD/opus.tar.gz"
    ( cd "$BUILD/opus-$OPUS_V"
      CC=$CC_W AR=$AR_D RANLIB=$RANLIB_D ./configure --host=aarch64-apple-darwin23.5 \
          --prefix="$STAGE" --disable-shared --enable-static --disable-doc \
          --disable-extra-programs >/dev/null
      make -j"$(nproc)" >/dev/null && make install >/dev/null )
    echo "opus: staged"
fi

# ── libvpx (own configure) ──
if have vpx; then echo "libvpx: staged, skipping"; else
    echo "=== libvpx $VPX_V ==="
    rm -rf "$BUILD/libvpx"
    git clone --depth 1 -b "$VPX_V" https://chromium.googlesource.com/webm/libvpx "$BUILD/libvpx" 2>/dev/null \
        || git clone --depth 1 -b "$VPX_V" https://github.com/webmproject/libvpx "$BUILD/libvpx"
    ( cd "$BUILD/libvpx"
      CC=$CC_W CXX=$CXX_W LD=$CC_W AR=$AR_D RANLIB=$RANLIB_D STRIP=$STRIP_D \
      ./configure --target=arm64-darwin20-gcc --prefix="$STAGE" \
          --disable-shared --enable-static --enable-vp8 --enable-vp9 --enable-pic \
          --disable-examples --disable-tools --disable-docs --disable-unit-tests >/dev/null
      make -j"$(nproc)" >/dev/null && make install >/dev/null )
    echo "libvpx: staged"
fi

# ── aom (cmake) ──
if have aom; then echo "aom: staged, skipping"; else
    echo "=== aom $AOM_V ==="
    rm -rf "$BUILD/aom"
    git clone --depth 1 -b "$AOM_V" https://aomedia.googlesource.com/aom "$BUILD/aom"
    cmake -S "$BUILD/aom" -B "$BUILD/aom/build-mac" \
        -DCMAKE_TOOLCHAIN_FILE="$ROOT/cross/darwin-arm64.cmake" \
        -DCMAKE_INSTALL_PREFIX="$STAGE" -DCMAKE_BUILD_TYPE=Release \
        -DBUILD_SHARED_LIBS=0 -DENABLE_EXAMPLES=0 -DENABLE_TESTS=0 \
        -DENABLE_DOCS=0 -DENABLE_TOOLS=0 -DCONFIG_PIC=1 >/dev/null
    cmake --build "$BUILD/aom/build-mac" -j"$(nproc)" >/dev/null
    cmake --install "$BUILD/aom/build-mac" >/dev/null
    echo "aom: staged"
fi

# ── libyuv (cmake; no upstream .pc — hand-written below) ──
if have libyuv; then echo "libyuv: staged, skipping"; else
    echo "=== libyuv ==="
    rm -rf "$BUILD/libyuv"
    git clone --depth 1 https://chromium.googlesource.com/libyuv/libyuv "$BUILD/libyuv"
    git -C "$BUILD/libyuv" rev-parse HEAD | tee "$STAGE/libyuv.commit"
    # JPEG off: otherwise cmake finds the HOST libjpeg and poisons the link.
    cmake -S "$BUILD/libyuv" -B "$BUILD/libyuv/build-mac" \
        -DCMAKE_TOOLCHAIN_FILE="$ROOT/cross/darwin-arm64.cmake" \
        -DCMAKE_INSTALL_PREFIX="$STAGE" -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_DISABLE_FIND_PACKAGE_JPEG=TRUE >/dev/null
    cmake --build "$BUILD/libyuv/build-mac" -j"$(nproc)" >/dev/null
    cmake --install "$BUILD/libyuv/build-mac" >/dev/null
    rm -f "$STAGE"/lib/libyuv*.dylib   # force static
    cat > "$STAGE/lib/pkgconfig/libyuv.pc" <<EOF
prefix=$STAGE
libdir=\${prefix}/lib
includedir=\${prefix}/include

Name: libyuv
Description: YUV conversion and scaling library (static, aarch64-apple-darwin)
Version: 1.0.0
Libs: -L\${libdir} -lyuv -lc++
Cflags: -I\${includedir}
EOF
    echo "libyuv: staged"
fi

echo
echo "=== verification ==="
for a in "$STAGE"/lib/*.a; do
    file "$a" | head -1
done
PKG_CONFIG_LIBDIR="$STAGE/lib/pkgconfig" pkg-config --cflags --libs vpx aom opus libyuv \
    && echo "pkg-config: all four resolve — Gate A clear"
