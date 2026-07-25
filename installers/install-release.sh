#!/bin/sh
# RustDesk (passless fork) installer — Photon-style: bare verified binaries, no packages.
# Integrity: .sha256 sidecars (the binary also carries an appended Ed25519 signature for
# manifest-level trust; rustdesk has no self-verify subcommand, so the sidecar is the gate).
#
# RUSTDESK_LOCAL_DIR=<dir>: take artifacts from a local directory instead of downloading
# (used for pre-publish smoke tests; grammy never needs it).
set -e

echo "RustDesk — passless remote desktop"
echo "=================================="
echo ""

BASE_URL="https://brobdingnagian.holdmyoscilloscope.com/rustdesk"

OS=$(uname -s)
ARCH=$(uname -m)

case "$OS" in
    Linux*)
        if [ "$ARCH" != "x86_64" ]; then
            echo "Error: Linux $ARCH not built yet (x86_64 only for now)."
            exit 1
        fi
        PLATFORM="linux-x86_64"
        SCITER_REMOTE="libsciter-gtk-linux-x86_64-release.so"
        SCITER_NAME="libsciter-gtk.so"
        INSTALL_DIR="$HOME/.local/bin"
        ;;
    Darwin*)
        if [ "$ARCH" != "arm64" ] && [ "$ARCH" != "aarch64" ]; then
            echo "Error: Intel macOS not built yet (Apple Silicon only for now)."
            exit 1
        fi
        PLATFORM="macos-arm64"
        SCITER_REMOTE="libsciter-macos-release.dylib"
        SCITER_NAME="libsciter.dylib"
        INSTALL_DIR="$HOME/.local/bin"
        APP_DIR="$HOME/Applications"
        APP_NAME="RustDesk.app"
        ;;
    *)
        echo "Error: Unsupported operating system: $OS"
        exit 1
        ;;
esac

BINARY_REMOTE="rustdesk-$PLATFORM-release"
BINARY_NAME="rustdesk"

echo "Detected: $OS ($ARCH)"
echo ""

get() { # get <remote-name> <dest>
    if [ -n "${RUSTDESK_LOCAL_DIR:-}" ]; then
        cp "$RUSTDESK_LOCAL_DIR/$1" "$2"
    elif command -v curl >/dev/null 2>&1; then
        curl -sSfL "$BASE_URL/$1" -o "$2"
    elif command -v wget >/dev/null 2>&1; then
        wget -q "$BASE_URL/$1" -O "$2"
    else
        echo "Error: Neither curl nor wget found. Please install one and try again."
        exit 1
    fi
}

sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    else
        shasum -a 256 "$1" | awk '{print $1}'
    fi
}

fetch_verified() { # fetch_verified <remote-name> <dest>
    get "$1" "$2"
    get "$1.sha256" "$2.sha256"
    want=$(awk '{print $1}' "$2.sha256")
    have=$(sha256_of "$2")
    if [ "$want" != "$have" ]; then
        echo "Error: checksum mismatch for $1 — corrupted or tampered download."
        rm -f "$2" "$2.sha256"
        exit 1
    fi
    rm -f "$2.sha256"
}

TMP_BINARY="/tmp/rustdesk-$$"
TMP_SCITER="/tmp/rustdesk-sciter-$$"

echo "Downloading RustDesk..."
fetch_verified "$BINARY_REMOTE" "$TMP_BINARY"
echo "Downloading UI runtime..."
fetch_verified "$SCITER_REMOTE" "$TMP_SCITER"
echo "✓ Checksums verified"
echo ""

chmod +x "$TMP_BINARY"
if [ "$OS" = "Darwin" ]; then
    xattr -c "$TMP_BINARY" "$TMP_SCITER" 2>/dev/null || true
fi

echo "Installing to $INSTALL_DIR..."
mkdir -p "$INSTALL_DIR"
# cp (not mv): mv from /tmp drags the SELinux user_tmp_t label along on Fedora-family
# systems, and dlopen of a tmp-labeled library is denied — the app then can't find its
# UI runtime. A fresh copy inherits the destination context.
cp "$TMP_BINARY" "$INSTALL_DIR/$BINARY_NAME"
# The sciter loader searches the executable's own directory.
cp "$TMP_SCITER" "$INSTALL_DIR/$SCITER_NAME"
rm -f "$TMP_BINARY" "$TMP_SCITER"
command -v restorecon >/dev/null 2>&1 && restorecon "$INSTALL_DIR/$BINARY_NAME" "$INSTALL_DIR/$SCITER_NAME" 2>/dev/null || true
if [ "$OS" = "Darwin" ]; then
    xattr -c "$INSTALL_DIR/$BINARY_NAME" "$INSTALL_DIR/$SCITER_NAME" 2>/dev/null || true
fi
echo "✓ Installed"
echo ""

# macOS .app bundle for Finder/Dock/Spotlight
if [ "$OS" = "Darwin" ]; then
    echo "Creating macOS app bundle..."
    mkdir -p "$APP_DIR/$APP_NAME/Contents/MacOS"
    mkdir -p "$APP_DIR/$APP_NAME/Contents/Resources"

    cp "$INSTALL_DIR/$BINARY_NAME" "$APP_DIR/$APP_NAME/Contents/MacOS/$BINARY_NAME"
    cp "$INSTALL_DIR/$SCITER_NAME" "$APP_DIR/$APP_NAME/Contents/MacOS/$SCITER_NAME"
    chmod +x "$APP_DIR/$APP_NAME/Contents/MacOS/$BINARY_NAME"

    ICON_TMP="/tmp/rustdesk-icon-$$"
    mkdir -p "$ICON_TMP.iconset"
    if get "icon-1024.png" "$ICON_TMP.png" 2>/dev/null; then
        sips -z 16 16     "$ICON_TMP.png" --out "$ICON_TMP.iconset/icon_16x16.png" 2>/dev/null || true
        sips -z 32 32     "$ICON_TMP.png" --out "$ICON_TMP.iconset/icon_16x16@2x.png" 2>/dev/null || true
        sips -z 32 32     "$ICON_TMP.png" --out "$ICON_TMP.iconset/icon_32x32.png" 2>/dev/null || true
        sips -z 64 64     "$ICON_TMP.png" --out "$ICON_TMP.iconset/icon_32x32@2x.png" 2>/dev/null || true
        sips -z 128 128   "$ICON_TMP.png" --out "$ICON_TMP.iconset/icon_128x128.png" 2>/dev/null || true
        sips -z 256 256   "$ICON_TMP.png" --out "$ICON_TMP.iconset/icon_128x128@2x.png" 2>/dev/null || true
        sips -z 256 256   "$ICON_TMP.png" --out "$ICON_TMP.iconset/icon_256x256.png" 2>/dev/null || true
        sips -z 512 512   "$ICON_TMP.png" --out "$ICON_TMP.iconset/icon_256x256@2x.png" 2>/dev/null || true
        sips -z 512 512   "$ICON_TMP.png" --out "$ICON_TMP.iconset/icon_512x512.png" 2>/dev/null || true
        sips -z 1024 1024 "$ICON_TMP.png" --out "$ICON_TMP.iconset/icon_512x512@2x.png" 2>/dev/null || true
        iconutil -c icns "$ICON_TMP.iconset" -o "$APP_DIR/$APP_NAME/Contents/Resources/AppIcon.icns" 2>/dev/null || true
        rm -rf "$ICON_TMP.png" "$ICON_TMP.iconset"
    fi

    # com.nickspiker.rustdesk: TCC grants key off the bundle id; a distinct id can never
    # collide with an official RustDesk install. Config paths are unaffected (hbb_common
    # hardcodes its own dirs).
    cat > "$APP_DIR/$APP_NAME/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>rustdesk</string>
    <key>CFBundleIconFile</key>
    <string>AppIcon</string>
    <key>CFBundleIdentifier</key>
    <string>com.nickspiker.rustdesk</string>
    <key>CFBundleName</key>
    <string>RustDesk</string>
    <key>CFBundleDisplayName</key>
    <string>RustDesk</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleVersion</key>
    <string>1.0</string>
    <key>CFBundleShortVersionString</key>
    <string>1.4.9</string>
    <key>LSMinimumSystemVersion</key>
    <string>11.0</string>
    <key>NSHighResolutionCapable</key>
    <true/>
    <key>NSSupportsAutomaticGraphicsSwitching</key>
    <true/>
    <key>NSMicrophoneUsageDescription</key>
    <string>RustDesk transmits this Mac's audio during remote sessions.</string>
    <key>NSCameraUsageDescription</key>
    <string>RustDesk can share this Mac's camera during remote sessions.</string>
</dict>
</plist>
PLIST

    xattr -cr "$APP_DIR/$APP_NAME" 2>/dev/null || true
    echo "✓ App bundle created at $APP_DIR/$APP_NAME"
    echo ""
fi

# Add to PATH — macOS bash uses .bash_profile; modern macOS defaults to zsh.
SHELL_RC=""
PATH_UPDATED=""
case "$SHELL" in
    */zsh) SHELL_RC="$HOME/.zshrc" ;;
    */bash)
        if [ "$OS" = "Darwin" ]; then SHELL_RC="$HOME/.bash_profile"; else SHELL_RC="$HOME/.bashrc"; fi ;;
    */fish) SHELL_RC="$HOME/.config/fish/config.fish" ;;
esac
if [ -n "$SHELL_RC" ]; then
    [ -f "$SHELL_RC" ] || touch "$SHELL_RC"
    if ! grep -q "$INSTALL_DIR" "$SHELL_RC" 2>/dev/null; then
        {
            echo ""
            echo "# Added by RustDesk installer"
            echo "export PATH=\"\$PATH:$INSTALL_DIR\""
        } >> "$SHELL_RC"
        PATH_UPDATED="$SHELL_RC"
        echo "✓ Added to PATH in $SHELL_RC"
    fi
fi

# Desktop entry (Linux)
if [ "$OS" = "Linux" ]; then
    echo "Creating desktop shortcut..."
    ICON_DIR="$HOME/.local/share/icons/hicolor/256x256/apps"
    mkdir -p "$ICON_DIR"
    get "app.png" "$ICON_DIR/rustdesk.png" 2>/dev/null || true

    DESKTOP_DIR="$HOME/.local/share/applications"
    mkdir -p "$DESKTOP_DIR"
    cat > "$DESKTOP_DIR/rustdesk.desktop" <<EOF
[Desktop Entry]
Version=1.0
Type=Application
Name=RustDesk
Comment=Passless remote desktop — your machines just show up
Exec=$INSTALL_DIR/$BINARY_NAME
Icon=rustdesk
Terminal=false
Categories=Network;RemoteAccess;
Keywords=remote;desktop;passless;fleet;
StartupWMClass=rustdesk
EOF
    chmod +x "$DESKTOP_DIR/rustdesk.desktop"
    command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database "$DESKTOP_DIR" 2>/dev/null || true
    command -v gtk-update-icon-cache >/dev/null 2>&1 && gtk-update-icon-cache -f -t "$HOME/.local/share/icons/hicolor" 2>/dev/null || true
    echo "✓ Desktop shortcut created"
fi

echo ""
echo "=================================="
echo "✓ RustDesk installed successfully!"
echo "=================================="
echo ""

if [ "$OS" = "Darwin" ]; then
    echo "Open it: Finder → ~/Applications → RustDesk (or Spotlight: 'RustDesk')"
    echo ""
    echo "First launch, macOS will ask you to grant two permissions in"
    echo "System Settings → Privacy & Security:"
    echo "  • Screen Recording   (so a fleet device can see this screen)"
    echo "  • Accessibility      (so it can control mouse and keyboard)"
    echo ""
    echo "If you're logged in (Photon), your machines appear in the My Fleet tab —"
    echo "no password, no setup."
    [ -n "$PATH_UPDATED" ] && echo "" && echo "(terminal use: restart your shell or 'source $PATH_UPDATED')"
else
    echo "Run 'rustdesk' or find RustDesk in your application menu."
    echo ""
    echo "If you're logged in (Photon), your machines appear in the My Fleet tab —"
    echo "no password, no setup."
    [ -n "$PATH_UPDATED" ] && echo "" && echo "(restart your terminal or: source $PATH_UPDATED)"
fi
echo ""
echo "Note: this machine is reachable by your fleet while RustDesk is running."
echo "      (Auto-start as a service is coming; for now, keep it open.)"
