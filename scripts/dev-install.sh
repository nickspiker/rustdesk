#!/usr/bin/env bash
# dev-install: build this fork and atomically (re)install the binary you're actually RUNNING —
# so you never test a stale copy again. The stale-binary trap has three parts, and this closes
# all three:
#   1. build output (target/release/rustdesk) != run location (.app bundle / ~/.local/bin),
#   2. a live process keeps the OLD on-disk image mapped until it exits,
#   3. a supervisor (macOS LaunchAgent / systemd user service) relaunches the OLD file.
# So: build → STOP the app + its supervisor + wait for the table to clear → swap the run-location
# binary → verify hash → relaunch. One command, on either machine.
#
# Usage:  scripts/dev-install.sh            (build + install + relaunch)
#         scripts/dev-install.sh --no-build (install the existing target/release build)
set -euo pipefail
cd "$(dirname "$0")/.."

FEATURES="inline,fgtw,fluor-viewer,linux-pkg-config"
OS="$(uname)"
BUILT="$(pwd)/target/release/rustdesk"

sha() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'; else shasum -a 256 "$1" | awk '{print $1}'; fi; }

if [ "${1:-}" != "--no-build" ]; then
    echo "▶ building (fast dev profile: no LTO)…"
    # CXXFLAGS=-include cstdint is pinned in .cargo/config.toml, so a bare build already works.
    CARGO_PROFILE_RELEASE_LTO=false \
    CARGO_PROFILE_RELEASE_CODEGEN_UNITS=16 \
    CARGO_PROFILE_RELEASE_OPT_LEVEL=2 \
        cargo build --release --features "$FEATURES"
fi
[ -f "$BUILT" ] || { echo "✗ no build at $BUILT"; exit 1; }
BUILT_HASH="$(sha "$BUILT")"

echo "▶ stopping any running / supervised RustDesk…"
if [ "$OS" = "Darwin" ]; then
    osascript -e 'tell application "RustDesk" to quit' 2>/dev/null || true
    launchctl bootout "gui/$(id -u)/com.nickspiker.rustdesk" 2>/dev/null || true
    launchctl remove com.nickspiker.rustdesk 2>/dev/null || true
else
    systemctl --user stop rustdesk-fgtw.service 2>/dev/null || true
fi
pkill -9 -x rustdesk 2>/dev/null || true
pkill -9 -f "rustdesk --" 2>/dev/null || true
# Wait up to ~6s for the process table to clear before we overwrite the file.
for _ in $(seq 1 12); do pgrep -x rustdesk >/dev/null 2>&1 || break; sleep 0.5; done
if pgrep -x rustdesk >/dev/null 2>&1; then
    echo "✗ rustdesk keeps respawning — a supervisor is still up. Investigate, don't install stale:"
    pgrep -alx rustdesk || true
    exit 1
fi

echo "▶ installing $BUILT_HASH into the run location…"
if [ "$OS" = "Darwin" ]; then
    APP="$HOME/Applications/RustDesk.app"; [ -d "$APP" ] || APP="/Applications/RustDesk.app"
    DEST="$APP/Contents/MacOS/rustdesk"
    [ -d "$(dirname "$DEST")" ] || { echo "✗ no app bundle at $APP — run installers/install-release.sh once to create it"; exit 1; }
    cp -f "$BUILT" "$DEST"
    xattr -c "$DEST" 2>/dev/null || true
else
    DEST="$HOME/.local/bin/rustdesk"
    mkdir -p "$(dirname "$DEST")"
    cp -f "$BUILT" "$DEST"
    command -v restorecon >/dev/null 2>&1 && restorecon "$DEST" 2>/dev/null || true
fi

# The run location must now be byte-identical to what we built — no silent no-op copy.
[ "$(sha "$DEST")" = "$BUILT_HASH" ] || { echo "✗ installed hash != build hash — copy didn't take"; exit 1; }
echo "✓ run location matches build: $BUILT_HASH"

echo "▶ relaunching…"
if [ "$OS" = "Darwin" ]; then
    open "$APP"
else
    if systemctl --user cat rustdesk-fgtw.service >/dev/null 2>&1; then
        systemctl --user start rustdesk-fgtw.service
    else
        DISPLAY="${DISPLAY:-:0}" nohup "$DEST" --service >/dev/null 2>&1 &
    fi
fi
echo "✓ done — you are running the fresh build ($BUILT_HASH). No stale copy."
