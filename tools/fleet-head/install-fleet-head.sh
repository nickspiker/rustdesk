#!/usr/bin/env bash
# Install a virtual monitor ("fleet head") on an unused display connector.
#
# WHY: a remote viewer wants a screen of its own — its own resolution, workspace, panel and clock —
# without touching the monitor someone at the desk is using. A head on a merely-disconnected
# connector gets none of that: the desktop ignores it and the compositor switches it off on every
# restart. Feeding the kernel a synthetic EDID makes the connector report as connected, and from
# there the desktop treats it as an ordinary monitor and manages it like one.
#
# The host binary finds this head by the monitor name in its EDID, so it knows which display is safe
# to resize (nobody is looking at it) and which is not.
#
# Size it to the VIEWER'S backing size, not to a round number: resolution-follow asks the host to
# render at exactly the viewer's pixel size, and any mismatch costs a rescale.
#
# Run:  sudo bash install-fleet-head.sh [CONNECTOR] [WxH]
# Undo: sudo bash install-fleet-head.sh --undo
set -euo pipefail

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DRACUT_CONF=/etc/dracut.conf.d/fleet-edid.conf
EDID_DIR=/lib/firmware/edid

if [ "${1:-}" = "--undo" ]; then
    command -v grubby >/dev/null && grubby --update-kernel=ALL --remove-args="drm.edid_firmware video" || true
    rm -f "$DRACUT_CONF" "$EDID_DIR"/fleet-*.bin
    command -v dracut >/dev/null && dracut -f --regenerate-all || true
    echo "UNDONE. Reboot to return to the previous display setup."
    exit 0
fi

CONNECTOR="${1:-HDMI-A-1}"
RES="${2:-3840x2160}"
BLOB="fleet-${RES}.bin"

# List candidates if the named connector is not one a head can live on.
if [ ! -d "/sys/class/drm/card"*"-${CONNECTOR}" ] 2>/dev/null; then
    echo "Connector '$CONNECTOR' not found. Disconnected connectors on this machine:"
    for c in /sys/class/drm/card*-*/; do
        [ -f "$c/status" ] || continue
        [ "$(cat "$c/status")" = "disconnected" ] || continue
        echo "   $(basename "$c" | cut -d- -f2-)"
    done
    exit 1
fi

install -d -m 0755 "$EDID_DIR"
python3 "$SRC/make-edid.py" "${RES%x*}" "${RES#*x}" "$EDID_DIR/$BLOB"
chmod 0644 "$EDID_DIR/$BLOB"

# The EDID is requested when the GPU driver probes the connector, which happens inside the initramfs
# — so the blob has to live there too, not just on the root filesystem. Takes ~45 s.
printf 'install_items+=" %s/%s "\n' "$EDID_DIR" "$BLOB" > "$DRACUT_CONF"
dracut -f --regenerate-all
echo "initramfs regenerated with $BLOB"

grubby --update-kernel=ALL --remove-args="drm.edid_firmware video" || true
grubby --update-kernel=ALL --args="drm.edid_firmware=${CONNECTOR}:edid/${BLOB} video=${CONNECTOR}:e"
echo "kernel args:"; grubby --info=DEFAULT | grep -o 'drm.edid_firmware=[^ "]*\|video=[^ "]*' || true

cat <<MSG

DONE. Reboot, then check for two monitors:   xrandr --query | grep " connected"
Undo with:                                   sudo bash $SRC/install-fleet-head.sh --undo
MSG
