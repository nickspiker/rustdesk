#!/usr/bin/env python3
"""Generate a forced-EDID blob describing a virtual monitor of an arbitrary size.

A virtual head only earns a desktop if the connector it lives on reports as *connected*. A
disconnected connector gets no workspace, no panel and no clock, and the compositor switches it back
off on every restart. Feeding the kernel a synthetic EDID for an unused connector makes it a monitor
as far as userspace is concerned, which is all the desktop needs.

Timings are CVT reduced-blanking, computed here rather than shelled out to `cvt`, which is often
absent on a headless box. The blob also advertises 1920x1080, 1024x768 and 640x480 as fallbacks, so
a preferred timing the hardware rejects still leaves a usable head instead of a dead one.

Usage:  make-edid.py 3840 2160 [out.bin]
"""
import struct
import sys

CVT_RB_H_BLANK = 160
CVT_RB_V_FRONT = 3
CVT_RB_V_SYNC = 4
CVT_RB_MIN_V_BLANK_US = 460.0


def cvt_rb(width, height, refresh=60):
    """CVT reduced-blanking totals: (h_total, v_total, pixel_clock_in_10kHz)."""
    h_total = width + CVT_RB_H_BLANK
    v_blank = max(
        CVT_RB_V_FRONT + CVT_RB_V_SYNC + 1,
        int(round(refresh * CVT_RB_MIN_V_BLANK_US * 1e-6 * height
                  / (1 - refresh * CVT_RB_MIN_V_BLANK_US * 1e-6)))
        + CVT_RB_V_FRONT + CVT_RB_V_SYNC,
    )
    v_total = height + v_blank
    return h_total, v_total, int(round(h_total * v_total * refresh / 10000.0))


def build(width, height, name):
    h_total, v_total, clock = cvt_rb(width, height)
    e = bytearray(128)
    e[0:8] = bytes([0, 255, 255, 255, 255, 255, 255, 0])
    # Manufacturer "LNX", arbitrary product/serial — nothing keys off them.
    e[8:10] = struct.pack(">H", ((ord("L") - 64) << 10) | ((ord("N") - 64) << 5) | (ord("X") - 64))
    e[10:12] = struct.pack("<H", 1)
    e[12:16] = struct.pack("<I", 1)
    e[16], e[17] = 0, 33                      # week 0, year 2023
    e[18], e[19] = 1, 4                       # EDID 1.4
    e[20] = 0xA0                              # digital, 8 bpc
    e[21], e[22] = max(1, width // 64), max(1, height // 64)   # physical size, cm
    e[23], e[24] = 120, 0x06                  # gamma 2.2, features
    e[25:35] = bytes([0x5A, 0x8A, 0xA5, 0x59, 0x4A, 0x98, 0x25, 0x20, 0x50, 0x54])  # chroma
    e[35], e[36], e[37] = 0x20, 0x08, 0x00    # established: 640x480@60, 1024x768@60
    for i in range(38, 54):
        e[i] = 0x01                           # unused standard-timing slots
    e[38], e[39] = (1920 // 8) - 31, 0x40     # standard timing: 1920x1080@60

    h_blank, v_blank = h_total - width, v_total - height
    h_sync_off, h_sync_w, v_sync_off, v_sync_w = h_blank // 2 - 32, 32, 3, 4
    d = bytearray(18)
    d[0:2] = struct.pack("<H", clock)
    d[2] = width & 0xFF
    d[3] = h_blank & 0xFF
    d[4] = ((width >> 8) << 4) | ((h_blank >> 8) & 0xF)
    d[5] = height & 0xFF
    d[6] = v_blank & 0xFF
    d[7] = ((height >> 8) << 4) | ((v_blank >> 8) & 0xF)
    d[8] = h_sync_off & 0xFF
    d[9] = h_sync_w & 0xFF
    d[10] = ((v_sync_off & 0xF) << 4) | (v_sync_w & 0xF)
    d[11] = ((h_sync_off >> 8) << 6) | ((h_sync_w >> 8) << 4) | ((v_sync_off >> 4) << 2) | (v_sync_w >> 4)
    d[17] = 0x1E
    e[54:72] = d

    # Monitor name — this is what the host matches on to know the head is its own.
    nm = bytearray(18)
    nm[0:5] = bytes([0, 0, 0, 0xFC, 0])
    nm[5:18] = (name + "\n").ljust(13)[:13].encode()
    e[72:90] = nm
    for off in (90, 108):
        dd = bytearray(18)
        dd[0:5] = bytes([0, 0, 0, 0x10, 0])
        dd[5:18] = b" " * 13
        e[off:off + 18] = dd
    e[127] = (-sum(e[0:127])) & 0xFF
    return bytes(e)


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return 1
    width, height = int(sys.argv[1]), int(sys.argv[2])
    out = sys.argv[3] if len(sys.argv) > 3 else f"fleet-{width}x{height}.bin"
    blob = build(width, height, f"FLEET{height}")
    assert sum(blob) % 256 == 0, "EDID checksum"
    with open(out, "wb") as f:
        f.write(blob)
    h_total, v_total, clock = cvt_rb(width, height)
    print(f"{out}: {width}x{height} @ {clock / 100:.1f} MHz ({h_total}x{v_total} total)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
