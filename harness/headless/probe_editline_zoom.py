"""
Type "4+5" and dump a heavily-zoomed grayscale image of the edit-line band plus a
per-row ink profile, so we can see exactly where the glyph sits vs the separator
(top) and the menu band (bottom).
"""
from __future__ import annotations

import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import load
import m3_one_plus_one as m3
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32
from PIL import Image

LO, HI = 90, 116  # rows to inspect (edit line lives here)
ZOOM = 10


def main():
    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    m3.install_sentinel_halt(uc)
    shim, img = m3.boot(uc)

    for kc in (45, 42, 46):  # 4, +, 5  -- wait, need correct keycodes
        pass

    # keycodes: from KEY_SEQUENCE 1->42, +->45. Digits: 0..9 map to keycodes.
    # We know 1=42. The HP keypad numeric block: figure 4,5 by trying the layout.
    # 1->42, so 2->43,3->44 (row), 4->39,5->40,6->41 (row above). + -> 45.
    for kc in (39, 45, 40):  # 4, +, 5
        m3.inject_key(uc, shim, kc)

    fb = m3.read_framebuffer(uc)
    gray = m3.decode_to_grayscale(fb)
    width = 256

    print("row : ink   (90..115)")
    for row in range(LO, HI):
        ink = sum(1 for x in range(width) if gray[row * width + x] != 0)
        full = gray[row * width] != 0 and gray[row * width + 200] != 0
        print(f"{row:3} : {ink:3}  {'SEPARATOR' if ink > 200 else ''}")

    # zoomed crop of left 120px x rows LO..HI, mapped 0..3 -> 0/85/170/255
    crop_w = 120
    band = bytearray(crop_w * (HI - LO))
    for r in range(LO, HI):
        for x in range(crop_w):
            band[(r - LO) * crop_w + x] = min(255, gray[r * width + x] * 85)
    im = Image.frombytes("L", (crop_w, HI - LO), bytes(band))
    im = im.resize((crop_w * ZOOM, (HI - LO) * ZOOM), Image.NEAREST)
    out = os.path.join(HERE, "frames", "editline_zoom.png")
    im.save(out)
    print(f"\nsaved {out}")


if __name__ == "__main__":
    main()
