"""
Boot, type "1+1", and profile the framebuffer rows around the edit line to
confirm the FUN_00944630 fix widened the edit-line region from ~4px to ~17px.

Diagnosis baseline:
  native (correct): edit-line separator row 94, glyph rows 95-110 (~15px)
  broken harness:   separator row 107, glyph rows 108-110 (~3px, tops only)
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


def row_profile(uc, lo=88, hi=127):
    fb = m3.read_framebuffer(uc)
    gray = m3.decode_to_grayscale(fb)
    width = 256
    print(f"  row : ink-pixels (rows {lo}..{hi-1}), '#' per 4 ink px")
    for row in range(lo, hi):
        ink = sum(1 for x in range(width) if gray[row * width + x] != 0)
        bar = "#" * (ink // 4)
        print(f"  {row:3} : {ink:3}  {bar}")


def main():
    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    m3.install_sentinel_halt(uc)
    shim, img = m3.boot(uc)

    # widget-height sanity: dump the ABCNumView edit-line widget top/height if we
    # can find it is hard without the tree; instead just type and profile rows.
    for label, kc in m3.KEY_SEQUENCE[:3]:  # 1, +, 1  (stop before ENTER so edit line still shows "1+1")
        m3.inject_key(uc, shim, kc)
        print(f"[typed {label}]")

    print("\n[edit-line row profile after typing '1+1']")
    row_profile(uc)


if __name__ == "__main__":
    main()
