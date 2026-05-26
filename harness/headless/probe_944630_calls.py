"""
Log every FUN_00944630 call (widget ptr, flags@+0x2c, computed selector, chosen
font height, resulting top) during boot and while typing, so we can identify the
edit-line widget and see why it picks h12 instead of the native h16.
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
from unicorn.x86_const import UC_X86_REG_ECX

CALLS = []

# Replace the internal hook with a logging wrapper that still does the real work.
def logging_944630(shim, a):
    uc = shim.uc
    widget = uc.reg_read(UC_X86_REG_ECX)
    flags = load._u32(uc, widget + 0x2c)
    if (flags >> 0xc) & 1:
        sel = 1
    elif (flags >> 0xd) & 1:
        sel = 2
    else:
        bridge = load._u32(uc, 0x00DECA00)
        sel = (load._u32(uc, bridge + 0x584) if bridge else 1) or 1
    idx = (sel - 1) if sel != 0 else 0
    if idx < 0 or idx > 1:
        idx = 1
    font_ptr = load._u32(uc, 0x00C18D00 + idx * 4)
    height = 16
    if font_ptr:
        try:
            height = uc.mem_read(font_ptr, 1)[0] or 16
        except Exception:
            pass
    state = load._u32(uc, 0x00DEC9F8)
    screen_h = load._u32(uc, state + 0x10) if state else 127
    if screen_h == 0:
        screen_h = 127
    top = (screen_h - height - 0x11) & 0xFFFFFFFF
    CALLS.append((widget, flags, sel, height, top))
    uc.mem_write(widget + 8, struct.pack("<I", top))
    uc.mem_write(widget + 0x10, struct.pack("<I", (height + 1) & 0xFFFFFFFF))
    return 0

load.INTERNAL_HOOKS[0x00944630] = ("fix_FUN_00944630", logging_944630)


def main():
    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    m3.install_sentinel_halt(uc)
    print("=== boot ===")
    shim, img = m3.boot(uc)
    print(f"  {len(CALLS)} FUN_00944630 calls during boot")
    for w, f, s, h, t in CALLS:
        print(f"    widget=0x{w:08x} flags=0x{f:08x} sel={s} h={h} top={t}")
    CALLS.clear()
    print("=== type '1' ===")
    m3.inject_key(uc, shim, 42)
    for w, f, s, h, t in CALLS:
        print(f"    widget=0x{w:08x} flags=0x{f:08x} sel={s} h={h} top={t}  bit0xc={ (f>>0xc)&1 } bit0xd={ (f>>0xd)&1 }")


if __name__ == "__main__":
    main()
