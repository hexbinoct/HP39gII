"""
Probe the static font pointer table at 0xC18D00 and the font records it points
to, on a real headless boot. Goal: confirm whether embedded fonts exist and what
their height byte (font record +0) is — that byte drives the edit-line widget
height in FUN_00944630.
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

FONT_TABLE = 0x00C18D00


def rd(uc, addr, n):
    return bytes(uc.mem_read(addr, n))


def rd32(uc, addr):
    return struct.unpack("<I", uc.mem_read(addr, 4))[0]


def main():
    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    m3.install_sentinel_halt(uc)
    shim, img = m3.boot(uc)

    bridge = rd32(uc, m3.ADDR_HOST_BRIDGE)
    state = rd32(uc, m3.ADDR_STATE)
    print(f"[probe] host_bridge=0x{bridge:x}  state(CDesktop)=0x{state:x}")
    print(f"[probe] state+0x10 (screen height) = {rd32(uc, state + 0x10)}")
    print(f"[probe] host_bridge+0x584 (font count/default) = {rd32(uc, bridge + 0x584)}")

    print(f"\n[probe] static font pointer table @ 0x{FONT_TABLE:x}:")
    for i in range(16):
        ptr = rd32(uc, FONT_TABLE + i * 4)
        note = ""
        if ptr != 0:
            try:
                rec = rd(uc, ptr, 16)
                height = rec[0]
                note = f"  height_byte={height}  rec[0:16]={rec.hex()}"
            except Exception as e:
                note = f"  <unreadable: {e}>"
        print(f"  table[{i:2}] @0x{FONT_TABLE + i*4:x} = 0x{ptr:08x}{note}")


if __name__ == "__main__":
    main()
