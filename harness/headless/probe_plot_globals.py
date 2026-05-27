"""
#16 fix-hunt: FUN_0093a450 builds the plot transform from the canvas extent (correct
in our boot) + three global decimal constants DAT_00dfe988, DAT_00dfe978, DAT_00d41c00.
Scale/origin come out ZERO in our headless. If one of these globals is an uninitialized
(zero/undefined) decimal in our boot, that's the missing-init root. Dump them after boot
(byte[3]=type: 00=UNDEF/zero, 01=+, ff=-).
"""
from __future__ import annotations
import os, sys, struct
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import load, m3_one_plus_one as m3
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32

GLOBALS = {"DAT_00dfe978": 0xdfe978, "DAT_00dfe988": 0xdfe988, "DAT_00d41c00": 0xd41c00,
           "DAT_00b88830": 0xb88830, "DAT_00b88834": 0xb88834}


def dtag(b):
    t = b[3]
    return {0x00: "UNDEF/zero", 0x01: "+", 0xff: "-", 0x02: "NaN+", 0xfe: "NaN-"}.get(t, f"0x{t:02x}")


def main():
    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    m3.install_sentinel_halt(uc)
    shim, img = m3.boot(uc)
    # also run the symb/define keys (in case a global is lazily set)
    for name, kc in [("symb", 6), ("SIN", 21), ("X", 19), ("ENTER", 50)]:
        m3.inject_key(uc, shim, kc)

    print("\n==== global decimal constants used by the plot transform ====")
    for name, addr in GLOBALS.items():
        try:
            b = bytes(uc.mem_read(addr, 16))
            print(f"  {name} @0x{addr:x}: {dtag(b):<10} {b.hex()}")
        except Exception as e:
            print(f"  {name} @0x{addr:x}: read fail {e}")


if __name__ == "__main__":
    main()
