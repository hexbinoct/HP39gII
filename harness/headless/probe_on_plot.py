"""
Repro for the reported hang: press ON (kc 46), then Plot (kc 7) -> calc stops
responding. Boots headless and injects the two keys through the same path the
Android app uses (enqueue + press + drain/tick + release + drain/tick), with a
fault logger installed so we see exactly where Plot's handler dies, if it does.
"""
from __future__ import annotations

import os
import sys
import struct
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import load
import m3_one_plus_one as m3
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UcError, UC_HOOK_CODE
from unicorn.x86_const import UC_X86_REG_EIP, UC_X86_REG_ESP, UC_X86_REG_EAX

# Per Small 39gII.skin: Symb=6, Plot=7, Num=8, Home=11, Apps=12, Views=13.
# Each tested from a FRESH boot (the first crash bricks the VM).
TESTS = [("Symb", 6), ("Plot", 7), ("Num", 8), ("Home", 11), ("Apps", 12), ("Views", 13)]


def test_one(label, kc):
    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    m3.install_sentinel_halt(uc)
    shim, img = m3.boot(uc)
    try:
        m3.inject_key(uc, shim, kc)
        fb = m3.read_framebuffer(uc)
        nz = sum(1 for b in fb if b)
        return f"OK  (framebuffer nonzero={nz}/10922)"
    except (UcError, RuntimeError) as e:
        eip = uc.reg_read(UC_X86_REG_EIP)
        return f"CRASH  EIP=0x{eip:08x}  {e}"


def main():
    results = []
    for label, kc in TESTS:
        print(f"\n===== {label} (kc {kc}) =====")
        import io, contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            r = test_one(label, kc)
        results.append((label, kc, r))
        print(r)
    print("\n\n[SUMMARY]")
    for label, kc, r in results:
        print(f"  {label:>6} (kc {kc:>2}) : {r}")


if __name__ == "__main__":
    main()
