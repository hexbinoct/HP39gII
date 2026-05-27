"""
Test the fix: run __mtinit (CRT per-thread-data init, 0x0097cdd2) at boot, then
evaluate ifactor(24) via the edit-line+ENTER path. Success = no NULL call and a
non-echo result rendered in the history area.
"""
from __future__ import annotations
import os, sys, struct
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import m3_one_plus_one as m3
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32
import load
import probe_ifactor_repro as R

MTINIT = 0x0097CDD2
OUT = os.path.join(HERE, "frames_ifactor_fix")


def dump(uc, label):
    os.makedirs(OUT, exist_ok=True)
    fb = m3.read_framebuffer(uc)
    gray = m3.decode_to_grayscale(fb)
    m3.write_pgm(os.path.join(OUT, f"{label}.pgm"), gray)
    rows = [r for r in range(0, 94) if any(gray[r*256+x] for x in range(256))]
    print(f"[{label}] history-area rows with ink (0..93): {rows[:1]}..{rows[-1:]}  count={len(rows)}")
    for r in range(0, 94):
        ink = sum(1 for x in range(256) if gray[r*256+x])
        if ink:
            print(f"   {r:3}: {ink:3} {'#'*(ink//4)}")


def main():
    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    m3.install_sentinel_halt(uc)
    shim, img = m3.boot(uc)

    print(f"[fix] DAT_00e00e40 before __mtinit = 0x{struct.unpack('<I', uc.mem_read(0x00E00E40,4))[0]:x}")
    m3.call_emu(uc, MTINIT)
    print(f"[fix] DAT_00e00e40 after  __mtinit = 0x{struct.unpack('<I', uc.mem_read(0x00E00E40,4))[0]:x}")
    print(f"[fix] DAT_00de9f6c (TLS idx) = 0x{struct.unpack('<I', uc.mem_read(0x00DE9F6C,4))[0]:x}")

    m3.inject_key(uc, shim, 19)
    buf, owner = R.find_buf_owner(uc, shim)
    R.set_text(uc, buf, owner, "ifactor(24)")
    print(f"[fix] typed ifactor(24); pressing ENTER...")
    try:
        m3.inject_key(uc, shim, 50)
        print("[fix] ENTER processed WITHOUT null-call [OK]")
    except Exception as e:
        print(f"[fix] ENTER still failed: {str(e)[:80]}")
        return
    dump(uc, "after_enter")


if __name__ == "__main__":
    main()
