"""
Find the Home edit-line text buffer: inject a distinctive key and scan the heap
for the newly-written UTF-16 character, so we can later write 'ifactor(24)'
directly and press ENTER (the faithful tokenize+eval path).
"""
from __future__ import annotations
import os, sys, struct
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import m3_one_plus_one as m3
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32
import load


def scan_u16(uc, ch, lo, hi):
    pat = struct.pack("<H", ch)
    hits = []
    CHUNK = 0x100000
    a = lo
    while a < hi:
        n = min(CHUNK, hi - a)
        data = bytes(uc.mem_read(a, n))
        off = data.find(pat)
        while off != -1:
            if off + 4 <= len(data):
                # require it look like part of a UTF-16 string (next char printable or NUL)
                nxt = struct.unpack("<H", data[off+2:off+4])[0] if off+4 <= len(data) else 0
                hits.append(a + off)
            off = data.find(pat, off + 2)
        a += n
    return hits


def main():
    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    m3.install_sentinel_halt(uc)
    shim, img = m3.boot(uc)
    HEAP_HI = shim.heap_ptr if hasattr(shim, "heap_ptr") else 0x14000000

    # type 'X' (keycode 19) then ';' ... use two dedicated keys: X=19, then 7? keep simple: X then SIN.
    before = set(scan_u16(uc, ord('X'), load.HEAP_BASE, HEAP_HI))
    m3.inject_key(uc, shim, 19)   # X
    HEAP_HI = shim.heap_ptr
    after = scan_u16(uc, ord('X'), load.HEAP_BASE, HEAP_HI)
    new = [a for a in after if a not in before]
    print(f"[X] total 'X' u16 hits={len(after)} new={len(new)}")
    for a in new[:40]:
        ctx = bytes(uc.mem_read(a - 8, 24))
        print(f"   0x{a:x}: ...{ctx.hex()}")


if __name__ == "__main__":
    main()
