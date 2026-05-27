"""
Map the edit-line buffer's owner struct + length field. Type 'X' twice; find
(a) the buffer, (b) any pointer to it, (c) a nearby counter that goes 1->2.
"""
from __future__ import annotations
import os, sys, struct
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import m3_one_plus_one as m3
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32
import load


def find_ptr_to(uc, target, lo, hi):
    pat = struct.pack("<I", target)
    hits = []
    a = lo
    while a < hi:
        n = min(0x100000, hi - a)
        data = bytes(uc.mem_read(a, n))
        off = data.find(pat)
        while off != -1:
            if off % 4 == 0:
                hits.append(a + off)
            off = data.find(pat, off + 1)
        a += n
    return hits


def main():
    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    m3.install_sentinel_halt(uc)
    shim, img = m3.boot(uc)

    m3.inject_key(uc, shim, 19)   # X
    # locate buffer (the single 'X' u16)
    buf = None
    a = load.HEAP_BASE
    while a < shim.heap_ptr:
        n = min(0x100000, shim.heap_ptr - a)
        data = bytes(uc.mem_read(a, n))
        off = data.find(b"\x58\x00")
        if off != -1:
            buf = a + off; break
        a += n
    print(f"[buf] edit-line buffer at 0x{buf:x}")
    print(f"[buf] bytes: {bytes(uc.mem_read(buf, 24)).hex()}")

    # find pointers to the buffer (owner struct)
    owners = find_ptr_to(uc, buf, load.HEAP_BASE, shim.heap_ptr)
    owners += find_ptr_to(uc, buf, 0x00DD7000, 0x00E02a3b)  # .data
    print(f"[owner] pointers to buffer: {[hex(o) for o in owners]}")
    for o in owners[:8]:
        print(f"   owner 0x{o:x} ctx: {bytes(uc.mem_read(o-16, 40)).hex()}")

    # type X again -> length should change
    m3.inject_key(uc, shim, 19)
    print(f"[buf after 2nd X] bytes: {bytes(uc.mem_read(buf, 24)).hex()}")
    for o in owners[:8]:
        print(f"   owner 0x{o:x} ctx now: {bytes(uc.mem_read(o-16, 40)).hex()}")


if __name__ == "__main__":
    main()
