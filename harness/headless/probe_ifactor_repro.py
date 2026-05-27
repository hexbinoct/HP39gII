"""
Reproduce ifactor(24) the faithful way: type one char to materialise the Home
edit-line buffer, overwrite it with 'ifactor(24)', fix the length, press ENTER,
then render the framebuffer. Real exe shows 2^3*3; the bug shows the echo.
"""
from __future__ import annotations
import os, sys, struct
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import m3_one_plus_one as m3
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32
import load

OUT = os.path.join(HERE, "frames_ifactor")


def find_buf_owner(uc, shim):
    buf = None
    a = load.HEAP_BASE
    while a < shim.heap_ptr:
        n = min(0x100000, shim.heap_ptr - a)
        data = bytes(uc.mem_read(a, n))
        off = data.find(b"\x58\x00")
        if off != -1:
            buf = a + off; break
        a += n
    pat = struct.pack("<I", buf)
    owner = None
    a = load.HEAP_BASE
    while a < shim.heap_ptr:
        n = min(0x100000, shim.heap_ptr - a)
        data = bytes(uc.mem_read(a, n))
        off = data.find(pat)
        if off != -1 and (a + off) % 4 == 0:
            owner = a + off; break
        a += n
    return buf, owner


def set_text(uc, buf, owner, text):
    b = b"".join(struct.pack("<H", ord(c)) for c in text) + b"\x00\x00"
    uc.mem_write(buf, b)
    uc.mem_write(owner + 8, struct.pack("<I", len(text)))   # length field


def dump(uc, label):
    os.makedirs(OUT, exist_ok=True)
    fb = m3.read_framebuffer(uc)
    gray = m3.decode_to_grayscale(fb)
    m3.write_pgm(os.path.join(OUT, f"{label}.pgm"), gray)
    # ink profile per row to read what's on screen
    print(f"[{label}] row ink (rows 0..110, '#'=4px):")
    for row in range(0, 111):
        ink = sum(1 for x in range(256) if gray[row * 256 + x])
        if ink:
            print(f"   {row:3}: {ink:3} {'#' * (ink // 4)}")


def main():
    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    m3.install_sentinel_halt(uc)
    shim, img = m3.boot(uc)
    m3.inject_key(uc, shim, 19)   # 'X' -> materialise buffer
    buf, owner = find_buf_owner(uc, shim)
    print(f"[repro] buf=0x{buf:x} owner=0x{owner:x}")
    set_text(uc, buf, owner, "ifactor(24)")
    print(f"[repro] buffer now: {bytes(uc.mem_read(buf, 26)).hex()}  len@owner+8={struct.unpack('<I', uc.mem_read(owner+8,4))[0]}")
    dump(uc, "0_typed")
    m3.inject_key(uc, shim, 50)   # ENTER
    dump(uc, "1_after_enter")


if __name__ == "__main__":
    main()
