"""
The grapher draw methods all run in our headless plot, but the canvas stays blank.
So: where do they WRITE? Watch UC_HOOK_MEM_WRITE during the plot tick and bucket
the targets. Answer two things:
  (1) Does the framebuffer [fb_ptr, fb_ptr+10922] get written, and in which ROWS
      (offset/86)? If only the bottom status rows are written and the canvas rows
      are not -> the curve draw is NOT targeting our fb (hidden bitmap).
  (2) What other heap region gets a big cluster of writes (the candidate hidden
      plot bitmap to be blitted)?
"""
from __future__ import annotations
import os, sys, struct
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import load, m3_one_plus_one as m3
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_MEM_WRITE
from unicorn.x86_const import UC_X86_REG_ESP, UC_X86_REG_ECX, UC_X86_REG_EIP

BUDGET, SHOT = 300_000_000, 20_000_000
PITCH = 86

watching = False
fb_lo = fb_hi = 0
fb_row_writes = {}        # row -> count (writes inside fb)
page_writes = {}          # (addr>>12) -> count (all writes, to find hidden buffer)


def call_to_sentinel(uc, fn_va, ecx=0, stack_args=()):
    esp = uc.reg_read(UC_X86_REG_ESP)
    for a in reversed(stack_args):
        esp -= 4
        uc.mem_write(esp, struct.pack("<I", a & 0xFFFFFFFF))
    esp -= 4
    uc.mem_write(esp, struct.pack("<I", m3.SENTINEL_HOST_RET))
    uc.reg_write(UC_X86_REG_ESP, esp)
    uc.reg_write(UC_X86_REG_ECX, ecx & 0xFFFFFFFF)
    spent, eip = 0, fn_va
    while spent < BUDGET:
        uc.emu_start(eip, 0, count=SHOT)
        eip = uc.reg_read(UC_X86_REG_EIP)
        spent += SHOT
        if eip == m3.SENTINEL_HOST_RET:
            return


def drain_to_sentinel(uc):
    queue = struct.unpack("<I", uc.mem_read(m3.ADDR_EVENT_QUEUE, 4))[0]
    bridge = struct.unpack("<I", uc.mem_read(m3.ADDR_HOST_BRIDGE, 4))[0]
    arg = struct.unpack("<I", uc.mem_read(bridge + 0x20, 4))[0]
    state = struct.unpack("<I", uc.mem_read(m3.ADDR_STATE, 4))[0]
    f2c = struct.unpack("<I", uc.mem_read(state + 0x2c, 4))[0]
    uc.mem_write(state + 0x2c, struct.pack("<I", f2c & 0xfffffbff))
    f90 = struct.unpack("<I", uc.mem_read(state + 0x90, 4))[0]
    if (f90 & 0x10) == 0:
        uc.mem_write(state + 0x90, struct.pack("<I", f90 | 0x10))
    call_to_sentinel(uc, m3.FN_DRAIN_QUEUE, ecx=queue, stack_args=(arg,))
    call_to_sentinel(uc, m3.FN_TICK, ecx=state, stack_args=(0,))


def main():
    global watching, fb_lo, fb_hi
    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    m3.install_sentinel_halt(uc)
    shim, img = m3.boot(uc)

    def on_write(uc, access, address, size, value, ud):
        if not watching:
            return
        page_writes[address >> 12] = page_writes.get(address >> 12, 0) + 1
        if fb_lo <= address < fb_hi:
            row = (address - fb_lo) // PITCH
            fb_row_writes[row] = fb_row_writes.get(row, 0) + 1
    uc.hook_add(UC_HOOK_MEM_WRITE, on_write)

    for name, kc in [("symb", 6), ("SIN", 21), ("X", 19), ("ENTER", 50)]:
        m3.inject_key(uc, shim, kc)

    state_ptr = struct.unpack("<I", uc.mem_read(m3.ADDR_STATE, 4))[0]
    fb_lo = struct.unpack("<I", uc.mem_read(state_ptr + m3.STATE_FB_PTR_OFS, 4))[0]
    fb_hi = fb_lo + 10922
    print(f"[fb] framebuffer @ 0x{fb_lo:x}..0x{fb_hi:x} (256x127, pitch {PITCH})")

    print("[setup done] injecting PLOT (watching writes)...")
    payload = shim.malloc(16)
    uc.mem_write(payload, b"\x01" + b"\x00" * 3 + bytes([7]) + b"\x00" * 11)
    queue = struct.unpack("<I", uc.mem_read(m3.ADDR_EVENT_QUEUE, 4))[0]
    m3.call_emu(uc, m3.FN_ENQUEUE_EVENT, ecx=queue, stack_args=(0, payload))
    m3.call_emu(uc, m3.FN_PRESS_KEY, stack_args=(7,))
    watching = True
    drain_to_sentinel(uc)
    watching = False

    fb_total = sum(fb_row_writes.values())
    print(f"\n==== framebuffer writes during plot: {fb_total} total, {len(fb_row_writes)} rows touched ====")
    if fb_row_writes:
        rows = sorted(fb_row_writes)
        print(f"  rows touched: min={rows[0]} max={rows[-1]}")
        # show which rows got writes (canvas ~0..110, status ~111..126)
        for r in rows:
            print(f"    row {r:>3}: {fb_row_writes[r]} writes")
    else:
        print("  *** NO writes into the framebuffer at all during plot ***")

    print("\n==== top 25 written PAGES (find a hidden plot bitmap) ====")
    top = sorted(page_writes.items(), key=lambda kv: kv[1], reverse=True)[:25]
    for pg, n in top:
        tag = "  <-- FRAMEBUFFER" if (pg << 12) <= fb_lo < ((pg << 12) + 0x1000) or fb_lo <= (pg << 12) < fb_hi else ""
        print(f"    page 0x{pg<<12:08x}: {n:>8} writes{tag}")


if __name__ == "__main__":
    main()
