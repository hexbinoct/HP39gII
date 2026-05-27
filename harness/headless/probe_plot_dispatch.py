"""
#10: range check PASSES (range valid). So FUN_0093f310 takes the draw branch.
Trace exactly which gate in FUN_0093f310's draw path our headless hits, to find
where the curve paint is skipped. Gates (from disasm of 0x93f310):
  0x93f344  EBP = range-check result (0 => draw path @0x93f392)
  0x93f348  MsgCurtain construct (range FAIL path) -- should NOT hit
  0x93f3b2  CMP [ESI+0x7c],0  -> if !=0 bail to end (pending curtain)
  0x93f3c3  TEST AL  (AL=FUN_009392f0=host_bridge+0x5d5) -> if !=0 DEFER (no draw)
  0x93f3d7  entered DRAW block
  0x93f3e8  call renderer[+0x3c]  (draw prep)
  0x93f416  CMP byte[host_bridge+0x5d4],0 -> JZ skips the main paint
  0x93f42a  call renderer[+0x40]  (MAIN PAINT)
  0x93f45e  draw completed (FUN_00939350)
"""
from __future__ import annotations
import os, sys, struct
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import load, m3_one_plus_one as m3
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE
from unicorn.x86_const import (UC_X86_REG_ESP, UC_X86_REG_ECX, UC_X86_REG_EIP,
                               UC_X86_REG_EAX, UC_X86_REG_EBP, UC_X86_REG_ESI)

BUDGET, SHOT = 300_000_000, 20_000_000
log = []


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
    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    m3.install_sentinel_halt(uc)
    shim, img = m3.boot(uc)
    armed = {"on": False, "n": 0}
    bridge = struct.unpack("<I", uc.mem_read(m3.ADDR_HOST_BRIDGE, 4))[0]

    def at(va, fn):
        uc.hook_add(UC_HOOK_CODE, fn, begin=va, end=va + 1)

    def h_entry(uc, a, s, ud):
        if not armed["on"]:
            return
        armed["n"] += 1
        ecx = uc.reg_read(UC_X86_REG_ECX)
        b5d4 = uc.mem_read(bridge + 0x5d4, 1)[0]
        b5d5 = uc.mem_read(bridge + 0x5d5, 1)[0]
        log.append(f"[call #{armed['n']}] FUN_0093f310 grapher=0x{ecx:x}  "
                   f"host_bridge+0x5d4=0x{b5d4:02x} +0x5d5=0x{b5d5:02x}")

    def h_range(uc, a, s, ud):
        if armed["on"]:
            log.append(f"    0x93f344 range-check EBP=0x{uc.reg_read(UC_X86_REG_EBP):x} "
                       f"({'DRAW path' if uc.reg_read(UC_X86_REG_EBP)==0 else 'FAIL->curtain'})")

    def h_curtain(uc, a, s, ud):
        if armed["on"]:
            log.append("    0x93f348 *** MsgCurtain construct (range FAIL) ***")

    def h_bail(uc, a, s, ud):
        if armed["on"]:
            esi = uc.reg_read(UC_X86_REG_ESI)
            v = struct.unpack("<I", uc.mem_read(esi + 0x7c, 4))[0]
            log.append(f"    0x93f3b2 [ESI+0x7c](MsgCurtain ptr)=0x{v:x} "
                       f"({'bail to end (NO draw)' if v else 'ok continue'})")

    def h_defer(uc, a, s, ud):
        if armed["on"]:
            al = uc.reg_read(UC_X86_REG_EAX) & 0xff
            log.append(f"    0x93f3c3 FUN_009392f0->AL=0x{al:02x} "
                       f"({'DEFER via FUN_00940200 (NO draw)' if al else 'enter draw block'})")

    def h_drawblock(uc, a, s, ud):
        if armed["on"]:
            log.append("    0x93f3d7 >>> entered DRAW block (FUN_0093de30 + renderer paint)")

    def h_prep(uc, a, s, ud):
        if armed["on"]:
            esi = uc.reg_read(UC_X86_REG_ESI)
            rend = struct.unpack("<I", uc.mem_read(esi + 0x8c, 4))[0]
            vt = struct.unpack("<I", uc.mem_read(rend, 4))[0]
            fn3c = struct.unpack("<I", uc.mem_read(vt + 0x3c, 4))[0]
            log.append(f"    0x93f3e8 call renderer[+0x3c]: renderer=0x{rend:x} vtable=0x{vt:x} fn_3c=0x{fn3c:x}")

    def h_paintgate(uc, a, s, ud):
        if armed["on"]:
            b = uc.mem_read(bridge + 0x5d4, 1)[0]
            log.append(f"    0x93f416 host_bridge+0x5d4=0x{b:02x} "
                       f"({'-> call MAIN PAINT renderer[+0x40]' if b else '-> SKIP main paint (JZ)'})")

    def h_paint(uc, a, s, ud):
        if armed["on"]:
            esi = uc.reg_read(UC_X86_REG_ESI)
            rend = struct.unpack("<I", uc.mem_read(esi + 0x8c, 4))[0]
            vt = struct.unpack("<I", uc.mem_read(rend, 4))[0]
            paint = struct.unpack("<I", uc.mem_read(vt + 0x40, 4))[0]
            log.append(f"    0x93f42a >>> renderer[+0x40] MAIN PAINT: renderer=0x{rend:x} "
                       f"vtable=0x{vt:x} paint_fn=0x{paint:x} <<<")

    def h_done(uc, a, s, ud):
        if armed["on"]:
            log.append("    0x93f45e draw path completed (FUN_00939350)")

    at(0x93f310, h_entry)
    at(0x93f344, h_range)
    at(0x93f348, h_curtain)
    at(0x93f3b2, h_bail)
    at(0x93f3c3, h_defer)
    at(0x93f3d7, h_drawblock)
    at(0x93f3e8, h_prep)
    at(0x93f416, h_paintgate)
    at(0x93f42a, h_paint)
    at(0x93f45e, h_done)

    for name, kc in [("symb", 6), ("SIN", 21), ("X", 19), ("ENTER", 50)]:
        m3.inject_key(uc, shim, kc)

    print("[setup done] injecting PLOT, tracing FUN_0093f310 draw dispatch...")
    payload = shim.malloc(16)
    uc.mem_write(payload, b"\x01" + b"\x00" * 3 + bytes([7]) + b"\x00" * 11)
    queue = struct.unpack("<I", uc.mem_read(m3.ADDR_EVENT_QUEUE, 4))[0]
    m3.call_emu(uc, m3.FN_ENQUEUE_EVENT, ecx=queue, stack_args=(0, payload))
    m3.call_emu(uc, m3.FN_PRESS_KEY, stack_args=(7,))
    armed["on"] = True
    drain_to_sentinel(uc)
    armed["on"] = False

    print(f"\n==== FUN_0093f310 dispatched {armed['n']} time(s) ====")
    for line in log:
        print(line)


if __name__ == "__main__":
    main()
