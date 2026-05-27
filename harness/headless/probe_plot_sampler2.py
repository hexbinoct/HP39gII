"""
#11: we DO reach the curve drawer FUN_0093c560 -> FUN_0095ac90 -> FUN_0095a9d0 (the
adaptive bisection sampler). The actual line raster is FUN_00959d40 (segment) and
point plot FUN_00959d00, reached only at the END of FUN_0095a9d0 IF drawing isn't
suppressed. Two suppressors:
  (A) entry gate `if ((*(byte*)(*param_1+0x18) & 3)==0)` -- sketch+0x18 low2 bits.
  (B) abort poll FUN_0043bde0(0x2e)/FUN_0043bde0(5): tests key bits 46 & 5 in the
      64-bit pressed-key mask DAT_00dfdc88/0x8c; if down -> early return (no draw).
This probe dumps sketch+0x18 + the keymask at FUN_0095a9d0 entry, and counts whether
the line-draw FUN_00959d40 / point FUN_00959d00 ever run.
"""
from __future__ import annotations
import os, sys, struct
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import load, m3_one_plus_one as m3
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE
from unicorn.x86_const import UC_X86_REG_ESP, UC_X86_REG_ECX, UC_X86_REG_EIP

BUDGET, SHOT = 300_000_000, 20_000_000
FN_SAMPLER = 0x95a9d0
FN_LINE    = 0x959d40
FN_POINT   = 0x959d00
KEYMASK_LO = 0xdfdc88
KEYMASK_HI = 0xdfdc8c
hits = {FN_SAMPLER: 0, FN_LINE: 0, FN_POINT: 0}
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


def tick_only(uc):
    state = struct.unpack("<I", uc.mem_read(m3.ADDR_STATE, 4))[0]
    call_to_sentinel(uc, m3.FN_TICK, ecx=state, stack_args=(0,))


def main():
    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    m3.install_sentinel_halt(uc)
    shim, img = m3.boot(uc)
    armed = {"on": False}

    def h_sampler(uc, a, s, ud):
        if not armed["on"]:
            return
        hits[FN_SAMPLER] += 1
        esp = uc.reg_read(UC_X86_REG_ESP)
        sketch = struct.unpack("<I", uc.mem_read(esp + 4, 4))[0]
        try:
            f18 = uc.mem_read(sketch + 0x18, 1)[0]
        except Exception:
            f18 = -1
        km_lo = struct.unpack("<I", uc.mem_read(KEYMASK_LO, 4))[0]
        km_hi = struct.unpack("<I", uc.mem_read(KEYMASK_HI, 4))[0]
        km = km_lo | (km_hi << 32)
        k5 = (km >> 5) & 1
        k46 = (km >> 46) & 1
        gate = "DRAW (gate&3==0)" if (f18 != -1 and (f18 & 3) == 0) else "*** SUPPRESSED (gate&3!=0) ***"
        log.append(f"  [#{hits[FN_SAMPLER]}] sketch=0x{sketch:x} sketch+0x18=0x{f18:02x} -> {gate}")
        log.append(f"        keymask=0x{km:016x}  key5_down={k5} key46_down={k46}  "
                   f"{'(would ABORT)' if (k5 or k46) else '(no abort)'}")

    def mk(addr):
        def _h(uc, a, s, ud):
            if armed["on"]:
                hits[addr] += 1
        return _h

    uc.hook_add(UC_HOOK_CODE, h_sampler, begin=FN_SAMPLER, end=FN_SAMPLER + 1)
    uc.hook_add(UC_HOOK_CODE, mk(FN_LINE), begin=FN_LINE, end=FN_LINE + 1)
    uc.hook_add(UC_HOOK_CODE, mk(FN_POINT), begin=FN_POINT, end=FN_POINT + 1)

    for name, kc in [("symb", 6), ("SIN", 21), ("X", 19), ("ENTER", 50)]:
        m3.inject_key(uc, shim, kc)

    print("[setup done] injecting PLOT, tracing curve sampler/line-draw...")
    payload = shim.malloc(16)
    uc.mem_write(payload, b"\x01" + b"\x00" * 3 + bytes([7]) + b"\x00" * 11)
    queue = struct.unpack("<I", uc.mem_read(m3.ADDR_EVENT_QUEUE, 4))[0]
    m3.call_emu(uc, m3.FN_ENQUEUE_EVENT, ecx=queue, stack_args=(0, payload))
    m3.call_emu(uc, m3.FN_PRESS_KEY, stack_args=(7,))
    armed["on"] = True
    drain_to_sentinel(uc)
    for _ in range(8):
        tick_only(uc)
    armed["on"] = False

    print("\n==== curve sampler + line-raster hits ====")
    print(f"  FUN_0095a9d0 sampler : {hits[FN_SAMPLER]}")
    print(f"  FUN_00959d40 line    : {hits[FN_LINE]}    {'(DREW LINES)' if hits[FN_LINE] else '*** NO LINES DRAWN ***'}")
    print(f"  FUN_00959d00 point   : {hits[FN_POINT]}")
    for line in log:
        print(line)


if __name__ == "__main__":
    main()
