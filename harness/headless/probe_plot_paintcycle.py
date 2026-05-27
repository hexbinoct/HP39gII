"""
#10 DECISIVE: Frida on the real exe shows the plot fires renderer vtable 0xc1b3f4
slots that our headless FUN_0093f310 path NEVER calls:
  +0x1c FUN_0093eb80 (renderer OnPaint)  -> +0x48 FUN_0093cd40 (per-curve draw loop)
       -> FUN_0093c560 (draws each curve).
The curve draw (*renderer+0x48) lives inside FUN_0093e2b0, gated by the dirty bit
renderer+0x2c bit7 (0x80). Our headless does the SETUP (FUN_0093f310: +0x3c/+0x40)
but apparently not the PAINT cycle (OnPaint -> FUN_0093e2b0 -> +0x48).

This probe hooks the paint-cycle fns during our plot drain+tick (and several extra
ticks) to answer: does our headless call OnPaint / FUN_0093e2b0 / +0x48 / the curve
drawer at all? And when FUN_0093e2b0 runs, is the dirty bit (renderer+0x2c bit7) set?
"""
from __future__ import annotations
import os, sys, struct
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import load, m3_one_plus_one as m3
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE
from unicorn.x86_const import UC_X86_REG_ESP, UC_X86_REG_ECX, UC_X86_REG_EIP

BUDGET, SHOT = 300_000_000, 20_000_000
hits = {0x93eb80: 0, 0x93e2b0: 0, 0x93cd40: 0, 0x93c560: 0, 0x93f310: 0}
NAMES = {0x93eb80: "OnPaint +0x1c", 0x93e2b0: "paint-worker FUN_0093e2b0",
         0x93cd40: "+0x48 curve-loop", 0x93c560: "FUN_0093c560 curve-drawer",
         0x93f310: "FUN_0093f310 dispatch (setup)"}
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

    def mk(addr):
        def _h(uc, a, s, ud):
            if not armed["on"]:
                return
            hits[addr] += 1
            if addr == 0x93e2b0:
                ecx = uc.reg_read(UC_X86_REG_ECX)
                f2c = struct.unpack("<I", uc.mem_read(ecx + 0x2c, 4))[0]
                log.append(f"    FUN_0093e2b0 this=0x{ecx:x}  renderer+0x2c=0x{f2c:x}  "
                           f"dirty bit7(0x80)={'SET' if f2c & 0x80 else 'clear'}")
        return _h
    for a in hits:
        uc.hook_add(UC_HOOK_CODE, mk(a), begin=a, end=a + 1)

    for name, kc in [("symb", 6), ("SIN", 21), ("X", 19), ("ENTER", 50)]:
        m3.inject_key(uc, shim, kc)

    print("[setup done] injecting PLOT + draining + extra ticks, tracing paint cycle...")
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

    print("\n==== paint-cycle function hits in our headless plot ====")
    for a in (0x93f310, 0x93eb80, 0x93e2b0, 0x93cd40, 0x93c560):
        n = hits[a]
        flag = "" if n else "   *** NEVER CALLED ***"
        print(f"  0x{a:08x}  {NAMES[a]:<32}  hits={n}{flag}")
    for line in log:
        print(line)


if __name__ == "__main__":
    main()
