"""
#17 FIX VALIDATION: root cause = our boot enters at the calc thread and skips
mainCRTStartup's _initterm walk of the C++ static-init table (.CRT$XC*), so the
static initializers FUN_00a2c190 / FUN_00a2c1d0 (which set DAT_00dfe978 =
DAT_00dfe988 = 21/2 = 10.5, the plot-transform scale constants) never run -> scale=0
-> curve maps to (0,0). Validate: call those two initializers after boot, then plot
and check (a) the transform scale ctx+0x10 is now a valid decimal, (b) the per-sample
screen coords are no longer (0,0).
"""
from __future__ import annotations
import os, sys, struct
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import load, m3_one_plus_one as m3
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE
from unicorn.x86_const import (UC_X86_REG_ESP, UC_X86_REG_ECX, UC_X86_REG_EIP,
                               UC_X86_REG_EAX, UC_X86_REG_EBX)

BUDGET, SHOT = 300_000_000, 20_000_000
INIT_FNS = [0xa2c190, 0xa2c1d0, 0xa2c210, 0xa2c250]  # X: dfe978/988, Y: dfe998/9a8 (all = 10.5)
samples = []


def dtag(b):
    t = b[3]
    return {0x00: "UNDEF", 0x01: "+", 0xff: "-", 0x02: "NaN+", 0xfe: "NaN-"}.get(t, f"0x{t:02x}")


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

    print("\n[fix] DAT_00dfe978/988 before init:",
          dtag(bytes(uc.mem_read(0xdfe978, 16))), dtag(bytes(uc.mem_read(0xdfe988, 16))))
    for fn in INIT_FNS:
        m3.call_emu(uc, fn)
    d978 = bytes(uc.mem_read(0xdfe978, 16)); d988 = bytes(uc.mem_read(0xdfe988, 16))
    print(f"[fix] after running static inits FUN_00a2c190/FUN_00a2c1d0:")
    print(f"      DAT_00dfe978 = {dtag(d978)} {d978.hex()}")
    print(f"      DAT_00dfe988 = {dtag(d988)} {d988.hex()}")

    armed = {"on": False}

    def h_screen(uc, a, s, ud):
        if not armed["on"] or len(samples) >= 20:
            return
        sx = uc.reg_read(UC_X86_REG_EAX) & 0xffff
        sy = uc.reg_read(UC_X86_REG_EBX) & 0xffff
        samples.append((sx, sy))
    uc.hook_add(UC_HOOK_CODE, h_screen, begin=0x959dc9, end=0x959dca)

    for name, kc in [("symb", 6), ("SIN", 21), ("X", 19), ("ENTER", 50)]:
        m3.inject_key(uc, shim, kc)

    print("\n[setup done] injecting PLOT with inits applied...")
    payload = shim.malloc(16)
    uc.mem_write(payload, b"\x01" + b"\x00" * 3 + bytes([7]) + b"\x00" * 11)
    queue = struct.unpack("<I", uc.mem_read(m3.ADDR_EVENT_QUEUE, 4))[0]
    m3.call_emu(uc, m3.FN_ENQUEUE_EVENT, ecx=queue, stack_args=(0, payload))
    m3.call_emu(uc, m3.FN_PRESS_KEY, stack_args=(7,))
    armed["on"] = True
    drain_to_sentinel(uc)
    armed["on"] = False

    nonzero = [(x, y) for x, y in samples if not (x == 0 and y == 0)]
    print(f"\n==== first {len(samples)} curve screen coords (was all (0,0) before fix) ====")
    print("  " + "  ".join(f"({x},{y})" for x, y in samples))
    print(f"\n  non-(0,0) points: {len(nonzero)}/{len(samples)}  -> "
          f"{'*** CURVE NOW HAS REAL COORDS — FIX CONFIRMED ***' if nonzero else 'still zero — not fixed'}")


if __name__ == "__main__":
    main()
