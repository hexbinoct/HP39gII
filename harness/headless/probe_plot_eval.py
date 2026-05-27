"""
#13: the curve coords are undefined. FUN_00959d90 is the per-sample evaluator+transform:
  entry: [ESP+8] = &X (input math X, 16B decimal)
  0x959dab: EAX = eval result struct; result+0 = eval'd X dec, result+0x10 = Y=F1(X) dec
  0x959dc9: AX = screenX short, BX = screenY short
Capture per sample to see (a) does X sweep across the window, (b) is Y=F1(X) a sine or
UNDEFINED (decimal byte[3]==0). If Y is undefined for most X -> per-sample eval fails.
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
samples = []
cur = {}


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
    armed = {"on": False}

    def h_entry(uc, a, s, ud):
        if not armed["on"]:
            return
        esp = uc.reg_read(UC_X86_REG_ESP)
        xp = struct.unpack("<I", uc.mem_read(esp + 8, 4))[0]
        try:
            cur["xin"] = bytes(uc.mem_read(xp, 16))
        except Exception:
            cur["xin"] = None

    def h_result(uc, a, s, ud):
        if not armed["on"]:
            return
        res = uc.reg_read(UC_X86_REG_EAX)
        try:
            cur["xev"] = bytes(uc.mem_read(res + 0, 16))
            cur["yev"] = bytes(uc.mem_read(res + 0x10, 16))
        except Exception:
            cur["xev"] = cur["yev"] = None

    def h_screen(uc, a, s, ud):
        if not armed["on"]:
            return
        sx = uc.reg_read(UC_X86_REG_EAX) & 0xffff
        sy = uc.reg_read(UC_X86_REG_EBX) & 0xffff
        if len(samples) < 30:
            samples.append(dict(cur, sx=sx, sy=sy))
        cur.clear()

    uc.hook_add(UC_HOOK_CODE, h_entry, begin=0x959d90, end=0x959d91)
    uc.hook_add(UC_HOOK_CODE, h_result, begin=0x959dab, end=0x959dac)
    uc.hook_add(UC_HOOK_CODE, h_screen, begin=0x959dc9, end=0x959dca)

    for name, kc in [("symb", 6), ("SIN", 21), ("X", 19), ("ENTER", 50)]:
        m3.inject_key(uc, shim, kc)

    print("[setup done] injecting PLOT, tracing per-sample eval FUN_00959d90...")
    payload = shim.malloc(16)
    uc.mem_write(payload, b"\x01" + b"\x00" * 3 + bytes([7]) + b"\x00" * 11)
    queue = struct.unpack("<I", uc.mem_read(m3.ADDR_EVENT_QUEUE, 4))[0]
    m3.call_emu(uc, m3.FN_ENQUEUE_EVENT, ecx=queue, stack_args=(0, payload))
    m3.call_emu(uc, m3.FN_PRESS_KEY, stack_args=(7,))
    armed["on"] = True
    drain_to_sentinel(uc)
    armed["on"] = False

    print(f"\n==== first {len(samples)} curve samples (X -> F1(X) -> screen) ====")
    print(f"  {'X input':<26} {'X eval':<10} {'Y=F1(X) eval':<26} {'sx':>5} {'sy':>5}")
    for s in samples:
        xin = s.get("xin"); xev = s.get("xev"); yev = s.get("yev")
        xin_s = f"{dtag(xin)} {xin.hex()}" if xin else "?"
        xev_s = dtag(xev) if xev else "?"
        yev_s = f"{dtag(yev)} {yev.hex()}" if yev else "?"
        print(f"  {xin_s:<26} {xev_s:<10} {yev_s:<26} {s['sx']:>5} {s['sy']:>5}")


if __name__ == "__main__":
    main()
