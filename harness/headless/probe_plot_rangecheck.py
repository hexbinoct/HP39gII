"""
HYPOTHESIS (2026-05-27 #9): the curve never draws because the grapher's plot-range
validator FUN_00937230 (0x937230) fails. It compares Xmin<Xmax (BCD decimals at
grapher+0x00 vs +0x10) and Ymin<Ymax (+0x20 vs +0x30) via FUN_00490920 (a BCD compare:
byte[3] = sign/type, 00=undefined, 01=+, ff=-, 02/fe=NaN/inf). If any bound is
undefined/invalid it returns 0x437..0x43a (nonzero) -> FUN_0093f310 builds the
MsgCurtain_PlotSetup busy curtain (the persistent ※) and NEVER draws the curve.
This unifies "X: undefined" + busy icon + blank canvas.

This probe hooks 0x937230 entry, dumps ECX (grapher this) and the 4 range decimals,
and captures the return value. If the decimals are undefined (byte[3]==0) and/or it
returns nonzero -> hypothesis CONFIRMED.
"""
from __future__ import annotations
import os, sys, struct
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import load, m3_one_plus_one as m3
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE
from unicorn.x86_const import UC_X86_REG_ESP, UC_X86_REG_ECX, UC_X86_REG_EIP, UC_X86_REG_EAX

FN_RANGECHECK = 0x937230
FN_DISPATCH   = 0x93f310

BUDGET, SHOT = 300_000_000, 20_000_000

events = []          # log lines
ret_addrs = set()    # caller return addrs of FN_RANGECHECK (to read EAX on return)
pending_ret = []     # stack of return addrs we expect


def fmt_dec(b):
    # 16-byte BCD decimal; byte[3] = sign/type
    t = b[3]
    tag = {0x00: "UNDEFINED", 0x01: "+", 0xff: "-", 0x02: "NaN/inf+", 0xfe: "NaN/inf-"}.get(t, f"type=0x{t:02x}")
    return f"[3]=0x{t:02x} {tag:<10} raw={b.hex()}"


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

    def on_entry(uc, address, size, ud):
        if not armed["on"]:
            return
        armed["n"] += 1
        ecx = uc.reg_read(UC_X86_REG_ECX)
        esp = uc.reg_read(UC_X86_REG_ESP)
        ret = struct.unpack("<I", uc.mem_read(esp, 4))[0]
        pending_ret.append(ret)
        try:
            d0 = uc.mem_read(ecx + 0x00, 16)
            d1 = uc.mem_read(ecx + 0x10, 16)
            d2 = uc.mem_read(ecx + 0x20, 16)
            d3 = uc.mem_read(ecx + 0x30, 16)
        except Exception as e:
            events.append(f"  [call #{armed['n']}] ECX=0x{ecx:x} READ FAIL: {e}")
            return
        events.append(f"  [call #{armed['n']}] FUN_00937230 ECX(grapher)=0x{ecx:x} ret->0x{ret:x}")
        events.append(f"      Xmin +0x00: {fmt_dec(d0)}")
        events.append(f"      Xmax +0x10: {fmt_dec(d1)}")
        events.append(f"      Ymin +0x20: {fmt_dec(d2)}")
        events.append(f"      Ymax +0x30: {fmt_dec(d3)}")

    RET_VERDICT = {0x437: "X: Xmin<Xmax FAIL", 0x438: "X: 2nd-check FAIL",
                   0x439: "Y: Ymin<Ymax FAIL", 0x43a: "Y: 2nd-check FAIL"}

    def on_ret(uc, address, size, ud):
        if not armed["on"]:
            return
        eax = uc.reg_read(UC_X86_REG_EAX)
        if eax == 0:
            events.append(f"      => returned EAX=0x0  OK (range valid -> should draw)")
        else:
            events.append(f"      => returned EAX=0x{eax:x}  FAIL: {RET_VERDICT.get(eax,'?')} -> busy curtain, NO draw")

    uc.hook_add(UC_HOOK_CODE, on_entry, begin=FN_RANGECHECK, end=FN_RANGECHECK + 1)
    for ret_va in (0x937253, 0x937266, 0x93728b, 0x93729e, 0x9372a5):
        uc.hook_add(UC_HOOK_CODE, on_ret, begin=ret_va, end=ret_va + 1)

    for name, kc in [("symb", 6), ("SIN", 21), ("X", 19), ("ENTER", 50)]:
        m3.inject_key(uc, shim, kc)

    print("[setup done] injecting PLOT, watching FUN_00937230 range validator...")
    payload = shim.malloc(16)
    uc.mem_write(payload, b"\x01" + b"\x00" * 3 + bytes([7]) + b"\x00" * 11)
    queue = struct.unpack("<I", uc.mem_read(m3.ADDR_EVENT_QUEUE, 4))[0]
    m3.call_emu(uc, m3.FN_ENQUEUE_EVENT, ecx=queue, stack_args=(0, payload))
    m3.call_emu(uc, m3.FN_PRESS_KEY, stack_args=(7,))
    armed["on"] = True
    drain_to_sentinel(uc)
    armed["on"] = False

    print(f"\n==== FUN_00937230 (plot-range validator) fired {armed['n']} time(s) ====")
    for line in events:
        print(line)
    if armed["n"] == 0:
        print("  *** never called -- hypothesis path not reached; rethink ***")


if __name__ == "__main__":
    main()
