"""
#14 ROOT: eval works (X sweeps, SIN(X) valid) but FUN_00959400 (decimal->screen-pixel)
returns 0 for every coord. FUN_00959400 does:
  FUN_004902f0(ctx, value, t);  FUN_00490a50(t, ctx+0x10, r, 0);
  if (r.type==0 || r.type==-2) return 0;   // UNDEFINED transform result
i.e. it multiplies/combines the value against the transform coefficient at ctx+0x10
(and uses ctx+0, clamp ctx+0x40). If ctx+0x10 (scale/offset) is UNDEFINED, all coords
collapse to 0. Dump the X-transform ctx and Y-transform ctx coefficient decimals.
"""
from __future__ import annotations
import os, sys, struct
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import load, m3_one_plus_one as m3
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE
from unicorn.x86_const import UC_X86_REG_ESP, UC_X86_REG_ECX, UC_X86_REG_EIP

BUDGET, SHOT = 300_000_000, 20_000_000
seen = []


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
    for fn in (0xa2c190, 0xa2c1d0):   # run the 2 plot-transform static initializers
        m3.call_emu(uc, fn)
    print("[fix] ran FUN_00a2c190/FUN_00a2c1d0 (set DAT_00dfe978/988 = 10.5)")
    armed = {"on": False}

    def h(uc, a, s, ud):
        if not armed["on"] or len(seen) >= 8:
            return
        ctx = uc.reg_read(UC_X86_REG_ECX)
        esp = uc.reg_read(UC_X86_REG_ESP)
        valp = struct.unpack("<I", uc.mem_read(esp + 4, 4))[0]
        try:
            c00 = bytes(uc.mem_read(ctx + 0x00, 16))
            c10 = bytes(uc.mem_read(ctx + 0x10, 16))
            c40 = struct.unpack("<I", uc.mem_read(ctx + 0x40, 4))[0]
            val = bytes(uc.mem_read(valp, 16))
        except Exception as e:
            seen.append(f"  ctx=0x{ctx:x} read fail {e}")
            return
        seen.append(
            f"  ctx=0x{ctx:x}\n"
            f"      ctx+0x00 (origin?):  {dtag(c00):<6} {c00.hex()}\n"
            f"      ctx+0x10 (scale?):   {dtag(c10):<6} {c10.hex()}\n"
            f"      ctx+0x40 (clamp max): {c40}\n"
            f"      value in:            {dtag(val):<6} {val.hex()}")

    uc.hook_add(UC_HOOK_CODE, h, begin=0x959400, end=0x959401)

    for name, kc in [("symb", 6), ("SIN", 21), ("X", 19), ("ENTER", 50)]:
        m3.inject_key(uc, shim, kc)

    print("[setup done] injecting PLOT, dumping screen-transform context...")
    payload = shim.malloc(16)
    uc.mem_write(payload, b"\x01" + b"\x00" * 3 + bytes([7]) + b"\x00" * 11)
    queue = struct.unpack("<I", uc.mem_read(m3.ADDR_EVENT_QUEUE, 4))[0]
    m3.call_emu(uc, m3.FN_ENQUEUE_EVENT, ecx=queue, stack_args=(0, payload))
    m3.call_emu(uc, m3.FN_PRESS_KEY, stack_args=(7,))
    armed["on"] = True
    drain_to_sentinel(uc)
    armed["on"] = False

    print(f"\n==== FUN_00959400 transform context (first {len(seen)} calls) ====")
    for s in seen:
        print(s)


if __name__ == "__main__":
    main()
