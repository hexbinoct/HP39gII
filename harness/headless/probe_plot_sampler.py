"""
#11: full draw path runs incl. renderer main-paint FUN_0093ede0 -> FUN_0093e730.
FUN_0093e730 @0x93e78d does `CALL EDX` where EDX = [[ESI+0x5c]]+0x64 = the curve
SAMPLER/DRAWER (vtable slot 100 on the function-source). Args:
  ESP+0x24 = out rect1, [host_bridge+0x5d0], EDI=gfxctx(host_bridge+0x5d8), EBP=out rect2.
This is where per-sample eval + line-draw into the gfx context happens. If the gfx
context (or its clip) has zero width/height the sampler emits no pixels -> blank curve.

Dump at 0x93e78d (pre-sampler): the sampler fn addr, gfxctx bytes, [host_bridge+0x5d0],
the func-source header; at 0x93e792 (post-sampler): the returned rect.
"""
from __future__ import annotations
import os, sys, struct
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import load, m3_one_plus_one as m3
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE
from unicorn.x86_const import (UC_X86_REG_ESP, UC_X86_REG_ECX, UC_X86_REG_EIP,
                               UC_X86_REG_EAX, UC_X86_REG_EDX, UC_X86_REG_EDI,
                               UC_X86_REG_ESI, UC_X86_REG_EBP)

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


def hexd(uc, addr, n):
    try:
        return uc.mem_read(addr, n).hex()
    except Exception as e:
        return f"<read fail {e}>"


def main():
    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    m3.install_sentinel_halt(uc)
    shim, img = m3.boot(uc)
    armed = {"on": False, "n": 0}
    bridge = struct.unpack("<I", uc.mem_read(m3.ADDR_HOST_BRIDGE, 4))[0]
    pend = {"out1": 0, "out2": 0}

    def h_pre(uc, a, s, ud):
        if not armed["on"]:
            return
        armed["n"] += 1
        edx = uc.reg_read(UC_X86_REG_EDX)   # sampler fn
        edi = uc.reg_read(UC_X86_REG_EDI)   # gfxctx = host_bridge+0x5d8
        esi = uc.reg_read(UC_X86_REG_ESI)
        esp = uc.reg_read(UC_X86_REG_ESP)
        d0 = struct.unpack("<I", uc.mem_read(bridge + 0x5d0, 4))[0]
        fsrc = struct.unpack("<I", uc.mem_read(esi + 0x5c, 4))[0]
        pend["out1"] = esp + 0x24 - 4   # account: CALL hasn't pushed yet at 0x93e78d? see note
        pend["out2"] = uc.reg_read(UC_X86_REG_EBP)
        log.append(f"[sampler call #{armed['n']}] fn=0x{edx:x}  gfxctx(=hb+0x5d8)=0x{edi:x}  "
                   f"hb+0x5d0=0x{d0:x}  func_src=0x{fsrc:x}")
        log.append(f"    gfxctx[0x00..0x40]: {hexd(uc, edi, 0x40)}")
        log.append(f"    gfxctx[0x40..0x80]: {hexd(uc, edi + 0x40, 0x40)}")
        log.append(f"    func_src[0x00..0x20]: {hexd(uc, fsrc, 0x20)}")
        u20 = struct.unpack("<H", uc.mem_read(fsrc + 0x20, 2))[0]
        branch = "IF (copy real rect)" if (d0 & 0xffff) < u20 else "ELSE (DAT_00b88a40 EMPTY/default rect) <-- !!!"
        log.append(f"    *(ushort*)(func_src+0x20)=0x{u20:04x}  param_3=0x{d0:x}  =>  {branch}")
        log.append(f"    DAT_00b88a40 (default rect) [0..0x20]: {hexd(uc, 0xb88a40, 0x20)}")

    def h_post(uc, a, s, ud):
        if not armed["on"]:
            return
        eax = uc.reg_read(UC_X86_REG_EAX)   # sampler return (rect ptr)
        log.append(f"    -> sampler returned EAX=0x{eax:x}  ret[0x00..0x20]: {hexd(uc, eax, 0x20)}")
        log.append(f"    out2 rect (EBP) [0..0x20]: {hexd(uc, pend['out2'], 0x20)}")

    uc.hook_add(UC_HOOK_CODE, h_pre, begin=0x93e78d, end=0x93e78e)
    uc.hook_add(UC_HOOK_CODE, h_post, begin=0x93e78f, end=0x93e790)

    for name, kc in [("symb", 6), ("SIN", 21), ("X", 19), ("ENTER", 50)]:
        m3.inject_key(uc, shim, kc)

    print("[setup done] injecting PLOT, tracing curve sampler...")
    payload = shim.malloc(16)
    uc.mem_write(payload, b"\x01" + b"\x00" * 3 + bytes([7]) + b"\x00" * 11)
    queue = struct.unpack("<I", uc.mem_read(m3.ADDR_EVENT_QUEUE, 4))[0]
    m3.call_emu(uc, m3.FN_ENQUEUE_EVENT, ecx=queue, stack_args=(0, payload))
    m3.call_emu(uc, m3.FN_PRESS_KEY, stack_args=(7,))
    armed["on"] = True
    drain_to_sentinel(uc)
    armed["on"] = False

    print(f"\n==== curve sampler (FUN_0093e730 slot-100) fired {armed['n']} time(s) ====")
    for line in log:
        print(line)
    if armed["n"] == 0:
        print("  *** sampler never called ***")


if __name__ == "__main__":
    main()
