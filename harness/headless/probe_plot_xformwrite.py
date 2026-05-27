"""
#15 fix-hunt: real exe has valid scale/origin in the transform ctx; ours are zero, but
the clamp (ctx+0x40) matches -> ctx partially built, only scale(+0x10)/origin(+0x00)
missing. Watch writes to the two transform ctxs (grapher+0x208 = X ctx, grapher+0x250 =
Y ctx; grapher base has been 0x10020d00) across the WHOLE plot. For each write to the
origin/scale fields, log address + value + EIP (the writer). If they're NEVER written ->
setup step skipped; if written with zero -> bad input. Either way we learn the writer.
"""
from __future__ import annotations
import os, sys, struct
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import load, m3_one_plus_one as m3
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_MEM_WRITE
from unicorn.x86_const import UC_X86_REG_ESP, UC_X86_REG_ECX, UC_X86_REG_EIP

BUDGET, SHOT = 300_000_000, 20_000_000
# transform ctxs (grapher 0x10020d00 + 0x208 / +0x250); origin=+0x00, scale=+0x10
WATCH_LO, WATCH_HI = 0x10020f00, 0x10020f70
writes = []


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

    def on_write(uc, access, address, size, value, ud):
        if not armed["on"]:
            return
        if WATCH_LO <= address < WATCH_HI:
            eip = uc.reg_read(UC_X86_REG_EIP)
            off = address - 0x10020d00
            writes.append((address, off, size, value & ((1 << (size * 8)) - 1), eip))
    uc.hook_add(UC_HOOK_MEM_WRITE, on_write)

    for name, kc in [("symb", 6), ("SIN", 21), ("X", 19), ("ENTER", 50)]:
        m3.inject_key(uc, shim, kc)

    print("[setup done] injecting PLOT, watching transform-ctx writes...")
    payload = shim.malloc(16)
    uc.mem_write(payload, b"\x01" + b"\x00" * 3 + bytes([7]) + b"\x00" * 11)
    queue = struct.unpack("<I", uc.mem_read(m3.ADDR_EVENT_QUEUE, 4))[0]
    m3.call_emu(uc, m3.FN_ENQUEUE_EVENT, ecx=queue, stack_args=(0, payload))
    armed["on"] = True
    m3.call_emu(uc, m3.FN_PRESS_KEY, stack_args=(7,))
    drain_to_sentinel(uc)
    armed["on"] = False

    print(f"\n==== writes into transform ctxs [0x{WATCH_LO:x}..0x{WATCH_HI:x}) : {len(writes)} ====")
    if not writes:
        print("  *** NO writes -> the scale/origin SETUP STEP IS SKIPPED in our boot ***")
    for addr, off, size, val, eip in writes[:60]:
        which = ("X-ctx" if 0x208 <= off < 0x248 else "Y-ctx" if 0x250 <= off < 0x290 else "?")
        field = {0x208: "X.origin", 0x218: "X.scale", 0x248: "X.clamp",
                 0x250: "Y.origin", 0x260: "Y.scale", 0x290: "Y.clamp"}.get(off, "")
        print(f"  [{which}] 0x{addr:x} (graph+0x{off:x} {field}) sz{size} = 0x{val:0{size*2}x}  by EIP=0x{eip:x}")


if __name__ == "__main__":
    main()
