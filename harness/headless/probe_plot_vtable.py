"""
Decisive diff: the real exe's plot fires this ONE-SHOT grapher-vtable draw
sequence (from Frida plot_vtable.js, vtable @0xa8c1e4):
   [1]0x45c160(3x) [5]0x93fe60 [7]0x939160 [8]0x939290 [10]0x93ece0
   [11]0x939300 [12]0x939420 [25]0x939990(2x)
Hook the same addresses in our headless plot (UNCAPPED via resume-to-sentinel) and
see which our run fails to call. Methods the real exe calls but ours skips = the
missing curve-draw path.
"""
from __future__ import annotations
import os, sys, struct
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import load, m3_one_plus_one as m3
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE
from unicorn.x86_const import UC_X86_REG_ESP, UC_X86_REG_ECX, UC_X86_REG_EIP

REAL = {  # addr -> (vtable_idx, real_exe_count)
    0x45c160: (1, 3), 0x93fe60: (5, 1), 0x939160: (7, 1), 0x939290: (8, 1),
    0x93ece0: (10, 1), 0x939300: (11, 1), 0x939420: (12, 1), 0x939990: (25, 2),
}
counts = {a: 0 for a in REAL}

BUDGET = 300_000_000
SHOT = 20_000_000


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
    print(f"  [budget exhausted in {fn_va:#x}, eip=0x{eip:x}]")


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

    def mk(addr):
        def _h(uc, address, size, ud):
            counts[addr] += 1
        return _h
    for a in REAL:
        uc.hook_add(UC_HOOK_CODE, mk(a), begin=a, end=a + 1)

    for name, kc in [("symb", 6), ("SIN", 21), ("X", 19), ("ENTER", 50)]:
        m3.inject_key(uc, shim, kc)
    for a in counts:
        counts[a] = 0
    print("[setup done] injecting PLOT (uncapped, resume-to-sentinel)...")

    payload = shim.malloc(16)
    uc.mem_write(payload, b"\x01" + b"\x00" * 3 + bytes([7]) + b"\x00" * 11)
    queue = struct.unpack("<I", uc.mem_read(m3.ADDR_EVENT_QUEUE, 4))[0]
    m3.call_emu(uc, m3.FN_ENQUEUE_EVENT, ecx=queue, stack_args=(0, payload))
    m3.call_emu(uc, m3.FN_PRESS_KEY, stack_args=(7,))
    drain_to_sentinel(uc)

    print("\n==== GRAPHER VTABLE DRAW METHODS: real exe vs our headless ====")
    print(f"  {'addr':>10}  {'idx':>4}  {'real':>5}  {'ours':>5}   status")
    for a, (idx, real_n) in REAL.items():
        ours = counts[a]
        status = "OK" if ours > 0 else "*** MISSING (skipped draw) ***"
        print(f"  0x{a:08x}  [{idx:>2}]  {real_n:>5}  {ours:>5}   {status}")
    print("===============================================================")


if __name__ == "__main__":
    main()
