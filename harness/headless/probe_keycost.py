"""
Measure instructions-per-call for a NORMAL key vs a PLOT key, to see whether the
resume-to-sentinel change made normal keys heavier (regression) or whether the
per-action latency is just inherent emulation cost. Counts in 1M-instruction shots
(cheap: no per-instruction Python callback) -> resolution ~1M.
Old cap was 10M; if a normal key's ticks finish well under 10M, resume-to-sentinel
did NOT change them.
"""
from __future__ import annotations
import os, sys, struct
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import load, m3_one_plus_one as m3
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32
from unicorn.x86_const import UC_X86_REG_ESP, UC_X86_REG_ECX, UC_X86_REG_EIP

SHOT = 1_000_000


def measure_call(uc, fn_va, ecx=0, stack_args=()):
    """Run one emulated call, returning (instr_estimate_millions, reached_sentinel)."""
    esp = uc.reg_read(UC_X86_REG_ESP)
    for a in reversed(stack_args):
        esp -= 4; uc.mem_write(esp, struct.pack("<I", a & 0xFFFFFFFF))
    esp -= 4; uc.mem_write(esp, struct.pack("<I", m3.SENTINEL_HOST_RET))
    uc.reg_write(UC_X86_REG_ESP, esp)
    uc.reg_write(UC_X86_REG_ECX, ecx & 0xFFFFFFFF)
    eip, shots = fn_va, 0
    while shots < 500:
        uc.emu_start(eip, 0, count=SHOT)
        eip = uc.reg_read(UC_X86_REG_EIP)
        shots += 1
        if eip == m3.SENTINEL_HOST_RET:
            return shots, True
    return shots, False


def drain_tick_cost(uc, label):
    queue = struct.unpack("<I", uc.mem_read(m3.ADDR_EVENT_QUEUE, 4))[0]
    bridge = struct.unpack("<I", uc.mem_read(m3.ADDR_HOST_BRIDGE, 4))[0]
    arg = struct.unpack("<I", uc.mem_read(bridge + 0x20, 4))[0]
    state = struct.unpack("<I", uc.mem_read(m3.ADDR_STATE, 4))[0]
    f2c = struct.unpack("<I", uc.mem_read(state + 0x2c, 4))[0]
    uc.mem_write(state + 0x2c, struct.pack("<I", f2c & 0xfffffbff))
    f90 = struct.unpack("<I", uc.mem_read(state + 0x90, 4))[0]
    if (f90 & 0x10) == 0:
        uc.mem_write(state + 0x90, struct.pack("<I", f90 | 0x10))
    d, ds = measure_call(uc, m3.FN_DRAIN_QUEUE, ecx=queue, stack_args=(arg,))
    t, ts = measure_call(uc, m3.FN_TICK, ecx=state, stack_args=(0,))
    print(f"  [{label}] DRAIN ~{d}M (sentinel={ds})  TICK ~{t}M (sentinel={ts})  "
          f"{'<= under old 10M cap' if t <= 10 else '*** EXCEEDS old 10M cap (was truncated before) ***'}")


def inject_measured(uc, shim, kc, label):
    payload = shim.malloc(16)
    uc.mem_write(payload, b"\x01" + b"\x00" * 3 + bytes([kc]) + b"\x00" * 11)
    queue = struct.unpack("<I", uc.mem_read(m3.ADDR_EVENT_QUEUE, 4))[0]
    m3.call_emu(uc, m3.FN_ENQUEUE_EVENT, ecx=queue, stack_args=(0, payload))
    m3.call_emu(uc, m3.FN_PRESS_KEY, stack_args=(kc,))
    drain_tick_cost(uc, label + " press")


def main():
    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    m3.install_sentinel_halt(uc)
    shim, img = m3.boot(uc)
    print("\n==== per-key tick cost (1M-insn resolution; old cap was 10M) ====")
    inject_measured(uc, shim, 42, "digit '1' (home)")
    inject_measured(uc, shim, 43, "digit '2' (home)")
    # now define + plot to measure the heavy plot tick
    for kc in (6, 21, 19, 50):   # symb, SIN, X, ENTER
        m3.inject_key(uc, shim, kc)
    inject_measured(uc, shim, 7, "PLOT")


if __name__ == "__main__":
    main()
