"""
Settle "infinite loop vs just-over-the-10M-cap" for the plot tick.

Replicate inject_key(PLOT) but for the final drain/tick, resume emulation to the
SENTINEL (loop emu_start from the stopped EIP) with a large instruction budget,
instead of one bounded 10M shot. If it reaches the sentinel and draws pixels ->
it was only the cap (fix = resume-to-sentinel in call_emu). If it never reaches
the sentinel within the budget -> genuine non-terminating loop.
"""
from __future__ import annotations
import os, sys, struct
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import load, m3_one_plus_one as m3
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32
from unicorn.x86_const import UC_X86_REG_ESP, UC_X86_REG_ECX, UC_X86_REG_EIP

BUDGET = 300_000_000   # total instruction budget for the plot tick
SHOT = 20_000_000      # per emu_start chunk


def call_to_sentinel(uc, fn_va, ecx=0, stack_args=()):
    """Like m3.call_emu but resumes to the sentinel across multiple shots."""
    esp = uc.reg_read(UC_X86_REG_ESP)
    for a in reversed(stack_args):
        esp -= 4
        uc.mem_write(esp, struct.pack("<I", a & 0xFFFFFFFF))
    esp -= 4
    uc.mem_write(esp, struct.pack("<I", m3.SENTINEL_HOST_RET))
    uc.reg_write(UC_X86_REG_ESP, esp)
    uc.reg_write(UC_X86_REG_ECX, ecx & 0xFFFFFFFF)

    spent = 0
    eip = fn_va
    while spent < BUDGET:
        uc.emu_start(eip, 0, count=SHOT)
        eip = uc.reg_read(UC_X86_REG_EIP)
        spent += SHOT
        if eip == m3.SENTINEL_HOST_RET:
            print(f"  [reached sentinel after ~{spent:,} insns]")
            return uc.reg_read(0)  # EAX-ish; value unused
        print(f"  [shot done, spent ~{spent:,}, eip=0x{eip:x}] still running...")
    print(f"  [BUDGET {BUDGET:,} EXHAUSTED, eip=0x{eip:x}] -> non-terminating")
    return None


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
    print("  draining queue (to sentinel)...")
    call_to_sentinel(uc, m3.FN_DRAIN_QUEUE, ecx=queue, stack_args=(arg,))
    print("  ticking (to sentinel)...")
    call_to_sentinel(uc, m3.FN_TICK, ecx=state, stack_args=(0,))


def main():
    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    m3.install_sentinel_halt(uc)
    shim, img = m3.boot(uc)
    for name, kc in [("symb", 6), ("SIN", 21), ("X", 19), ("ENTER", 50)]:
        m3.inject_key(uc, shim, kc)

    print("\n=== PLOT key, uncapped drain/tick ===")
    payload = shim.malloc(16)
    uc.mem_write(payload, b"\x01" + b"\x00" * 3 + bytes([7]) + b"\x00" * 11)
    queue = struct.unpack("<I", uc.mem_read(m3.ADDR_EVENT_QUEUE, 4))[0]
    m3.call_emu(uc, m3.FN_ENQUEUE_EVENT, ecx=queue, stack_args=(0, payload))
    m3.call_emu(uc, m3.FN_PRESS_KEY, stack_args=(7,))
    drain_to_sentinel(uc)

    def snap(tag):
        g = m3.decode_to_grayscale(m3.read_framebuffer(uc))
        nz = sum(1 for p in g if p)
        from PIL import Image
        out = os.path.join(HERE, "frames_sin", f"plot_{tag}.png")
        Image.frombytes("L", (256, 127), bytes(min(255, p * 85) for p in g)).resize((512, 254)).save(out)
        print(f"  [{tag}] nonzero={nz}  ({out})")
        return nz

    snap("uncapped")
    # Deferred-work test: pump uncapped tick cycles (drive the idle worker too).
    bridge = struct.unpack("<I", uc.mem_read(m3.ADDR_HOST_BRIDGE, 4))[0]
    idle_cb = struct.unpack("<I", uc.mem_read(bridge + 0xba4, 4))[0]
    print(f"\nhost_bridge[+0xba4] idle worker = 0x{idle_cb:x}")
    for i in range(40):
        if idle_cb:
            try:
                call_to_sentinel(uc, idle_cb, stack_args=(0,))
            except Exception as e:
                print(f"  idle_cb shot {i} err: {e}")
        drain_to_sentinel(uc)
        if (i + 1) % 10 == 0:
            snap(f"pump{i+1}")


if __name__ == "__main__":
    main()
