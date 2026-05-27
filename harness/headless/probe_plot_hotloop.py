"""
Find the runaway loop empirically. Our Plot keypress drives FN_TICK into a
non-terminating loop (28,109 __allmul, hits the 10M-insn cap at EIP=0x495454)
while the real exe finishes in ~85 muls. Instead of guessing which grapher
callee loops, profile basic-block frequency during the plot keypress and print
the hottest blocks — the loop body will dominate, pinpointing the function to
decompile and diff.

Block hooks fire per basic block (~1/5th of instrs), so ~2M Python callbacks
under the 10M cap — slow but bounded (~1-2 min).
"""
from __future__ import annotations
import os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import load, m3_one_plus_one as m3
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_BLOCK

IMG_LO, IMG_HI = 0x400000, 0x400000 + 0xc00000

block_hits: dict[int, int] = {}
profiling = False


def main():
    global profiling
    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    m3.install_sentinel_halt(uc)
    shim, img = m3.boot(uc)

    def on_block(uc, address, size, ud):
        if profiling and IMG_LO <= address < IMG_HI:
            block_hits[address] = block_hits.get(address, 0) + 1

    uc.hook_add(UC_HOOK_BLOCK, on_block)

    for name, kc in [("symb", 6), ("SIN", 21), ("X", 19), ("ENTER", 50)]:
        m3.inject_key(uc, shim, kc)
    print("[setup done] injecting PLOT with block profiler armed...")

    profiling = True
    try:
        m3.inject_key(uc, shim, 7)
        print("  (plot completed without cap error?!)")
    except RuntimeError as e:
        print(f"  plot truncated as expected: {e}")
    profiling = False

    top = sorted(block_hits.items(), key=lambda kv: kv[1], reverse=True)[:35]
    total = sum(block_hits.values())
    print(f"\n========== HOTTEST BASIC BLOCKS during PLOT (total block hits={total}, distinct={len(block_hits)}) ==========")
    for addr, n in top:
        print(f"  {n:>9}  0x{addr:06x}")
    print("=====================================================================")


if __name__ == "__main__":
    main()
