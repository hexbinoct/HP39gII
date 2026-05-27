"""
Diff our headless Plot against the real exe's Frida trace (2026-05-27 finding):
the WORKING plot is ONE synchronous call to FUN_00444a00 reached via the key
handler dispatch  0x412a47 -> 0x411b06 -> 0x40c74d -> FUN_00444a00, and the
per-sample evaluator (~85 calls) is 0x973850. The timer FUN_004157e0 is NEVER
called.

This probe defines F1(X)=SIN(X), then injects Plot with address hooks armed on
the dispatch chain + grapher + evaluator, to answer:
  (a) does our FN_DRAIN_QUEUE on the Plot key reach FUN_00444a00 at all?
  (b) does the dispatch chain (0x412a47/0x411b06/0x40c74d) execute like the exe?
  (c) does the evaluator 0x973850 run ~85x (eval succeeds) or 0/few (X unbound)?
  (d) does the drain call_emu complete (return to sentinel) or hit the 10M cap?
"""
from __future__ import annotations
import os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import load, m3_one_plus_one as m3
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE
from PIL import Image

OUT = os.path.join(HERE, "frames_sin")
os.makedirs(OUT, exist_ok=True)

# addr -> label, from the Frida trace of the real exe
WATCH = {
    0x412a47: "dispatch_412a47",
    0x411b06: "dispatch_411b06",
    0x40c74d: "dispatch_40c74d (direct caller of grapher)",
    0x444a00: "FUN_00444a00 GRAPHER",
    0x973850: "eval? 0x973850 (85x on real exe)",
    0x4157e0: "FUN_004157e0 timer (should stay 0)",
}
counts = {a: 0 for a in WATCH}


def arm(uc):
    def mk(addr):
        def _h(uc, address, size, ud):
            counts[addr] += 1
        return _h
    for a in WATCH:
        uc.hook_add(UC_HOOK_CODE, mk(a), begin=a, end=a + 1)


def save(uc, name):
    g = m3.decode_to_grayscale(m3.read_framebuffer(uc))
    img = Image.frombytes("L", (256, 127), bytes(min(255, p * 85) for p in g))
    img.resize((512, 254)).save(os.path.join(OUT, name + ".png"))
    nz = sum(1 for p in g if p)
    print(f"  saved {name}: nonzero={nz}")
    return nz


def main():
    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    m3.install_sentinel_halt(uc)
    shim, img = m3.boot(uc)
    arm(uc)
    seq = [("symb", 6), ("SIN", 21), ("X", 19), ("ENTER", 50)]
    for name, kc in seq:
        m3.inject_key(uc, shim, kc)
        save(uc, name)

    # Reset counters right before Plot so we isolate the plot keypress.
    for a in counts:
        counts[a] = 0
    print("\n--- injecting PLOT (key 7) ---")
    try:
        m3.inject_key(uc, shim, 7)
        plot_ok = True
    except RuntimeError as e:
        plot_ok = False
        print(f"  !! inject_key(plot) raised: {e}")
    nz = save(uc, "plot")

    print("\n========== HEADLESS PLOT HOOK COUNTS (vs real exe) ==========")
    for a, label in WATCH.items():
        print(f"  {counts[a]:>8}  0x{a:06x}  {label}")
    print(f"  plot_completed_without_cap_error = {plot_ok}")
    print(f"  framebuffer nonzero pixels after plot = {nz}")
    print("=============================================================")


if __name__ == "__main__":
    main()
