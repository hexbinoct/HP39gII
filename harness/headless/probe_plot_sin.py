"""
Repro: define F1(X)=SIN(X) in the Function aplet's Symb view, then Plot.
Windows plots the sine instantly; our emulator shows the grid but no curve and
"X: undefined / F1(X): undefined". Capture the Symb and Plot frames so we can
see whether the function was entered and whether the plot evaluates it.

Keys (Small 39gII.skin codes): Symb=6, SIN=21, X,T,th,N=19, ENTER=50, Plot=7.
"""
from __future__ import annotations
import os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import load, m3_one_plus_one as m3
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32
from PIL import Image

OUT = os.path.join(HERE, "frames_sin")
os.makedirs(OUT, exist_ok=True)


def save(uc, name):
    g = m3.decode_to_grayscale(m3.read_framebuffer(uc))
    img = Image.frombytes("L", (256, 127), bytes(min(255, p * 85) for p in g))
    img.resize((512, 254)).save(os.path.join(OUT, name + ".png"))
    nz = sum(1 for p in g if p)
    print(f"  saved {name}: nonzero={nz}")


def main():
    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    m3.install_sentinel_halt(uc)
    shim, img = m3.boot(uc)
    seq = [("symb", 6), ("SIN", 21), ("X", 19), ("ENTER", 50), ("plot", 7)]
    for name, kc in seq:
        m3.inject_key(uc, shim, kc)
        save(uc, name)


if __name__ == "__main__":
    main()
