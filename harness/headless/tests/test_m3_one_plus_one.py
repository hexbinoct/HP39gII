"""
M3 end-to-end test: boot the calc headless, inject 1+1=ENTER, dump 5 frames,
assert all are distinct (calc computed something at each step).

Stronger assertions on specific MD5s would require gold values from the
native-harness session, which weren't recorded. So we settle for "all
distinct + final frame has more nonzero bytes than the lead-up" — that's
the visual signature of the "2" being drawn on ENTER.
"""
from __future__ import annotations

import hashlib
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

import m3_one_plus_one as m3  # noqa: E402
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32


def test_one_plus_one_renders_five_distinct_frames():
    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    m3.install_sentinel_halt(uc)
    shim, _img = m3.boot(uc)

    md5s = []
    nonzero = []

    def snapshot():
        fb = m3.read_framebuffer(uc)
        md5s.append(hashlib.md5(fb).hexdigest())
        nonzero.append(sum(1 for b in fb if b != 0))

    snapshot()  # 00: boot
    for label, keycode in m3.KEY_SEQUENCE:
        m3.inject_key(uc, shim, keycode)
        snapshot()

    # 5 frames total
    assert len(md5s) == 5

    # All MD5s distinct
    assert len(set(md5s)) == 5, f"frames are not all distinct: {md5s}"

    # Boot frame is blank (0 nonzero); every subsequent frame has content.
    assert nonzero[0] == 0, f"boot frame is not blank: {nonzero[0]} nonzero bytes"
    for i, n in enumerate(nonzero[1:], start=1):
        assert n > 2000, f"frame {i} has only {n} nonzero bytes (calc didn't render)"

    # ENTER frame should have MORE nonzero bytes than the last digit press, because
    # the result "2" gets drawn on the right.
    assert nonzero[4] > nonzero[3], \
        f"ENTER frame ({nonzero[4]} nonzero) should exceed last-digit frame ({nonzero[3]})"

    print("[OK] M3 1+1=ENTER produced 5 distinct frames:")
    for label, m, n in zip(["boot"] + [k[0] for k in m3.KEY_SEQUENCE], md5s, nonzero):
        print(f"  {label:>6} : {m}  ({n} nonzero)")


if __name__ == "__main__":
    test_one_plus_one_renders_five_distinct_frames()
