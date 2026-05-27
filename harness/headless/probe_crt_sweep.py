"""
probe_crt_sweep.py — investigate the _initterm gap for CAS commands (ifactor).

Hypothesis (see memory project-plot-curve-not-drawn #12): our boot enters at the
calc worker thread and skips mainCRTStartup's _initterm walk of the C++ static-
init table (.CRT$XC*). The plot fix runs 4 hand-picked inits; the giac CAS
command registry is populated by MANY more of those same initializers, left
empty -> ifactor(24) etc. return unevaluated (symbolic echo).

This probe:
  1. Boots to the main loop (m3 boot already runs the 4 plot inits).
  2. Locates the .CRT$XC initializer table in .rdata (contiguous array of
     pointers into the init-thunk range [0xa2c000, 0xa2cc00)).
  3. Snapshots the giac 'ifactor' registration object at 0xddc8c0 and the 4 plot
     scale constants.
  4. Runs EVERY init thunk, fault-guarded (catch UcError, restore ESP, skip).
  5. Re-reads those globals to see what the sweep populated.

No keystrokes — this just measures whether the registration globals change.
"""
from __future__ import annotations

import os, struct, sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import load
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UcError
from unicorn.x86_const import UC_X86_REG_ESP, UC_X86_REG_EIP

import m3_one_plus_one as m3

THUNK_LO, THUNK_HI = 0x00A2C000, 0x00A2CC00   # init-thunk range (tail of .text)
RDATA_LO, RDATA_HI = 0x00A2D000, 0x00A2E000   # search window for the .CRT table

# giac 'ifactor' registration object (.data) — name ptr at +0xc -> "ifactor".
IFACTOR_OBJ = 0x00DDC8C0
# 4 plot-transform scale constants the plot fix sets to 10.5.
PLOT_CONSTS = (0x00DFE978, 0x00DFE988, 0x00DFE998, 0x00DFE9A8)


def rd(uc, va, n):
    return bytes(uc.mem_read(va, n))


def find_crt_table(uc):
    """Return the sorted list of distinct init-thunk addresses found as a
    contiguous-ish pointer array in the .rdata search window."""
    thunks = []
    for va in range(RDATA_LO, RDATA_HI, 4):
        v = struct.unpack("<I", rd(uc, va, 4))[0]
        if THUNK_LO <= v < THUNK_HI:
            thunks.append((va, v))
    return thunks


def main():
    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    m3.install_sentinel_halt(uc)
    print("[boot] booting to main loop (runs the 4 plot inits)...")
    shim, img = m3.boot(uc)
    print("[boot] OK")

    # snapshot BEFORE the sweep
    before_ifactor = rd(uc, IFACTOR_OBJ, 16)
    before_plot = [struct.unpack("<d", rd(uc, a, 8))[0] for a in PLOT_CONSTS]
    print(f"[before] ifactor obj @0x{IFACTOR_OBJ:x}: {before_ifactor.hex()}")
    print(f"[before] plot consts: {before_plot}")

    table = find_crt_table(uc)
    print(f"[crt] found {len(table)} init-thunk pointers in {RDATA_LO:#x}..{RDATA_HI:#x}")
    if table:
        print(f"[crt] table span: {table[0][0]:#x}..{table[-1][0]:#x}")

    safe_esp = uc.reg_read(UC_X86_REG_ESP)
    ran = skipped = 0
    skipped_addrs = []
    for tbl_va, thunk in table:
        uc.reg_write(UC_X86_REG_ESP, safe_esp)  # avoid cumulative ESP drift
        try:
            m3.call_emu(uc, thunk)
            ran += 1
        except (UcError, RuntimeError) as e:
            skipped += 1
            skipped_addrs.append((thunk, str(e)[:40]))

    print(f"[sweep] ran={ran} skipped={skipped}")
    for a, e in skipped_addrs[:30]:
        print(f"   skip 0x{a:x}: {e}")

    after_ifactor = rd(uc, IFACTOR_OBJ, 16)
    after_plot = [struct.unpack("<d", rd(uc, a, 8))[0] for a in PLOT_CONSTS]
    print(f"[after]  ifactor obj @0x{IFACTOR_OBJ:x}: {after_ifactor.hex()}")
    print(f"[after]  plot consts: {after_plot}")
    print(f"[diff]   ifactor obj changed: {before_ifactor != after_ifactor}")
    print(f"[diff]   plot consts intact:  {before_plot == after_plot}")


if __name__ == "__main__":
    main()
