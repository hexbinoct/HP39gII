"""
probe_ifactor_eval.py — reproduce ifactor(24) WITHOUT keystrokes by calling the
giac string-eval entry directly, and test whether the CRT static-init sweep
changes the outcome.

FUN_005cf460(result_gen*, char* expr, level) is giac's parse+eval-from-string:
  - FUN_00835280 = parser (string -> internal),  FUN_005ceb70 = eval,
  - context = PTR_DAT_00ddc730 (global),  result gen written at arg0.

Discriminator (no renderer needed):
  * a RECOGNISED command runs real work (ifactor factors 24 -> many insns,
    structured result gen);
  * an UNRECOGNISED name builds a tiny symbolic echo (few insns).
Compare ifactor(24) vs a control known good ("2+3") and a control known unknown
("qwzzz(24)"), both before and after sweeping the .CRT$XC init table.
"""
from __future__ import annotations
import os, sys, struct
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import m3_one_plus_one as m3
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE, UcError
from unicorn.x86_const import UC_X86_REG_ESP, UC_X86_REG_EIP

GIAC_EVAL_STR = 0x005CF460
THUNK_LO, THUNK_HI = 0x00A2C000, 0x00A2CC00
RDATA_LO, RDATA_HI = 0x00A2D000, 0x00A2E000

_count = {"n": 0}
def _counter(uc, addr, size, ud):
    _count["n"] += 1


def eval_str(uc, shim, expr: str):
    """Call giac string-eval on `expr`; return (insn_count, result16, ok)."""
    buf = shim.malloc(len(expr) + 2)
    uc.mem_write(buf, expr.encode("latin-1") + b"\x00")
    res = shim.malloc(32)              # result gen storage (zeroed by malloc)
    _count["n"] = 0
    safe_esp = uc.reg_read(UC_X86_REG_ESP)
    try:
        m3.call_emu(uc, GIAC_EVAL_STR, stack_args=(res, buf, 1))
        ok = True
    except (UcError, RuntimeError) as e:
        ok = f"FAULT: {str(e)[:50]}"
    uc.reg_write(UC_X86_REG_ESP, safe_esp)
    result16 = bytes(uc.mem_read(res, 16))
    return _count["n"], result16, ok


def find_crt_table(uc):
    out = []
    for va in range(RDATA_LO, RDATA_HI, 4):
        v = struct.unpack("<I", uc.mem_read(va, 4))[0]
        if THUNK_LO <= v < THUNK_HI:
            out.append(v)
    return out


def run_suite(uc, shim, tag):
    print(f"\n==== eval suite [{tag}] ====")
    for expr in ("2+3", "ifactor(24)", "qwzzz(24)"):
        n, r, ok = eval_str(uc, shim, expr)
        print(f"  {expr:14} insns={n:>9}  result={r.hex()}  ok={ok}")


def main():
    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    m3.install_sentinel_halt(uc)
    shim, img = m3.boot(uc)
    uc.hook_add(UC_HOOK_CODE, _counter)   # count every executed instruction
    print("[boot] OK; context PTR_DAT_00ddc730 =", hex(struct.unpack("<I", uc.mem_read(0x00DDC730, 4))[0]))

    run_suite(uc, shim, "before CRT sweep")

    table = find_crt_table(uc)
    safe = uc.reg_read(UC_X86_REG_ESP)
    ran = skipped = 0
    for thunk in table:
        uc.reg_write(UC_X86_REG_ESP, safe)
        try:
            m3.call_emu(uc, thunk); ran += 1
        except (UcError, RuntimeError):
            skipped += 1
    print(f"\n[sweep] ran={ran} skipped={skipped} of {len(table)} init thunks")

    run_suite(uc, shim, "after CRT sweep")


if __name__ == "__main__":
    main()
