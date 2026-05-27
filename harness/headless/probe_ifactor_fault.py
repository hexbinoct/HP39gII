"""
Capture the EXACT unmapped address + faulting EIP when cold-calling giac
string-eval on an identifier ("ifactor(24)") vs a pure-number expr ("2+3").
The unmapped global read during identifier lexing is the prime suspect for the
skipped-static-init gap.
"""
from __future__ import annotations
import os, sys, struct
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import m3_one_plus_one as m3
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE, UC_HOOK_MEM_UNMAPPED, UcError
from unicorn.x86_const import UC_X86_REG_ESP, UC_X86_REG_EIP

GIAC_EVAL_STR = 0x005CF460
trace = []          # (eip, size) of executed insns, last few before fault
faults = []         # (access_addr, eip)


def main():
    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    m3.install_sentinel_halt(uc)
    shim, img = m3.boot(uc)

    last = []
    def code_h(uc, addr, size, ud):
        last.append(addr)
        if len(last) > 12:
            last.pop(0)
    uc.hook_add(UC_HOOK_CODE, code_h)

    def fault_h(uc, access, addr, size, value, ud):
        faults.append((addr, uc.reg_read(UC_X86_REG_EIP), list(last)))
        return False  # don't resolve -> abort (so we capture once)
    uc.hook_add(UC_HOOK_MEM_UNMAPPED, fault_h)

    for expr in ("ifactor(24)", "2+3"):
        faults.clear(); last.clear()
        buf = shim.malloc(len(expr) + 2)
        uc.mem_write(buf, expr.encode("latin-1") + b"\x00")
        res = shim.malloc(32)
        esp = uc.reg_read(UC_X86_REG_ESP)
        try:
            m3.call_emu(uc, GIAC_EVAL_STR, stack_args=(res, buf, 1))
        except (UcError, RuntimeError):
            pass
        uc.reg_write(UC_X86_REG_ESP, esp)
        print(f"\n=== {expr} ===")
        for addr, eip, lst in faults[:1]:
            print(f"  UNMAPPED access at 0x{addr:x}  faulting EIP=0x{eip:x}")
            print(f"  last insns: " + " ".join(f"0x{a:x}" for a in lst))


if __name__ == "__main__":
    main()
