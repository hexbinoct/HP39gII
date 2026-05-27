"""
Find the NULL-call site reached when evaluating ifactor(24) on ENTER.
Drive to ENTER, hook every instruction; when control reaches a near-null EIP,
capture the return address on the stack (= the call site), registers, and the
recent EIP trail. The call site reveals which (uninitialised) function pointer
is NULL.
"""
from __future__ import annotations
import os, sys, struct
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import m3_one_plus_one as m3
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE
from unicorn.x86_const import UC_X86_REG_ESP, UC_X86_REG_ECX, UC_X86_REG_EAX, UC_X86_REG_EDX
import load
import probe_ifactor_repro as R

trail = []
caught = {}


def main():
    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    m3.install_sentinel_halt(uc)
    shim, img = m3.boot(uc)
    m3.inject_key(uc, shim, 19)
    buf, owner = R.find_buf_owner(uc, shim)
    R.set_text(uc, buf, owner, "ifactor(24)")

    def code_h(uc, addr, size, ud):
        trail.append(addr)
        if len(trail) > 24:
            trail.pop(0)
    uc.hook_add(UC_HOOK_CODE, code_h)

    try:
        m3.inject_key(uc, shim, 50)   # ENTER
    except Exception as e:
        print("(stopped:", str(e)[:60], ")")

    esp = uc.reg_read(UC_X86_REG_ESP)
    ret = struct.unpack("<I", uc.mem_read(esp, 4))[0]
    print(f"  ESP=0x{esp:x}  [ESP](call site+)=0x{ret:x}")
    print(f"  ecx=0x{uc.reg_read(UC_X86_REG_ECX):x} eax=0x{uc.reg_read(UC_X86_REG_EAX):x} edx=0x{uc.reg_read(UC_X86_REG_EDX):x}")
    print(f"  last EIPs (call site = last): " + " ".join(f"0x{a:x}" for a in trail[-12:]))


if __name__ == "__main__":
    main()
