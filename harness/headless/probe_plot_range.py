"""
Test the zero-step hypothesis for the plot runaway. FUN_00443150 installs a
32-byte range block (Xmin/Xmax as two 16-byte BCD decimals) into the grapher
(per Ghidra: copies param[0..7] -> grapher+0x28..+0x44). If our fresh in-memory
FS left the plot window uninitialised (Xmin==Xmax, i.e. dx=0), the x-step loop
never terminates -> the runaway we measured.

Hook FUN_00443150 entry, dump ECX and the first stack arg + 0x60 bytes from each,
during the Plot keypress. Compare against a sane window (Function default is
~Xmin=-15.9, Xmax=16.1).
"""
from __future__ import annotations
import os, sys, struct
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import load, m3_one_plus_one as m3
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE
from unicorn.x86_const import UC_X86_REG_ECX, UC_X86_REG_ESP

FUN_00443150 = 0x443150
hits = []


def hexdump(uc, ptr, n=0x60):
    try:
        data = uc.mem_read(ptr, n)
    except Exception as e:
        return f"<unreadable {ptr:#x}: {e}>"
    out = []
    for i in range(0, n, 16):
        chunk = data[i:i+16]
        out.append(f"    +{i:02x}: " + " ".join(f"{b:02x}" for b in chunk))
    return "\n".join(out)


def main():
    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    m3.install_sentinel_halt(uc)
    shim, img = m3.boot(uc)

    def on_443150(uc, address, size, ud):
        ecx = uc.reg_read(UC_X86_REG_ECX)
        esp = uc.reg_read(UC_X86_REG_ESP)
        arg0 = struct.unpack("<I", uc.mem_read(esp + 4, 4))[0]
        hits.append((ecx, arg0))
    uc.hook_add(UC_HOOK_CODE, on_443150, begin=FUN_00443150, end=FUN_00443150 + 1)

    for name, kc in [("symb", 6), ("SIN", 21), ("X", 19), ("ENTER", 50)]:
        m3.inject_key(uc, shim, kc)
    print("[setup done] injecting PLOT...")
    try:
        m3.inject_key(uc, shim, 7)
    except RuntimeError as e:
        print(f"  plot truncated (expected): {e}")

    print(f"\nFUN_00443150 entered {len(hits)} time(s) during plot.")
    for i, (ecx, arg0) in enumerate(hits):
        print(f"\n--- call #{i}: ECX={ecx:#010x}  stackArg0={arg0:#010x} ---")
        print(f"  [ECX] (this/dest grapher):\n{hexdump(uc, ecx)}")
        print(f"  [stackArg0] (range source?):\n{hexdump(uc, arg0)}")


if __name__ == "__main__":
    main()
