"""
#18: find the C++ static-init table (the pointer array containing 0xa2d6f4->FUN_00a2c190
and 0xa2d6f8->FUN_00a2c1d0) and run ALL of it during boot, then verify both plot axes
get valid transforms. Dump the table region, identify the contiguous run of in-image
code pointers (bounded by nulls), call each, then check the transform globals + plot
screen coords (both sx and sy should be non-zero / mid-screen).
"""
from __future__ import annotations
import os, sys, struct
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import load, m3_one_plus_one as m3
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE
from unicorn.x86_const import UC_X86_REG_EAX, UC_X86_REG_EBX

IMG_LO, IMG_HI = 0x401000, 0xb00000   # code range
SCAN_LO, SCAN_HI = 0xa2d400, 0xa2d800


def dtag(b):
    t = b[3]
    return {0x00: "UNDEF", 0x01: "+", 0xff: "-"}.get(t, f"0x{t:02x}")


def main():
    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    m3.install_sentinel_halt(uc)
    shim, img = m3.boot(uc)

    # Scan the .rdata region for the contiguous block of code pointers that includes
    # 0xa2d6f4 / 0xa2d6f8 (the known C++ init entries).
    ptrs = []
    for a in range(SCAN_LO, SCAN_HI, 4):
        v = struct.unpack("<I", uc.mem_read(a, 4))[0]
        ptrs.append((a, v))
    # find the run containing 0xa2d6f4
    def is_code(v):
        return IMG_LO <= v < IMG_HI
    # collect maximal contiguous code-pointer runs
    runs, cur = [], []
    for a, v in ptrs:
        if is_code(v):
            cur.append((a, v))
        else:
            if cur:
                runs.append(cur); cur = []
    if cur:
        runs.append(cur)
    target = next((r for r in runs if any(a in (0xa2d6f4, 0xa2d6f8) for a, _ in r)), None)
    print("==== candidate init table runs (addr range -> count) ====")
    for r in runs:
        mark = "  <-- contains our 2 inits" if r is target else ""
        print(f"  0x{r[0][0]:x}..0x{r[-1][0]+4:x}  ({len(r)} entries){mark}")

    if not target:
        print("  *** could not locate the init run; aborting ***")
        return
    print(f"\n[run] executing {len(target)} static initializers from "
          f"0x{target[0][0]:x}..0x{target[-1][0]+4:x}")
    for a, fn in target:
        try:
            m3.call_emu(uc, fn)
        except Exception as e:
            print(f"  init @0x{a:x} -> fn 0x{fn:x} FAILED: {e}")
    d978 = bytes(uc.mem_read(0xdfe978, 16)); d988 = bytes(uc.mem_read(0xdfe988, 16))
    print(f"  DAT_00dfe978 = {dtag(d978)} {d978.hex()}")
    print(f"  DAT_00dfe988 = {dtag(d988)} {d988.hex()}")

    samples = []
    armed = {"on": False}

    def h_screen(uc, a, s, ud):
        if armed["on"] and len(samples) < 20:
            samples.append((uc.reg_read(UC_X86_REG_EAX) & 0xffff, uc.reg_read(UC_X86_REG_EBX) & 0xffff))
    uc.hook_add(UC_HOOK_CODE, h_screen, begin=0x959dc9, end=0x959dca)

    for name, kc in [("symb", 6), ("SIN", 21), ("X", 19), ("ENTER", 50)]:
        m3.inject_key(uc, shim, kc)
    print("\n[setup done] injecting PLOT with full init table applied...")
    payload = shim.malloc(16)
    uc.mem_write(payload, b"\x01" + b"\x00" * 3 + bytes([7]) + b"\x00" * 11)
    queue = struct.unpack("<I", uc.mem_read(m3.ADDR_EVENT_QUEUE, 4))[0]
    m3.call_emu(uc, m3.FN_ENQUEUE_EVENT, ecx=queue, stack_args=(0, payload))
    m3.call_emu(uc, m3.FN_PRESS_KEY, stack_args=(7,))
    armed["on"] = True
    # drain + tick
    bridge = struct.unpack("<I", uc.mem_read(m3.ADDR_HOST_BRIDGE, 4))[0]
    arg = struct.unpack("<I", uc.mem_read(bridge + 0x20, 4))[0]
    state = struct.unpack("<I", uc.mem_read(m3.ADDR_STATE, 4))[0]
    f2c = struct.unpack("<I", uc.mem_read(state + 0x2c, 4))[0]
    uc.mem_write(state + 0x2c, struct.pack("<I", f2c & 0xfffffbff))
    f90 = struct.unpack("<I", uc.mem_read(state + 0x90, 4))[0]
    uc.mem_write(state + 0x90, struct.pack("<I", f90 | 0x10))
    m3.call_emu(uc, m3.FN_DRAIN_QUEUE, ecx=struct.unpack("<I", uc.mem_read(m3.ADDR_EVENT_QUEUE, 4))[0], stack_args=(arg,))
    m3.call_emu(uc, m3.FN_TICK, ecx=state, stack_args=(0,))
    armed["on"] = False

    print(f"\n==== plot screen coords (sx,sy) after full init ====")
    print("  " + "  ".join(f"({x},{y})" for x, y in samples))
    ys = set(y for _, y in samples)
    print(f"  distinct screen-Y values: {sorted(ys)}")
    print("  " + ("*** Y now varies -> SINE CURVE SHAPE ***" if len(ys) > 1 else "Y still constant — investigate further"))


if __name__ == "__main__":
    main()
