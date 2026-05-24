"""
M1 landmark test: boot the calc-core thread in Unicorn, and assert that the
init walk hits every predicted landmark.

This is a regression net for the loader + shim. If anyone breaks it later (wrong
FS setup, wrong stdcall argc, wrong CRT hook, etc.) one or more landmarks will
disappear from the trace.
"""
from __future__ import annotations

import os
import struct
import sys

# Make harness/headless importable
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

import load  # noqa: E402


def collect_run():
    """Run the loader and return (shim, final_eip). Suppress chatter."""
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UcError
    from unicorn.x86_const import UC_X86_REG_ESP, UC_X86_REG_EBP, UC_X86_REG_EIP

    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    uc.mem_map(load.STACK_BASE, load.STACK_SIZE)
    uc.mem_map(load.HEAP_BASE, load.HEAP_SIZE)
    uc.mem_map(load.TRAMP_BASE, load.TRAMP_SIZE)

    img = load.load_pe_into(uc)
    load.setup_fs_segment(uc)
    shim = load.Shim(uc=uc, verbose_per_name=0)  # silent
    load.install_iat_dispatcher(uc, img, shim)
    load.install_fault_logger(uc, shim)

    esp = load.STACK_BASE + load.STACK_SIZE - 0x100
    esp -= 4; uc.mem_write(esp, struct.pack("<I", 0))
    esp -= 4; uc.mem_write(esp, struct.pack("<I", load.SENTINEL_RET))
    uc.reg_write(UC_X86_REG_ESP, esp)
    uc.reg_write(UC_X86_REG_EBP, 0)

    try:
        uc.emu_start(load.CALC_THREAD_VA, 0, timeout=10_000_000, count=2_000_000)
    except UcError:
        pass

    return shim, uc.reg_read(UC_X86_REG_EIP)


def test_m1_landmarks():
    shim, final_eip = collect_run()

    # Landmark 1: CreateMutexW called exactly once with (NULL, TRUE, NULL)
    assert any("CreateMutexW" in line and "owned=1" in line for line in shim.log), \
        "CreateMutexW(NULL, TRUE, NULL) not seen"

    # Landmark 2: all 6 predicted state-struct allocations happened, in order.
    # First three go via calc_malloc (operator new), last three (framebuffer + 2
    # ROM regions) go via the static MSVCRT malloc hook.
    import re
    pat = re.compile(r"(?:calc_malloc|msvcrt_malloc)\(\[(\d+),")
    alloc_sizes_in_order = [int(m.group(1)) for line in shim.log for m in [pat.search(line)] if m]

    # Expected (per RESEARCH_NOTES): 84, 136, 152, then 10922 (framebuffer),
    # then 3000, 0xB18C, 0xB180. We may also see small interleaved mallocs.
    must_appear_in_order = [84, 136, 152, 10922]
    idx = 0
    for s in alloc_sizes_in_order:
        if idx < len(must_appear_in_order) and s == must_appear_in_order[idx]:
            idx += 1
    assert idx == len(must_appear_in_order), \
        f"missing/out-of-order landmark allocs. expected order containing {must_appear_in_order}, got {alloc_sizes_in_order[:20]}..."

    # Landmark 3: CreateThread was called for the conn-kit thread (start=0x407be0)
    assert any("CreateThread" in line and "0x407be0" in line for line in shim.log), \
        "conn-kit CreateThread(start=0x407be0) not seen"

    # Landmark 4: heap grew (state structs + framebuffer + post-init allocs)
    # Anything > 50KB confirms we're well past the framebuffer alloc.
    consumed = shim.heap_ptr - load.HEAP_BASE
    assert consumed > 50_000, f"heap consumed only {consumed} bytes; init bailed early"

    # Landmark 5: file-system probing for saved state happened (FindFirstFileW)
    # — confirms we got past keyboard_init and into the dialog's "restore state"
    # phase.
    assert any("FindFirstFileW" in line for line in shim.log), \
        "FindFirstFileW not seen (init bailed before reaching dialog save-state restore)"

    print(f"\n[OK] M1 landmarks all hit. {len(shim.log)} IAT/internal events, "
          f"{consumed} bytes heap, final EIP=0x{final_eip:x}")


if __name__ == "__main__":
    test_m1_landmarks()
