"""
M2 boot test: calc-core init runs to completion and reaches the main-loop entry
FUN_00401730 with no faults.
"""
from __future__ import annotations
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

import load  # noqa: E402


def test_m2_reaches_main_loop():
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UcError
    from unicorn.x86_const import UC_X86_REG_ESP, UC_X86_REG_EBP, UC_X86_REG_EIP

    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    uc.mem_map(load.STACK_BASE, load.STACK_SIZE)
    uc.mem_map(load.HEAP_BASE, load.HEAP_SIZE)
    uc.mem_map(load.TRAMP_BASE, load.TRAMP_SIZE)

    img = load.load_pe_into(uc)
    load.setup_fs_segment(uc)
    shim = load.Shim(uc=uc, verbose_per_name=0)
    load.install_iat_dispatcher(uc, img, shim)
    load.install_fault_logger(uc, shim)

    # M2 fixups: dummy dialog object + perf frequency
    dummy_dlg = shim.malloc(0x400)
    uc.mem_write(0x00DEB7E4, struct.pack("<I", dummy_dlg))
    uc.mem_write(0x00DFDCA8, struct.pack("<Q", 1))

    esp = load.STACK_BASE + load.STACK_SIZE - 0x100
    esp -= 4; uc.mem_write(esp, struct.pack("<I", 0))
    esp -= 4; uc.mem_write(esp, struct.pack("<I", load.SENTINEL_RET))
    uc.reg_write(UC_X86_REG_ESP, esp)
    uc.reg_write(UC_X86_REG_EBP, 0)

    fault = None
    try:
        uc.emu_start(load.CALC_THREAD_VA, 0, timeout=10_000_000, count=4_000_000)
    except UcError as e:
        fault = e

    final_eip = uc.reg_read(UC_X86_REG_EIP)

    # Must halt at MAIN_LOOP_VA (the explicit halt fired) with no UcError
    assert fault is None, f"emu_start raised {fault} at EIP=0x{final_eip:x}"
    assert final_eip == load.MAIN_LOOP_VA, \
        f"expected to halt at main loop 0x{load.MAIN_LOOP_VA:x}, got 0x{final_eip:x}"

    # Sanity: framebuffer must be readable at DAT_00DEC9F8+0x14 → real heap ptr
    state_ptr = struct.unpack("<I", uc.mem_read(0x00DEC9F8, 4))[0]
    assert load.HEAP_BASE <= state_ptr < load.HEAP_BASE + load.HEAP_SIZE, \
        f"DAT_00DEC9F8 was never set; got 0x{state_ptr:x}"
    fb_ptr = struct.unpack("<I", uc.mem_read(state_ptr + 0x14, 4))[0]
    assert load.HEAP_BASE <= fb_ptr < load.HEAP_BASE + load.HEAP_SIZE, \
        f"framebuffer ptr not in heap: 0x{fb_ptr:x}"

    # The framebuffer is 10922 bytes (127 rows * 86 bytes/row). Should be
    # readable end-to-end without faulting.
    fb = bytes(uc.mem_read(fb_ptr, 10922))
    assert len(fb) == 10922

    print(f"[OK] M2 reached main loop. state=0x{state_ptr:x}, fb=0x{fb_ptr:x}, "
          f"non-zero fb bytes={sum(1 for b in fb if b != 0)}/10922")


if __name__ == "__main__":
    test_m2_reaches_main_loop()
