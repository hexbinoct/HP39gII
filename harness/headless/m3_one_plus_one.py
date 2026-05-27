"""
M3: Boot the calc headless, then drive "1 + 1 = ENTER" by directly calling
into emulated functions (no main loop required). Dump and decode the
framebuffer after each key, write PNG-equivalents (PGM, since stdlib lacks
PNG), and print MD5s for comparison against the native-harness gold.

Mirrors the native probe.dll sequence from the 2026-05-17 session.
"""
from __future__ import annotations

import hashlib
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import load
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UcError
from unicorn.x86_const import (
    UC_X86_REG_EAX, UC_X86_REG_ECX, UC_X86_REG_ESP, UC_X86_REG_EBP, UC_X86_REG_EIP,
)

# Calc-internal function VAs (all verified against Ghidra, image is non-ASLR).
FN_ENQUEUE_EVENT = 0x00941210  # __thiscall queue, evt_type, payload_ptr  RET 8
FN_PRESS_KEY     = 0x0043BE90  # __cdecl, 1 stack arg = keycode (NOT ECX — notes were wrong)
FN_RELEASE_KEY   = 0x0043BED0  # __cdecl, 1 stack arg = keycode
FN_TICK          = 0x00944270  # __fastcall ecx=0, stack=0 — process+repaint  RET 4
FN_DRAIN_QUEUE   = 0x00942310  # __thiscall queue_in_ECX, arg = host_bridge[+0x20]

ADDR_EVENT_QUEUE = 0x00DECA08  # holds pointer to queue object
ADDR_HOST_BRIDGE = 0x00DECA00  # holds pointer to host bridge struct
ADDR_STATE       = 0x00DEC9F8  # holds pointer to CDesktop root
STATE_FB_PTR_OFS = 0x14
STATE_WIDTH_OFS  = 0x0C
STATE_HEIGHT_OFS = 0x10
STATE_PITCH_OFS  = 0x28

# Sentinel return address used when calling into emulated code. Hitting it
# stops emu_start. Must be page-aligned and mappable so Unicorn can fetch
# an instruction byte there before our code hook fires.
SENTINEL_HOST_RET = 0x21000000
SENTINEL_PAGE     = SENTINEL_HOST_RET & ~0xFFF


def boot(uc: Uc):
    """Run M2's boot sequence to the main-loop entry, then return ready-to-use
    shim. The main loop is NOT entered — we drive functions directly from here."""
    uc.mem_map(load.STACK_BASE, load.STACK_SIZE)
    uc.mem_map(load.HEAP_BASE, load.HEAP_SIZE)
    uc.mem_map(load.TRAMP_BASE, load.TRAMP_SIZE)

    img = load.load_pe_into(uc)
    load.setup_fs_segment(uc)
    shim = load.Shim(uc=uc, verbose_per_name=0)
    load.install_iat_dispatcher(uc, img, shim)
    load.install_fault_logger(uc, shim)

    # M2 fixups
    dummy_dlg = shim.malloc(0x400)
    uc.mem_write(0x00DEB7E4, struct.pack("<I", dummy_dlg))
    uc.mem_write(0x00DFDCA8, struct.pack("<Q", 1))

    esp = load.STACK_BASE + load.STACK_SIZE - 0x100
    esp -= 4; uc.mem_write(esp, struct.pack("<I", 0))
    esp -= 4; uc.mem_write(esp, struct.pack("<I", load.SENTINEL_RET))
    uc.reg_write(UC_X86_REG_ESP, esp)
    uc.reg_write(UC_X86_REG_EBP, 0)

    uc.emu_start(load.CALC_THREAD_VA, 0, timeout=10_000_000, count=4_000_000)
    assert uc.reg_read(UC_X86_REG_EIP) == load.MAIN_LOOP_VA, "boot did not reach main loop"

    # Post-boot fixup: host_bridge[+0x584] is the default FONT INDEX (not a
    # count). It is normally set when fonts load from calc.settings; we stub
    # that file I/O so it stays 0, which makes FUN_00935660's decrement-with-
    # wrap underflow to 0xFFFFFFFF and crash the widget sizer (FUN_00944630).
    # The system fonts are embedded in .rdata (static table @0xC18D00):
    #   index 1 -> table[0] line-height 12 (small), index 2 -> table[1] h=16 (large).
    # The native golden frame sizes the edit line with the height-16 font
    # (separator at row 94), so the real default index is 2 — set it to match.
    bridge = struct.unpack("<I", uc.mem_read(ADDR_HOST_BRIDGE, 4))[0]
    uc.mem_write(bridge + 0x584, struct.pack("<I", 2))
    print(f"[boot] set host_bridge[+0x584] = 2 (default font index -> embedded h=16 font)")

    # We enter at the calc worker thread (CALC_THREAD_VA) and so skip
    # mainCRTStartup's _initterm walk of the C++ static-initializer table
    # (.CRT$XC*). Most globals are plain .data, but a handful of plot-transform
    # scale constants are computed by static initializers and are left zero,
    # which makes the plot's decimal->pixel transform (FUN_00959400) map every
    # curve sample to (0,0) -> no curve drawn. Run the four plot-transform
    # initializers explicitly (each sets its global = 21/2 = 10.5):
    #   FUN_00a2c190 -> DAT_00dfe978   FUN_00a2c1d0 -> DAT_00dfe988  (X axis)
    #   FUN_00a2c210 -> DAT_00dfe998   FUN_00a2c250 -> DAT_00dfe9a8  (Y axis)
    # (Running the whole .CRT$XC* table blindly faults — those initializers need
    # CRT/environment state we don't reproduce; these four are self-contained.)
    for _init in (0xA2C190, 0xA2C1D0, 0xA2C210, 0xA2C250):
        call_emu(uc, _init)
    print("[boot] ran 4 plot-transform static initializers (DAT_00dfe978/988/998/9a8 = 10.5)")

    return shim, img


def call_emu(uc: Uc, fn_va: int, ecx: int = 0, stack_args: tuple[int, ...] = ()):
    """Call an emulated function from the host. Caller must know calling
    convention: ECX gets `ecx`, stack args are pushed right-to-left, the callee
    is assumed to clean up its own args (stdcall / __fastcall with RET imm).
    """
    esp = uc.reg_read(UC_X86_REG_ESP)
    # Push args (rightmost first onto the stack so leftmost ends at the top)
    for a in reversed(stack_args):
        esp -= 4
        uc.mem_write(esp, struct.pack("<I", a & 0xFFFFFFFF))
    # Push sentinel return address
    esp -= 4
    uc.mem_write(esp, struct.pack("<I", SENTINEL_HOST_RET))
    uc.reg_write(UC_X86_REG_ESP, esp)
    uc.reg_write(UC_X86_REG_ECX, ecx & 0xFFFFFFFF)
    # Resume-to-sentinel: a single bounded shot truncates long calls (e.g. one
    # plot tick runs ~15M instructions, past the old 10M cap, halting mid-math
    # and never drawing the curve). Loop emu_start from the stopped EIP until it
    # reaches the sentinel, capped by a generous total budget so a genuine
    # infinite loop still terminates.
    SHOT, BUDGET = 20_000_000, 400_000_000
    spent = 0
    eip = fn_va
    while True:
        uc.emu_start(eip, 0, timeout=5_000_000, count=SHOT)
        eip = uc.reg_read(UC_X86_REG_EIP)
        if eip == SENTINEL_HOST_RET:
            break
        spent += SHOT
        if spent >= BUDGET:
            raise RuntimeError(
                f"call_emu({fn_va:#x}) did not return to sentinel within "
                f"{BUDGET} insns: halted at EIP=0x{eip:x}"
            )
    actual_eip = eip
    return uc.reg_read(UC_X86_REG_EAX)


def install_sentinel_halt(uc: Uc):
    from unicorn import UC_HOOK_CODE
    uc.mem_map(SENTINEL_PAGE, 0x1000)
    uc.mem_write(SENTINEL_HOST_RET, b"\xC3")  # RET, in case the hook misses
    def _h(uc, address, size, ud):
        if address == SENTINEL_HOST_RET:
            uc.emu_stop()
    uc.hook_add(UC_HOOK_CODE, _h, begin=SENTINEL_HOST_RET, end=SENTINEL_HOST_RET + 1)


# ----- framebuffer decode (port of decode_fb.ps1) -----
# Per the 2026-05-17 native-harness session: 86 bytes/row × 127 rows; 3 pixels
# packed in 3+3+2 bits. After decode, the calc's display palette only shows
# 4 levels via (pixel >> 1).
def read_framebuffer(uc: Uc) -> bytes:
    state_ptr = struct.unpack("<I", uc.mem_read(ADDR_STATE, 4))[0]
    fb_ptr = struct.unpack("<I", uc.mem_read(state_ptr + STATE_FB_PTR_OFS, 4))[0]
    return bytes(uc.mem_read(fb_ptr, 10922))


def decode_to_grayscale(fb: bytes, width: int = 256, height: int = 127, pitch: int = 86) -> bytes:
    """Return height*width bytes, each 0..3 (displayed grayscale level)."""
    out = bytearray(width * height)
    for row in range(height):
        rowdata = fb[row * pitch:(row + 1) * pitch]
        for byte_idx, b in enumerate(rowdata):
            base_x = byte_idx * 3
            if base_x < width:
                out[row * width + base_x] = ((b >> 5) & 7) >> 1
            if base_x + 1 < width:
                out[row * width + base_x + 1] = ((b >> 2) & 7) >> 1
            if base_x + 2 < width:
                out[row * width + base_x + 2] = ((b << 1) & 7) >> 1
    return bytes(out)


def write_pgm(path: str, gray: bytes, width: int = 256, height: int = 127):
    """Write a Netpbm P5 grayscale image — viewable in most image tools and
    trivially convertible to PNG with `magick` or ImageMagick."""
    # Map 0..3 to 0/85/170/255 for visibility
    mapped = bytes(min(255, g * 85) for g in gray)
    with open(path, "wb") as f:
        f.write(f"P5\n{width} {height}\n255\n".encode())
        f.write(mapped)


# ----- the test sequence -----
KEY_SEQUENCE = [
    ("1", 42),
    ("+", 45),
    ("1", 42),
    ("ENTER", 50),
]


def drain_and_tick(uc: Uc):
    """Mirror what the main loop does after a wake: state flag fixups, drain, paint."""
    queue = struct.unpack("<I", uc.mem_read(ADDR_EVENT_QUEUE, 4))[0]
    bridge = struct.unpack("<I", uc.mem_read(ADDR_HOST_BRIDGE, 4))[0]
    arg = struct.unpack("<I", uc.mem_read(bridge + 0x20, 4))[0]
    state = struct.unpack("<I", uc.mem_read(ADDR_STATE, 4))[0]

    # Pre-drain state flag manipulations the main loop does after wake (loop body
    # 0x004018c9-0x004018e8). These tell the calc "fresh input pending".
    f2c = struct.unpack("<I", uc.mem_read(state + 0x2c, 4))[0]
    uc.mem_write(state + 0x2c, struct.pack("<I", f2c & 0xfffffbff))
    f90 = struct.unpack("<I", uc.mem_read(state + 0x90, 4))[0]
    if (f90 & 0x10) == 0:
        uc.mem_write(state + 0x90, struct.pack("<I", f90 | 0x10))

    call_emu(uc, FN_DRAIN_QUEUE, ecx=queue, stack_args=(arg,))
    call_emu(uc, FN_TICK, ecx=state, stack_args=(0,))


def diag(uc, tag):
    queue = struct.unpack("<I", uc.mem_read(ADDR_EVENT_QUEUE, 4))[0]
    head, tail = uc.mem_read(queue + 0x80, 2)
    keymask = struct.unpack("<Q", uc.mem_read(0x00DFDC88, 8))[0]
    print(f"    [{tag}] queue head={head} tail={tail}  keymask=0x{keymask:016x}")


def inject_key(uc: Uc, shim, keycode: int):
    """Mirror the native probe DLL: enqueue_event + press_key, drain, paint, release, drain, paint."""
    payload_addr = shim.malloc(16)
    uc.mem_write(payload_addr, b"\x01" + b"\x00" * 3 + bytes([keycode]) + b"\x00" * 11)
    queue = struct.unpack("<I", uc.mem_read(ADDR_EVENT_QUEUE, 4))[0]
    diag(uc, "pre-enqueue")
    call_emu(uc, FN_ENQUEUE_EVENT, ecx=queue, stack_args=(0, payload_addr))
    diag(uc, "post-enqueue")
    call_emu(uc, FN_PRESS_KEY, stack_args=(keycode,))
    diag(uc, "post-press")
    drain_and_tick(uc)
    diag(uc, "post-drain+tick")
    call_emu(uc, FN_RELEASE_KEY, stack_args=(keycode,))
    drain_and_tick(uc)
    diag(uc, "post-release+tick")


def main():
    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    install_sentinel_halt(uc)
    print("[boot] running M2 boot to main-loop entry...")
    shim, img = boot(uc)
    state_ptr = struct.unpack("<I", uc.mem_read(ADDR_STATE, 4))[0]
    fb_ptr = struct.unpack("<I", uc.mem_read(state_ptr + STATE_FB_PTR_OFS, 4))[0]
    print(f"[boot] OK. state=0x{state_ptr:x}, fb=0x{fb_ptr:x}")

    out_dir = os.path.join(HERE, "frames")
    os.makedirs(out_dir, exist_ok=True)

    def dump(label: str):
        fb = read_framebuffer(uc)
        md5 = hashlib.md5(fb).hexdigest()
        gray = decode_to_grayscale(fb)
        pgm_path = os.path.join(out_dir, f"{label}.pgm")
        write_pgm(pgm_path, gray)
        nonzero = sum(1 for b in fb if b != 0)
        print(f"  [frame {label}] md5={md5}  nonzero_bytes={nonzero}/10922  -> {pgm_path}")
        return md5

    md5s = []
    md5s.append(dump("00_boot"))

    for i, (label, keycode) in enumerate(KEY_SEQUENCE, start=1):
        print(f"[key {i}/{len(KEY_SEQUENCE)}] {label}  (keycode {keycode})")
        try:
            inject_key(uc, shim, keycode)
        except (UcError, RuntimeError) as e:
            print(f"  ! injection failed: {e}")
            break
        md5s.append(dump(f"{i:02d}_{label}"))

    print("\n[summary] framebuffer MD5 sequence:")
    for label, m in zip(["boot"] + [k[0] for k in KEY_SEQUENCE], md5s):
        print(f"  {label:>6} : {m}")


if __name__ == "__main__":
    main()
