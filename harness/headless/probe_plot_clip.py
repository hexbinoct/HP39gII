"""
#12 LIKELY ROOT: the curve IS plotted as 255 points (FUN_00959d00 -> setpixel
FUN_00946a80), but FUN_00946a80 only writes a pixel if the clip test FUN_00943070
returns !=0. FUN_00943070's first gate:
    if (x<0 || *(ctx+0xc)<=x || y<0 || *(ctx+0x10)<=y) return 0;
ctx+0xc = canvas WIDTH, ctx+0x10 = canvas HEIGHT. If either is 0, EVERY point is
rejected -> blank canvas. Same zero-dimension family as the edit-line fix.

This probe hooks FUN_00943070 (clip test) entry -> dumps ctx, width(+0xc),
height(+0x10), and (x,y); and counts actual pixel writes FUN_00946280. If width/height
are 0 and pixel-writes==0 while clip-tests>0 -> ROOT CONFIRMED.
"""
from __future__ import annotations
import os, sys, struct
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import load, m3_one_plus_one as m3
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE
from unicorn.x86_const import UC_X86_REG_ESP, UC_X86_REG_ECX, UC_X86_REG_EIP

BUDGET, SHOT = 300_000_000, 20_000_000
FN_CLIP  = 0x943070
FN_PIXEL = 0x946280
cnt = {"clip": 0, "pixel": 0, "rejected_dim": 0}
samples = []


def call_to_sentinel(uc, fn_va, ecx=0, stack_args=()):
    esp = uc.reg_read(UC_X86_REG_ESP)
    for a in reversed(stack_args):
        esp -= 4
        uc.mem_write(esp, struct.pack("<I", a & 0xFFFFFFFF))
    esp -= 4
    uc.mem_write(esp, struct.pack("<I", m3.SENTINEL_HOST_RET))
    uc.reg_write(UC_X86_REG_ESP, esp)
    uc.reg_write(UC_X86_REG_ECX, ecx & 0xFFFFFFFF)
    spent, eip = 0, fn_va
    while spent < BUDGET:
        uc.emu_start(eip, 0, count=SHOT)
        eip = uc.reg_read(UC_X86_REG_EIP)
        spent += SHOT
        if eip == m3.SENTINEL_HOST_RET:
            return


def drain_to_sentinel(uc):
    queue = struct.unpack("<I", uc.mem_read(m3.ADDR_EVENT_QUEUE, 4))[0]
    bridge = struct.unpack("<I", uc.mem_read(m3.ADDR_HOST_BRIDGE, 4))[0]
    arg = struct.unpack("<I", uc.mem_read(bridge + 0x20, 4))[0]
    state = struct.unpack("<I", uc.mem_read(m3.ADDR_STATE, 4))[0]
    f2c = struct.unpack("<I", uc.mem_read(state + 0x2c, 4))[0]
    uc.mem_write(state + 0x2c, struct.pack("<I", f2c & 0xfffffbff))
    f90 = struct.unpack("<I", uc.mem_read(state + 0x90, 4))[0]
    if (f90 & 0x10) == 0:
        uc.mem_write(state + 0x90, struct.pack("<I", f90 | 0x10))
    call_to_sentinel(uc, m3.FN_DRAIN_QUEUE, ecx=queue, stack_args=(arg,))
    call_to_sentinel(uc, m3.FN_TICK, ecx=state, stack_args=(0,))


def tick_only(uc):
    state = struct.unpack("<I", uc.mem_read(m3.ADDR_STATE, 4))[0]
    call_to_sentinel(uc, m3.FN_TICK, ecx=state, stack_args=(0,))


def main():
    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    m3.install_sentinel_halt(uc)
    shim, img = m3.boot(uc)
    armed = {"on": False}

    def h_clip(uc, a, s, ud):
        if not armed["on"]:
            return
        cnt["clip"] += 1
        ctx = uc.reg_read(UC_X86_REG_ECX)
        esp = uc.reg_read(UC_X86_REG_ESP)
        px = struct.unpack("<I", uc.mem_read(esp + 4, 4))[0]
        py = struct.unpack("<I", uc.mem_read(esp + 8, 4))[0]
        try:
            x = struct.unpack("<i", uc.mem_read(px, 4))[0]
            y = struct.unpack("<i", uc.mem_read(py, 4))[0]
            w = struct.unpack("<i", uc.mem_read(ctx + 0xc, 4))[0]
            h = struct.unpack("<i", uc.mem_read(ctx + 0x10, 4))[0]
        except Exception:
            return
        if x < 0 or w <= x or y < 0 or h <= y:
            cnt["rejected_dim"] += 1
        # collect canvas-context points (the 255x111 plot canvas) for shape analysis
        if w == 255 and h == 111:
            samples.append((x, y))

    def h_pixel(uc, a, s, ud):
        if armed["on"]:
            cnt["pixel"] += 1

    uc.hook_add(UC_HOOK_CODE, h_clip, begin=FN_CLIP, end=FN_CLIP + 1)
    uc.hook_add(UC_HOOK_CODE, h_pixel, begin=FN_PIXEL, end=FN_PIXEL + 1)

    for name, kc in [("symb", 6), ("SIN", 21), ("X", 19), ("ENTER", 50)]:
        m3.inject_key(uc, shim, kc)

    print("[setup done] injecting PLOT, tracing clip test + pixel writes...")
    payload = shim.malloc(16)
    uc.mem_write(payload, b"\x01" + b"\x00" * 3 + bytes([7]) + b"\x00" * 11)
    queue = struct.unpack("<I", uc.mem_read(m3.ADDR_EVENT_QUEUE, 4))[0]
    m3.call_emu(uc, m3.FN_ENQUEUE_EVENT, ecx=queue, stack_args=(0, payload))
    m3.call_emu(uc, m3.FN_PRESS_KEY, stack_args=(7,))
    armed["on"] = True
    drain_to_sentinel(uc)
    for _ in range(8):
        tick_only(uc)
    armed["on"] = False

    print("\n==== clip test (FUN_00943070) + pixel write (FUN_00946280) ====")
    print(f"  clip tests        : {cnt['clip']}")
    print(f"  rejected by dim    : {cnt['rejected_dim']}  (x<0||w<=x||y<0||h<=y)")
    print(f"  actual pixel writes: {cnt['pixel']}    {'*** ZERO -> all clipped ***' if cnt['pixel']==0 else ''}")
    # characterize the canvas points (curve shape)
    by_x = {}
    for x, y in samples:
        by_x.setdefault(x, []).append(y)
    xs = sorted(by_x)
    ys_all = [y for _, y in samples]
    print(f"\n  canvas(255x111) points: {len(samples)}  x-range=[{xs[0] if xs else '-'}..{xs[-1] if xs else '-'}]  "
          f"y-range=[{min(ys_all) if ys_all else '-'}..{max(ys_all) if ys_all else '-'}]")
    print("  y(x) for x=0..40 (first y per x):")
    line = "  "
    for x in range(0, 41):
        line += f"{by_x[x][0]:>3}" if x in by_x else "  ."
    print(line)
    # SIN(X) over the default window should oscillate; a constant y = X never swept.
    distinct_y = sorted(set(ys_all))
    print(f"  distinct y values: {len(distinct_y)}  -> {distinct_y[:30]}{' ...' if len(distinct_y)>30 else ''}")


if __name__ == "__main__":
    main()
