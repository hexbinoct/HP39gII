import sys, struct, re
sys.stdout.reconfigure(errors='replace')

with open('F:/ru/myprojects/april/calc/HP39gII.exe', 'rb') as f:
    data = f.read()

pe_offset = struct.unpack_from('<I', data, 0x3C)[0]
image_base = struct.unpack_from('<I', data, pe_offset + 24 + 28)[0]  # 0x400000
num_sections = struct.unpack_from('<H', data, pe_offset + 6)[0]
section_offset = pe_offset + 0xF8
sections = []
for i in range(num_sections):
    off = section_offset + i * 40
    name = data[off:off+8].rstrip(b'\x00').decode('ascii', errors='replace')
    vaddr = struct.unpack_from('<I', data, off+12)[0]
    vsize = struct.unpack_from('<I', data, off+8)[0]
    rawptr = struct.unpack_from('<I', data, off+20)[0]
    rawsize = struct.unpack_from('<I', data, off+16)[0]
    sections.append((name, vaddr, vsize, rawptr, rawsize))

def rva_to_offset(rva):
    for name, vaddr, vsize, rawptr, rawsize in sections:
        if vaddr <= rva < vaddr + rawsize:
            return rawptr + (rva - vaddr)
    return None

def va_to_offset(va_val):
    return rva_to_offset(va_val - image_base)

def offset_to_va(off):
    for name, vaddr, vsize, rawptr, rawsize in sections:
        if rawptr <= off < rawptr + rawsize:
            return image_base + vaddr + (off - rawptr)
    return None

# =========================================================================
# PART 1: Disassemble the 4 unique CVirtualLCD virtual functions
# =========================================================================
print("="*70)
print("DISASSEMBLING CVirtualLCD UNIQUE VIRTUAL FUNCTIONS")
print("="*70)

# CVirtualLCD vtable unique entries (different from CAspen_cDlg):
# [0] 0x0040a8d0 - unique
# [1] 0x0040aa30 - unique
# [3] 0x009627f6 - unique (but actually let's check - the CAspen one is 0x00964129)
# [10] 0x0040af30 - unique

unique_funcs = [
    (0, 0x0040a8d0, "CVirtualLCD::vfunc0"),
    (1, 0x0040aa30, "CVirtualLCD::vfunc1"),
    (3, 0x009627f6, "CVirtualLCD::vfunc3"),
    (10, 0x0040af30, "CVirtualLCD::vfunc10"),
]

def hexdump_code(file_offset, length, label=""):
    """Dump raw bytes with basic x86 pattern recognition"""
    print(f"\n--- {label} (file: {file_offset:#x}, VA: {offset_to_va(file_offset):#x}) ---")
    pos = file_offset
    end = file_offset + length
    while pos < end:
        byte = data[pos]
        va_val = offset_to_va(pos)
        # Show raw bytes, 16 per line
        line_bytes = data[pos:pos+16]
        hex_str = ' '.join(f'{b:02x}' for b in line_bytes)
        ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in line_bytes)
        print(f"  {va_val:#010x}: {hex_str:<48s} {ascii_str}")
        pos += 16

for slot, va_val, name in unique_funcs:
    file_off = va_to_offset(va_val)
    hexdump_code(file_off, 256, f"vtable[{slot}] = {name}")

# =========================================================================
# PART 2: Find StretchDIBits / BitBlt / StretchBlt IAT entries and trace calls
# =========================================================================
print()
print("="*70)
print("FINDING DISPLAY BLIT CALLS (IAT-based)")
print("="*70)

# Build IAT mapping by finding import thunks
# In PE, the Import Address Table entries are at the ILT/IAT RVAs
# Let's find the thunks (jmp [IAT]) which are in .text section usually at the end

# Scan for FF 25 patterns (jmp dword ptr [xxx]) in last part of .text
text_start = sections[0][3]  # .text raw offset
text_size = sections[0][4]
text_end = text_start + text_size

# Find all jmp [xxxx] thunks
thunks = {}
for pos in range(text_end - 0x2000, text_end):
    if data[pos] == 0xFF and data[pos+1] == 0x25:
        target_va = struct.unpack_from('<I', data, pos+2)[0]
        thunk_va = offset_to_va(pos)
        thunks[thunk_va] = target_va

# Now find which thunks correspond to our display functions
# by checking what the IAT points to after resolution
# Since this is an unloaded PE, the IAT still has the hint/name RVAs
# Let's map IAT VA -> function name

def get_import_name(iat_va):
    """Given an IAT entry VA, try to find the imported function name"""
    iat_off = va_to_offset(iat_va)
    if iat_off is None:
        return None
    hint_rva = struct.unpack_from('<I', data, iat_off)[0]
    if hint_rva & 0x80000000:
        return f"Ordinal_{hint_rva & 0xFFFF}"
    hint_off = rva_to_offset(hint_rva)
    if hint_off is None:
        return None
    try:
        name_end = data.index(b'\x00', hint_off + 2)
        return data[hint_off+2:name_end].decode('ascii')
    except:
        return None

# Map thunk VA -> function name
display_thunks = {}
for thunk_va, iat_va in thunks.items():
    fname = get_import_name(iat_va)
    if fname and fname in ['BitBlt', 'StretchBlt', 'StretchDIBits', 'CreateCompatibleDC',
                            'CreateCompatibleBitmap', 'CreateBitmap', 'SelectObject',
                            'InvalidateRect', 'BeginPaint', 'EndPaint', 'GetDC', 'ReleaseDC',
                            'SetDIBitsToDevice', 'GetClientRect', 'StretchBlt',
                            'GdipCreateBitmapFromScan0', 'GdipCreateBitmapFromHBITMAP']:
        display_thunks[thunk_va] = fname
        print(f"  Thunk {thunk_va:#010x} -> {fname}")

# Now find CALL instructions to these thunks
# CALL rel32 = E8 xx xx xx xx
print("\nCalls to display functions:")
for thunk_va, fname in sorted(display_thunks.items(), key=lambda x: x[1]):
    # Find E8 calls: E8 + (target - (call_addr + 5))
    call_sites = []
    for pos in range(text_start, text_end - 5):
        if data[pos] == 0xE8:
            rel32 = struct.unpack_from('<i', data, pos+1)[0]  # signed
            call_va = offset_to_va(pos)
            target = call_va + 5 + rel32
            if target == thunk_va:
                call_sites.append(call_va)

    if call_sites:
        print(f"\n  {fname} ({thunk_va:#x}): {len(call_sites)} call sites")
        for site in call_sites[:10]:
            print(f"    called from VA {site:#010x} (file {va_to_offset(site):#x})")

# =========================================================================
# PART 3: Look at what happens around the StretchDIBits / BitBlt calls
# =========================================================================
print()
print("="*70)
print("CONTEXT AROUND DISPLAY BLIT CALLS")
print("="*70)

# For each StretchDIBits/BitBlt call site, dump surrounding code
for thunk_va, fname in sorted(display_thunks.items(), key=lambda x: x[1]):
    if fname not in ['StretchDIBits', 'BitBlt', 'StretchBlt']:
        continue
    for pos in range(text_start, text_end - 5):
        if data[pos] == 0xE8:
            rel32 = struct.unpack_from('<i', data, pos+1)[0]
            call_va = offset_to_va(pos)
            target = call_va + 5 + rel32
            if target == thunk_va:
                # Dump 64 bytes before and 16 after the call
                start = pos - 80
                print(f"\n  --- Context for CALL {fname} at VA {call_va:#x} ---")
                for line_start in range(start, pos + 16, 16):
                    va_val = offset_to_va(line_start)
                    line_bytes = data[line_start:line_start+16]
                    hex_str = ' '.join(f'{b:02x}' for b in line_bytes)
                    marker = " <-- CALL" if line_start <= pos < line_start + 16 else ""
                    print(f"  {va_val:#010x}: {hex_str}{marker}")

# =========================================================================
# PART 4: Trace the framebuffer pointer at 0x00DEC9F8
# =========================================================================
print()
print("="*70)
print("TRACING FRAMEBUFFER POINTER 0x00DEC9F8")
print("="*70)

# VA 0x00DEC9F8 appeared in the screen descriptor structs
fb_ptr_va = 0x00DEC9F8
fb_ptr_off = va_to_offset(fb_ptr_va)
print(f"VA {fb_ptr_va:#x} -> file offset {fb_ptr_off:#x}" if fb_ptr_off else f"VA {fb_ptr_va:#x} -> NOT IN FILE (runtime allocated!)")

# Check if this is in .data section (initialized) or .bss (uninitialized)
fb_rva = fb_ptr_va - image_base
for name, vaddr, vsize, rawptr, rawsize in sections:
    if vaddr <= fb_rva < vaddr + vsize:
        in_raw = rawptr <= (rawptr + fb_rva - vaddr) < rawptr + rawsize
        print(f"  In section: {name}, VA range: {image_base+vaddr:#x}-{image_base+vaddr+vsize:#x}")
        print(f"  In raw file data: {in_raw}")
        if not in_raw:
            print(f"  ** This is in BSS (uninitialized data) - runtime only! **")

# Search for references to this address (who reads/writes it)
fb_bytes = struct.pack('<I', fb_ptr_va)
print(f"\nReferences to {fb_ptr_va:#x} in code:")
ref_count = 0
for m in re.finditer(re.escape(fb_bytes), data[:text_end]):
    ref_va = offset_to_va(m.start())
    if ref_va and sections[0][1] + image_base <= ref_va < sections[0][1] + sections[0][2] + image_base:
        ref_count += 1
        if ref_count <= 20:
            # Show a few bytes of context
            ctx = data[m.start()-4:m.start()+8]
            hex_ctx = ' '.join(f'{b:02x}' for b in ctx)
            print(f"  VA {ref_va:#010x}: ...{hex_ctx}...")
print(f"  Total references in .text: {ref_count}")

# =========================================================================
# PART 5: Look for GROB (Graphics Object) implementation
# =========================================================================
print()
print("="*70)
print("HP GROB (Graphics Object) - THE FRAMEBUFFER ABSTRACTION")
print("="*70)

# GROBs are HP's name for graphics objects / bitmaps
# The calc has multiple GROBs (G0-G9 typically)
# DIMGROB creates one, BLIT copies between them
# The screen is GROB G0

# Search for GROB-related patterns
grob_strings = [b'GROB', b'grob', b'G0', b'G1', b'G2']
for gs in [b'DIMGROB\x00', b'BLIT\x00', b'SUBGROB\x00', b'GROBW\x00', b'GROBH\x00']:
    for m in re.finditer(re.escape(gs), data):
        if m.start() > 0x7e0000:  # in string data area
            rva = m.start() - sections[1][3] + sections[1][1] if m.start() > sections[1][3] else None
            # Find who references this string
            if rva:
                str_va = image_base + rva
                str_bytes = struct.pack('<I', str_va)
                refs = list(re.finditer(re.escape(str_bytes), data[:text_end]))
                gs_clean = gs.rstrip(b'\x00').decode()
                print(f"  {gs_clean}: string at VA {str_va:#x}, {len(refs)} code references")

# =========================================================================
# PART 6: The screen dimension structs in detail
# =========================================================================
print()
print("="*70)
print("SCREEN REGION DESCRIPTORS (at 0x680DA0)")
print("="*70)

# These structs at 0x680DA0 define screen regions
# Format appears to be: {y_offset, width, height, context_ptr, ...}
loc = 0x680d98
print("Reading screen descriptor table:")
for i in range(8):
    base = loc + i * 20  # try stride of 20 bytes (5 dwords)
    if base + 20 <= len(data):
        vals = struct.unpack_from('<5I', data, base)
        print(f"  Region {i}: y={vals[0]:3d} w={vals[1]:3d} h={vals[2]:3d} ptr={vals[3]:#010x} flags={vals[4]:#x}")

# Also try stride of 16 (4 dwords)
print("\nTrying 16-byte stride:")
for i in range(8):
    base = loc + i * 16
    if base + 16 <= len(data):
        vals = struct.unpack_from('<4I', data, base)
        print(f"  Region {i}: [{vals[0]:6d}, {vals[1]:6d}, {vals[2]:6d}, {vals[3]:#010x}]")

# =========================================================================
# PART 7: Count Windows API calls vs pure computation
# =========================================================================
print()
print("="*70)
print("WINDOWS API CALL DENSITY ANALYSIS")
print("="*70)

# Count total E8 (CALL) instructions in .text
total_calls = 0
win_api_calls = 0
all_thunk_vas = set(thunks.keys())

for pos in range(text_start, text_end - 5):
    if data[pos] == 0xE8:
        rel32 = struct.unpack_from('<i', data, pos+1)[0]
        call_va = offset_to_va(pos)
        if call_va:
            target = call_va + 5 + rel32
            total_calls += 1
            if target in all_thunk_vas:
                win_api_calls += 1

print(f"Total CALL instructions in .text: {total_calls}")
print(f"Calls to Windows API thunks: {win_api_calls}")
print(f"Internal (calc core) calls: {total_calls - win_api_calls}")
print(f"Windows API dependency: {win_api_calls*100/total_calls:.1f}%")

# Which APIs are called most?
api_call_counts = {}
for pos in range(text_start, text_end - 5):
    if data[pos] == 0xE8:
        rel32 = struct.unpack_from('<i', data, pos+1)[0]
        call_va = offset_to_va(pos)
        if call_va:
            target = call_va + 5 + rel32
            if target in thunks:
                fname = get_import_name(thunks[target])
                if fname:
                    api_call_counts[fname] = api_call_counts.get(fname, 0) + 1

print("\nTop 30 most-called Windows APIs:")
for fname, count in sorted(api_call_counts.items(), key=lambda x: -x[1])[:30]:
    print(f"  {count:5d}x  {fname}")
