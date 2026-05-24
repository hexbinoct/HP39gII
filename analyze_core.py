import sys, struct, re
sys.stdout.reconfigure(errors='replace')

with open('F:/ru/myprojects/april/calc/HP39gII.exe', 'rb') as f:
    data = f.read()

pe_offset = struct.unpack_from('<I', data, 0x3C)[0]
image_base = struct.unpack_from('<I', data, pe_offset + 24 + 28)[0]
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

def offset_to_rva(off):
    for name, vaddr, vsize, rawptr, rawsize in sections:
        if rawptr <= off < rawptr + rawsize:
            return vaddr + (off - rawptr)
    return None

def va(rva):
    return image_base + rva

print("="*70)
print("PART 1: LOCATING CVirtualLCD")
print("="*70)

# Find the RTTI type descriptor for CVirtualLCD
# It contains the string ".?AVCVirtualLCD@@"
cvlcd_rtti_pos = data.find(b'.?AVCVirtualLCD@@')
if cvlcd_rtti_pos:
    print(f"CVirtualLCD RTTI type_info at file offset: {cvlcd_rtti_pos:#x}")
    rva = offset_to_rva(cvlcd_rtti_pos)
    print(f"  RVA: {rva:#x}, VA: {va(rva):#x}")

    # The type_info struct starts 8 bytes before the name string
    # (vtable ptr + spare ptr + name)
    type_info_start = cvlcd_rtti_pos - 8
    type_info_rva = offset_to_rva(type_info_start)
    type_info_va = va(type_info_rva)
    print(f"  type_info struct VA: {type_info_va:#x}")

    # Search for references to this type_info (pointers to it)
    # These will be in RTTI Complete Object Locator -> Class Hierarchy -> Base Class Array
    target_bytes = struct.pack('<I', type_info_va)
    refs = []
    for m in re.finditer(re.escape(target_bytes), data):
        ref_rva = offset_to_rva(m.start())
        if ref_rva:
            refs.append((m.start(), va(ref_rva)))
    print(f"  References to CVirtualLCD type_info: {len(refs)}")
    for foff, ref_va in refs:
        print(f"    at file {foff:#x} (VA {ref_va:#x})")

print()

# Also find the string "CVirtualLCD" in various contexts
print("All occurrences of 'VirtualLCD' string:")
for m in re.finditer(b'VirtualLCD', data):
    start = m.start()
    # Get surrounding context
    ctx_start = max(0, start - 20)
    ctx_end = min(len(data), start + 40)
    ctx = data[ctx_start:ctx_end]
    rva = offset_to_rva(start)
    print(f"  file {start:#x} (VA {va(rva) if rva else '???'}): ...{ctx}...")

print()
print("="*70)
print("PART 2: FINDING THE VTABLE FOR CVirtualLCD")
print("="*70)

# In MSVC RTTI, the vtable is pointed to by a Complete Object Locator
# which contains a pointer to the type_info
# The COL is at vtable[-1]
# Let's find the Complete Object Locator that references our type_info
# COL structure: signature(4) + offset(4) + cdOffset(4) + pTypeDescriptor(4) + pClassHierarchy(4)

type_info_va_bytes = struct.pack('<I', type_info_va)
# Search for COL entries that point to our type_info
# The pTypeDescriptor is at offset 12 in the COL
col_candidates = []
for m in re.finditer(re.escape(type_info_va_bytes), data):
    # Check if this could be a COL (pTypeDescriptor at offset 12)
    col_start = m.start() - 12
    if col_start >= 0:
        sig = struct.unpack_from('<I', data, col_start)[0]
        if sig == 0:  # COL signature is 0 for 32-bit
            col_rva = offset_to_rva(col_start)
            if col_rva:
                col_va = va(col_rva)
                print(f"  Complete Object Locator at file {col_start:#x} (VA {col_va:#x})")
                col_candidates.append((col_start, col_va))

# Now find vtables that point to these COLs
# vtable[-1] = pointer to COL
for col_off, col_va_val in col_candidates:
    col_ptr_bytes = struct.pack('<I', col_va_val)
    for m in re.finditer(re.escape(col_ptr_bytes), data):
        # The vtable starts right after this pointer
        vtable_start = m.start() + 4
        vtable_rva = offset_to_rva(vtable_start)
        if vtable_rva:
            vtable_va = va(vtable_rva)
            print(f"  CVirtualLCD vtable at file {vtable_start:#x} (VA {vtable_va:#x})")

            # Read first few vtable entries (virtual function pointers)
            print(f"  Virtual functions:")
            for j in range(20):
                vfunc_off = vtable_start + j * 4
                if vfunc_off + 4 <= len(data):
                    vfunc_va = struct.unpack_from('<I', data, vfunc_off)[0]
                    # Verify it points to .text section
                    vfunc_rva = vfunc_va - image_base
                    vfunc_file = rva_to_offset(vfunc_rva)
                    if vfunc_file and sections[0][1] <= vfunc_rva < sections[0][1] + sections[0][2]:
                        print(f"    [{j:2d}] VA {vfunc_va:#010x} (file {vfunc_file:#x})")
                    else:
                        print(f"    [{j:2d}] VA {vfunc_va:#010x} -- end of vtable?")
                        break

print()
print("="*70)
print("PART 3: KEY INPUT - LOOKING FOR GETKEY / KEY HANDLING")
print("="*70)

# Find GETKEY, ISKEYDOWN, and key-related HP PPL functions
key_strings = [b'GETKEY\x00', b'ISKEYDOWN\x00', b'GetKey', b'KeyPress', b'keypress',
               b'OnKeyDown', b'OnKeyUp', b'key_pressed', b'KeyEvent', b'keyevent',
               b'VK_', b'WM_KEYDOWN', b'WM_KEYUP']
for ks in key_strings:
    for m in re.finditer(re.escape(ks), data):
        rva = offset_to_rva(m.start())
        va_val = va(rva) if rva else 0
        ctx = data[m.start():m.start()+30]
        ctx_clean = ctx.split(b'\x00')[0]
        print(f"  {m.start():#x} (VA {va_val:#x}): {ctx_clean}")

print()
print("="*70)
print("PART 4: ALL RTTI CLASSES - MAPPING THE FULL ARCHITECTURE")
print("="*70)

# Find all RTTI class names to understand the full class hierarchy
rtti_pattern = re.compile(b'\\.\\?AV([A-Za-z0-9_]+)@@')
all_classes = []
for match in rtti_pattern.finditer(data):
    name = match.group(1).decode('ascii')
    all_classes.append(name)

# Group into categories
calc_core = []
mfc_ui = []
graphers = []
evaluators = []
other = []

mfc_prefixes = ['CWnd', 'CDialog', 'CWinApp', 'CWinThread', 'CCmdTarget', 'CObject',
                'CDC', 'CPen', 'CBrush', 'CMenu', 'CGdiObject', 'CStatic', 'CSliderCtrl',
                'AFX_', '_AFX_', 'CException', 'CFile', 'CArchive', 'CMap', 'CArray',
                'CPtr', 'COb', 'CWord', 'CByte', 'CString', 'CResource', 'CMemory',
                'CUser', 'COle', 'CInvalid', 'CNotSupported', 'CSimple', 'CHandle',
                'CClient', 'CPaint', 'CTest', 'CCommon', 'CShell', 'CComCtl', 'CCommDlg',
                'CDll', 'CNoTrack', 'CCmd', 'CDesktop', 'CAfx']

for cls in sorted(set(all_classes)):
    is_mfc = any(cls.startswith(p) for p in mfc_prefixes)
    if 'Grapher' in cls or 'Plotter' in cls or 'Plot' in cls:
        graphers.append(cls)
    elif 'Evaluator' in cls:
        evaluators.append(cls)
    elif is_mfc:
        mfc_ui.append(cls)
    else:
        calc_core.append(cls)

print("\n[CALCULATOR CORE classes]")
for cls in sorted(calc_core):
    print(f"  {cls}")

print("\n[GRAPHERS]")
for cls in sorted(graphers):
    print(f"  {cls}")

print("\n[EVALUATORS]")
for cls in sorted(evaluators):
    print(f"  {cls}")

print("\n[MFC/WINDOWS UI classes - to be replaced]")
for cls in sorted(mfc_ui):
    print(f"  {cls}")

print()
print("="*70)
print("PART 5: CROSS-REFERENCES - WHO CALLS BitBlt/StretchBlt?")
print("="*70)

# Find the IAT (Import Address Table) entries for BitBlt and StretchBlt
# Then find CALL instructions that reference them
# First find the import by looking for the string in the import section
for func_name in [b'BitBlt', b'StretchBlt', b'StretchDIBits', b'InvalidateRect']:
    print(f"\n  --- {func_name.decode()} ---")
    # Find in import names
    for m in re.finditer(re.escape(func_name + b'\x00'), data):
        rva = offset_to_rva(m.start())
        if rva and rva > sections[1][1]:  # in .rdata
            # This is a hint/name entry. The IAT will have the actual pointer.
            # For simplicity, let's search for CALL [IAT_addr] patterns
            # which are FF 15 xx xx xx xx (call dword ptr [addr])
            pass

# Alternative: just find all references to the string "CVirtualLCD" and "StretchBlt"
# in a way that tells us about the connection
print("\n\n  Looking for StretchDIBits call pattern (this is likely how framebuffer is displayed)...")
# StretchDIBits is the key function - it takes a DIB (device-independent bitmap)
# and stretches it to a DC. This is exactly how you'd display a framebuffer.
# Let's find cross-references

print()
print("="*70)
print("PART 6: FRAMEBUFFER CHARACTERISTICS")
print("="*70)
print()

# Look for the screen dimensions embedded in code
# HP 39gII screen: 256x127 pixels
# The skin file says MATRIX=256,127,86,20
# Look for these constants near each other

# Search for 256 (0x100) and 127 (0x7F) as 32-bit values near each other
target_256 = struct.pack('<I', 256)
target_127 = struct.pack('<I', 127)
target_320 = struct.pack('<I', 320)  # maybe padded to 320?
target_240 = struct.pack('<I', 240)  # common LCD height

print("Looking for screen dimension constants (256x127) in .text and .rdata...")
for m in re.finditer(re.escape(target_256), data):
    # Check if 127 is nearby (within 20 bytes)
    nearby = data[m.start()-20:m.start()+24]
    if target_127 in nearby:
        rva = offset_to_rva(m.start())
        if rva:
            section = 'unknown'
            for sname, svaddr, svsize, _, _ in sections:
                if svaddr <= rva < svaddr + svsize:
                    section = sname
            print(f"  256 at file {m.start():#x} (VA {va(rva):#x}) [{section}] - 127 found nearby!")

# Also look for common framebuffer allocation patterns
# A 256x127 grayscale buffer = 32512 bytes
# A 256x127 RGB buffer = 97536 bytes
# A 256x128 (padded) = 32768 bytes
fb_sizes = [(256*127, '256x127x8'), (256*128, '256x128x8'), (256*127*2, '256x127x16'),
            (256*127*4, '256x127x32'), (320*240, '320x240x8'), (320*240*2, '320x240x16')]
for size, desc in fb_sizes:
    target = struct.pack('<I', size)
    positions = [m.start() for m in re.finditer(re.escape(target), data[:sections[0][3]+sections[0][4]])]
    if positions:
        print(f"  Size {size} ({desc}): found {len(positions)} times in code, first at {positions[0]:#x}")

print()
print("="*70)
print("PART 7: CAspen_cDlg - THE THIN SHELL")
print("="*70)

# Find the Aspen dialog class RTTI and vtable
aspen_rtti = data.find(b'.?AVCAspen_cDlg@@')
if aspen_rtti:
    print(f"CAspen_cDlg RTTI at {aspen_rtti:#x}")
    type_info_start = aspen_rtti - 8
    type_info_rva = offset_to_rva(type_info_start)
    type_info_va_val = va(type_info_rva)
    print(f"  type_info VA: {type_info_va_val:#x}")

    # Find COL
    target = struct.pack('<I', type_info_va_val)
    for m in re.finditer(re.escape(target), data):
        col_start = m.start() - 12
        if col_start >= 0:
            sig = struct.unpack_from('<I', data, col_start)[0]
            if sig == 0:
                col_rva = offset_to_rva(col_start)
                if col_rva:
                    col_va_val = va(col_rva)
                    # Find vtable
                    col_ptr = struct.pack('<I', col_va_val)
                    for m2 in re.finditer(re.escape(col_ptr), data):
                        vt_start = m2.start() + 4
                        vt_rva = offset_to_rva(vt_start)
                        if vt_rva:
                            print(f"  CAspen_cDlg vtable at VA {va(vt_rva):#x}")
                            for j in range(30):
                                vf = struct.unpack_from('<I', data, vt_start + j*4)[0]
                                vf_rva = vf - image_base
                                vf_file = rva_to_offset(vf_rva)
                                if vf_file and sections[0][1] <= vf_rva < sections[0][1] + sections[0][2]:
                                    print(f"    [{j:2d}] VA {vf:#010x}")
                                else:
                                    break
