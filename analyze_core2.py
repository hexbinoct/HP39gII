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

# =========================================================================
# Look at the data around where 256x127 dimensions are stored together
# =========================================================================
print("="*70)
print("EXAMINING 256x127 DIMENSION LOCATIONS IN .rdata")
print("="*70)

# Location 1: 0x680da4
for loc in [0x680da0, 0x680db0]:
    print(f"\nAt file offset {loc:#x}:")
    for i in range(16):
        val = struct.unpack_from('<I', data, loc + i*4)[0]
        print(f"  +{i*4:3d}: {val:#010x} ({val})")

print()
print("="*70)
print("EXAMINING 256x127 DIMENSION LOCATIONS IN .data")
print("="*70)

# .data section locations where 256 and 127 appear together
for loc_base in [0x9e9570, 0x9e9dd0]:
    print(f"\nAt file offset {loc_base:#x}:")
    rva = offset_to_rva(loc_base)
    print(f"  VA: {va(rva):#x}")
    for i in range(20):
        off = loc_base + i*4
        val = struct.unpack_from('<I', data, off)[0]
        # Also show as bytes for potential struct fields
        b0, b1, b2, b3 = data[off], data[off+1], data[off+2], data[off+3]
        print(f"  +{i*4:3d} ({off:#x}): {val:#010x} ({val:10d})  bytes: {b0:3d} {b1:3d} {b2:3d} {b3:3d}")

print()
print("="*70)
print("CVirtualLCD - EXAMINING THE OBJECT STRING AREA")
print("="*70)

# The string "CVirtualLCD" at 0x62e44d is interesting - it's in the .text section!
# Let's look at the area around it
loc = 0x62e430
print(f"Context around CVirtualLCD string at 0x62e44d:")
for i in range(40):
    off = loc + i*4
    val = struct.unpack_from('<I', data, off)[0]
    rva = offset_to_rva(off)
    print(f"  {off:#x} (VA {va(rva):#x}): {val:#010x} ({val})")

print()
print("="*70)
print("LOOKING FOR THE FRAMEBUFFER BLIT TO SCREEN")
print("="*70)

# The key insight: StretchDIBits takes a pointer to pixel data and draws it.
# Let's find CALL [StretchDIBits] or CALL [StretchBlt] instructions.
# These are indirect calls through the IAT: FF 15 xx xx xx xx

# First, find the IAT entries for our target functions
# The IAT is in .rdata, and the entries are resolved at load time
# But we can find the original thunks

# Actually, let's look for the import thunks (jmp [IAT]) in the .text section
# These are typically at the start or end of .text: FF 25 xx xx xx xx (jmp dword [addr])

# Let's find all FF 25 and FF 15 patterns that reference .rdata addresses
print("Looking for indirect calls/jumps to GDI32 functions...")
gdi_funcs = ['BitBlt', 'StretchBlt', 'StretchDIBits', 'CreateCompatibleDC', 'CreateCompatibleBitmap',
             'CreateBitmap', 'SelectObject', 'DeleteDC', 'DeleteObject']

# Find IAT entries by looking at import thunks
# Thunks are: FF 25 [addr] where addr points to IAT
# Let's find them by scanning for jmp [xxxx] near known function name strings

# Alternative approach: find where the function names are, trace back to IAT
for fname in gdi_funcs:
    fname_bytes = fname.encode() + b'\x00'
    for m in re.finditer(re.escape(fname_bytes), data):
        if m.start() > 0x9d0000:  # in .rdata import section area
            # Hint/Name entry: 2 bytes hint + name
            hint_rva = offset_to_rva(m.start() - 2)
            hint_va = va(hint_rva)
            # Search for pointer to this hint/name (in the ILT)
            target = struct.pack('<I', hint_va)
            for ref in re.finditer(re.escape(target), data):
                ref_rva = offset_to_rva(ref.start())
                if ref_rva:
                    # This could be ILT or IAT entry
                    # The IAT entry will be called via FF 15 [iat_va]
                    iat_va = va(ref_rva)
                    iat_bytes = struct.pack('<I', iat_va)
                    # Search for FF 15 [iat_va] (call dword ptr [iat_va])
                    call_pattern = b'\xff\x15' + iat_bytes
                    call_refs = list(re.finditer(re.escape(call_pattern), data))
                    # Search for FF 25 [iat_va] (jmp dword ptr [iat_va]) - thunk
                    jmp_pattern = b'\xff\x25' + iat_bytes
                    jmp_refs = list(re.finditer(re.escape(jmp_pattern), data))
                    if call_refs or jmp_refs:
                        print(f"\n  {fname} (IAT VA: {iat_va:#x}):")
                        for cr in call_refs:
                            cr_rva = offset_to_rva(cr.start())
                            print(f"    CALL at VA {va(cr_rva):#x} (file {cr.start():#x})")
                        for jr in jmp_refs:
                            jr_rva = offset_to_rva(jr.start())
                            print(f"    JMP thunk at VA {va(jr_rva):#x} (file {jr.start():#x})")

print()
print("="*70)
print("LOOKING FOR THE MAIN CALCULATOR LOOP")
print("="*70)

# The calc core likely has a main loop that:
# 1. Processes key events
# 2. Updates internal state
# 3. Renders to CVirtualLCD
# 4. Signals the UI to refresh
#
# Look for strings that indicate the main loop / initialization

loop_strings = [b'main_loop', b'MainLoop', b'main loop', b'calc_loop', b'Run(',
                b'Initialize', b'Init(', b'startup', b'Startup']
for ls in loop_strings:
    for m in re.finditer(re.escape(ls), data):
        rva = offset_to_rva(m.start())
        va_val = va(rva) if rva else 0
        ctx = data[m.start():min(m.start()+50, len(data))]
        ctx_clean = ctx.split(b'\x00')[0]
        print(f"  {m.start():#x} (VA {va_val:#x}): {ctx_clean}")

print()
print("="*70)
print("SHARED VTABLE FUNCTIONS BETWEEN CVirtualLCD AND CAspen_cDlg")
print("="*70)

# CVirtualLCD vtable at file 0x62e47c
# CAspen_cDlg vtable at file offset... let me find it
# From previous run: CAspen_cDlg vtable at VA 0xa2e484
# VA 0xa2e484 -> RVA 0x62e484 -> file offset
aspen_vt_rva = 0xa2e484 - image_base
aspen_vt_off = rva_to_offset(aspen_vt_rva)
lcd_vt_off = 0x62e47c  # from previous analysis

print("Comparing vtables (shared entries = inherited from common base class):")
print(f"{'Slot':>4} {'CVirtualLCD':>12} {'CAspen_cDlg':>12} {'Same?':>6}")
shared = 0
for j in range(20):
    lcd_func = struct.unpack_from('<I', data, lcd_vt_off + j*4)[0]
    asp_func = struct.unpack_from('<I', data, aspen_vt_off + j*4)[0]
    same = "YES" if lcd_func == asp_func else "no"
    if lcd_func == asp_func:
        shared += 1
    print(f"  [{j:2d}] {lcd_func:#010x}  {asp_func:#010x}  {same}")
print(f"\n{shared}/20 shared -> they share a common base class (CWnd/CDialog)")

print()
print("="*70)
print("SUMMARY: THE CALC CORE vs WINDOWS SHELL BOUNDARY")
print("="*70)
print("""
Based on analysis:

WINDOWS SHELL (to be replaced):
  - CAspen_cApp     : MFC application entry, WinMain
  - CAspen_cDlg     : Main dialog, loads skin, handles Win messages
  - CVirtualLCD     : CWnd-derived, receives the framebuffer and paints it
  - CScreenShotDlg  : Screenshot dialog
  - CAboutDlg       : About dialog

CALCULATOR CORE (to be preserved):
  - All Graphers    : FunctionGrapher, ParametricGrapher, PolarGrapher, etc.
  - All Evaluators  : FunctionEvaluator, PolarEvaluator, etc.
  - Giac/Xcas CAS   : The entire math engine
  - HP PPL interp   : GETKEY, BLIT, DIMGROB, TEXTOUT, etc.
  - UI widgets      : CChoose, CCharChooser, CTerminal, CEqw2, CMessageBox
                      (These render to the framebuffer, NOT to Windows)
  - CEQList, CStatEditor, CNumView, ABCNumView

KEY INTERFACES:
  1. FRAMEBUFFER: 256x127 pixels, likely 8-bit grayscale or 1-bit mono
     Written by calc core, read by CVirtualLCD for display
  2. KEY INPUT: Physical key codes fed into the core
  3. INDICATORS: The annunciator row (shift, alpha, etc.)
""")
