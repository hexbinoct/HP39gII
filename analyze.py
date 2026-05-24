import sys, re, struct
sys.stdout.reconfigure(errors='replace')

with open('F:/ru/myprojects/april/calc/HP39gII.exe', 'rb') as f:
    data = f.read()

print(f"=== EXE size: {len(data)} bytes ({len(data)/1024/1024:.1f} MB) ===")
print()

# Parse PE headers to understand sections
pe_offset = struct.unpack_from('<I', data, 0x3C)[0]
print(f"PE header at: {pe_offset:#x}")
num_sections = struct.unpack_from('<H', data, pe_offset + 6)[0]
print(f"Number of sections: {num_sections}")
print()

section_offset = pe_offset + 0xF8  # after optional header for PE32
print("Sections:")
for i in range(num_sections):
    off = section_offset + i * 40
    name = data[off:off+8].rstrip(b'\x00').decode('ascii', errors='replace')
    vsize = struct.unpack_from('<I', data, off+8)[0]
    vaddr = struct.unpack_from('<I', data, off+12)[0]
    rawsize = struct.unpack_from('<I', data, off+16)[0]
    rawptr = struct.unpack_from('<I', data, off+20)[0]
    chars = struct.unpack_from('<I', data, off+36)[0]
    flags = []
    if chars & 0x20: flags.append('CODE')
    if chars & 0x40: flags.append('INIT_DATA')
    if chars & 0x80: flags.append('UNINIT_DATA')
    if chars & 0x20000000: flags.append('EXEC')
    if chars & 0x40000000: flags.append('READ')
    if chars & 0x80000000: flags.append('WRITE')
    print(f"  {name:8s} VA:{vaddr:#010x} VSize:{vsize:#010x} Raw:{rawptr:#010x} RawSize:{rawsize:#010x} [{','.join(flags)}]")

print()

# Check for embedded ARM code
# ARM vector table typically starts with stack pointer value followed by reset vector
# For Cortex-M (like i.MX233), vectors are thumb addresses
print("=== Looking for embedded firmware/ARM signatures ===")

# Check for Freescale i.MX23 SB file format (starts with 'STMP')
stmp_positions = [m.start() for m in re.finditer(b'STMP', data)]
if stmp_positions:
    print(f"STMP (i.MX23 boot image) signatures: {len(stmp_positions)} at {[hex(p) for p in stmp_positions[:5]]}")

# Check for common firmware signatures
for sig_name, sig in [('ELF', b'\x7fELF'), ('PKzip', b'PK\x03\x04'), ('7z', b'7z\xBC\xAF'), ('LZMA', b'\x5d\x00\x00')]:
    positions = [m.start() for m in re.finditer(re.escape(sig), data)]
    if positions:
        print(f"{sig_name}: {len(positions)} occurrences, first at {hex(positions[0])}")

# Count zlib streams (might indicate compressed resources)
zlib_positions = [m.start() for m in re.finditer(b'\x78\x9c', data)]
print(f"Possible zlib streams: {len(zlib_positions)}")

print()
print("=== HP 39gII specific commands/functions found ===")
hp_cmds = set()
# Look specifically for HP PPL programming language commands
ppl_pattern = re.compile(b'(GETKEY|PIXON|PIXOFF|FREEZE|MSGBOX|CHOOSE|EDITMAT|STARTVIEW|STARTAPP|DRAWMENU|BLIT|DIMGROB|GROBW|GROBH|SUBGROB|TEXTOUT|MAKEMAT|EDITLIST|WAIT|BEEP|MOUSE|PRINT|DISPLAY|RECT|LINE|ARC|INPUT|RETURN|LOCAL|EXPORT|KILL|IF|THEN|ELSE|FOR|NEXT|WHILE|REPEAT|UNTIL|CASE|DEFAULT|IFERR|BREAK|CONTINUE)(?:_P)?(?=\x00|[^A-Za-z])')
for match in ppl_pattern.finditer(data):
    hp_cmds.add(match.group().decode('ascii'))
print(f"HP PPL commands found: {sorted(hp_cmds)}")

print()
print("=== Giac/Xcas version info ===")
for match in re.finditer(b'[\x20-\x7e]{4,}', data):
    s = match.group().decode('ascii')
    if 'giac' in s.lower() and ('version' in s.lower() or 'copyright' in s.lower() or re.search(r'\d+\.\d+', s)):
        print(f"  {s[:150]}")

print()
print("=== Key UI/App strings (HP 39gII specific) ===")
ui_keywords = ['Home', 'Function', 'Parametric', 'Polar', 'Sequence', 'Statistics', 'Solve', 'Finance', 'Linear Solver',
               'Triangle Solver', 'Inference', 'Explorer', 'Spreadsheet',
               'Symbolic View', 'Plot View', 'Numeric View', 'Note',
               'Sketch', 'Program', 'App Library', 'Toolbox', 'Math',
               'CAS', 'Catalog', 'Menu', 'Vars', 'Memory']
found_ui = {}
for match in re.finditer(b'[\x20-\x7e]{4,}', data):
    s = match.group().decode('ascii')
    for kw in ui_keywords:
        if kw.lower() in s.lower() and len(s) < 80:
            if kw not in found_ui:
                found_ui[kw] = []
            if len(found_ui[kw]) < 3:
                found_ui[kw].append((match.start(), s))
for kw in ui_keywords:
    if kw in found_ui:
        for offset, s in found_ui[kw]:
            print(f"  {offset:#x}: {s}")

print()
print("=== DLL imports (first 50) ===")
# Look for imported DLL names
dll_pattern = re.compile(b'[A-Za-z][A-Za-z0-9_]*\.dll', re.IGNORECASE)
dlls = set()
for match in dll_pattern.finditer(data):
    dlls.add(match.group().decode('ascii'))
for d in sorted(dlls):
    print(f"  {d}")

print()
print("=== Summary analysis ===")
# Is there ARM code embedded? Check for ARM instruction density
# ARM thumb: many 2-byte instructions with common patterns
# vs x86 which has different byte frequency distributions
# Simple heuristic: check sections for ARM-like patterns
code_section = None
for i in range(num_sections):
    off = section_offset + i * 40
    name = data[off:off+8].rstrip(b'\x00').decode('ascii', errors='replace')
    if name == '.text':
        rawptr = struct.unpack_from('<I', data, off+20)[0]
        rawsize = struct.unpack_from('<I', data, off+16)[0]
        code_section = (rawptr, rawsize)
        break

if code_section:
    start, size = code_section
    # Sample some code bytes
    sample = data[start:start+1000]
    # x86 code tends to have lots of 0x8B (MOV), 0x89, 0xE8 (CALL), 0xFF, 0x83, 0x85
    x86_opcodes = sum(1 for b in sample if b in (0x8B, 0x89, 0xE8, 0xFF, 0x83, 0x85, 0x55, 0x56, 0x57, 0xC3))
    print(f".text section: {size} bytes at {start:#x}")
    print(f"x86 opcode frequency in first 1000 bytes: {x86_opcodes} (high = likely x86)")

    # Also check for potential ARM firmware blob in .rdata or .data sections
    for i in range(num_sections):
        off = section_offset + i * 40
        name = data[off:off+8].rstrip(b'\x00').decode('ascii', errors='replace')
        rawptr = struct.unpack_from('<I', data, off+20)[0]
        rawsize = struct.unpack_from('<I', data, off+16)[0]
        if name in ('.data', '.rdata') and rawsize > 1000000:
            print(f"\nLarge {name} section ({rawsize} bytes) - checking for embedded firmware...")
            section_data = data[rawptr:rawptr+rawsize]
            # Check for ARM vector table pattern at various offsets
            for check_off in range(0, min(rawsize, 100000), 0x1000):
                if check_off + 8 <= rawsize:
                    word1 = struct.unpack_from('<I', section_data, check_off)[0]
                    word2 = struct.unpack_from('<I', section_data, check_off+4)[0]
                    # Typical ARM Cortex-M vector table: SP in RAM range, reset in flash range
                    if (0x20000000 <= word1 <= 0x20100000) and (0x00000000 < word2 < 0x10000000):
                        print(f"  Possible ARM vector table at section+{check_off:#x}: SP={word1:#x} Reset={word2:#x}")
