import sys, struct
sys.stdout.reconfigure(errors='replace')

with open('F:/ru/myprojects/april/calc/HP39gII.exe', 'rb') as f:
    data = f.read()

# Parse PE to extract import table
pe_offset = struct.unpack_from('<I', data, 0x3C)[0]
optional_hdr_offset = pe_offset + 24
magic = struct.unpack_from('<H', data, optional_hdr_offset)[0]
print(f"PE Magic: {magic:#x} ({'PE32' if magic == 0x10b else 'PE32+'})")

image_base = struct.unpack_from('<I', data, optional_hdr_offset + 28)[0]
print(f"Image base: {image_base:#x}")

# Number of data directory entries
num_dd = struct.unpack_from('<I', data, optional_hdr_offset + 92)[0]

# Import table is data directory entry 1
import_rva = struct.unpack_from('<I', data, optional_hdr_offset + 96 + 8)[0]
import_size = struct.unpack_from('<I', data, optional_hdr_offset + 96 + 12)[0]
print(f"Import directory RVA: {import_rva:#x}, size: {import_size:#x}")

# Parse sections to build RVA->file offset mapping
num_sections = struct.unpack_from('<H', data, pe_offset + 6)[0]
section_offset = pe_offset + 0xF8
sections = []
for i in range(num_sections):
    off = section_offset + i * 40
    name = data[off:off+8].rstrip(b'\x00').decode('ascii', errors='replace')
    vsize = struct.unpack_from('<I', data, off+8)[0]
    vaddr = struct.unpack_from('<I', data, off+12)[0]
    rawsize = struct.unpack_from('<I', data, off+16)[0]
    rawptr = struct.unpack_from('<I', data, off+20)[0]
    sections.append((name, vaddr, vsize, rawptr, rawsize))

def rva_to_offset(rva):
    for name, vaddr, vsize, rawptr, rawsize in sections:
        if vaddr <= rva < vaddr + rawsize:
            return rawptr + (rva - vaddr)
    return None

def read_string(offset):
    end = data.index(b'\x00', offset)
    return data[offset:end].decode('ascii', errors='replace')

# Parse import directory
print("\n" + "="*70)
print("COMPLETE IMPORT TABLE")
print("="*70)

all_imports = {}
total_funcs = 0
pos = rva_to_offset(import_rva)
while True:
    ilt_rva = struct.unpack_from('<I', data, pos)[0]
    timestamp = struct.unpack_from('<I', data, pos+4)[0]
    forwarder = struct.unpack_from('<I', data, pos+8)[0]
    name_rva = struct.unpack_from('<I', data, pos+12)[0]
    iat_rva = struct.unpack_from('<I', data, pos+16)[0]

    if ilt_rva == 0 and name_rva == 0:
        break

    dll_name = read_string(rva_to_offset(name_rva))
    functions = []

    # Parse ILT (Import Lookup Table)
    lookup_rva = ilt_rva if ilt_rva != 0 else iat_rva
    ilt_pos = rva_to_offset(lookup_rva)
    while True:
        entry = struct.unpack_from('<I', data, ilt_pos)[0]
        if entry == 0:
            break
        if entry & 0x80000000:  # Import by ordinal
            functions.append(f"Ordinal_{entry & 0xFFFF}")
        else:
            hint_offset = rva_to_offset(entry)
            hint = struct.unpack_from('<H', data, hint_offset)[0]
            func_name = read_string(hint_offset + 2)
            functions.append(func_name)
        ilt_pos += 4

    all_imports[dll_name] = functions
    total_funcs += len(functions)
    pos += 20

# Print organized by DLL with categories
categories = {
    'DISPLAY/GDI (need shim)': [],
    'WINDOW/UI (need shim)': [],
    'MEMORY/PROCESS (easy shim)': [],
    'FILE I/O (easy shim)': [],
    'THREADING (moderate shim)': [],
    'HID/DEVICE (may not need)': [],
    'OTHER (assess)': [],
}

gdi_kw = ['bit','blt','bitmap','brush','pen','font','text','draw','paint','dc','gdi','color','rgb',
           'pixel','region','clip','path','fill','stroke','select','object','delete','create',
           'stretch','device','display','palette','dib','scan','graphic','image']
ui_kw = ['window','wnd','message','msg','menu','dialog','dlg','button','scroll','class','caption',
         'cursor','caret','icon','child','parent','client','rect','invalidate','update','show',
         'move','size','focus','capture','timer','clipboard','keyboard','key','char',
         'dispatch','translate','peek','get','post','send','def','register','unregister',
         'enable','disable','adjust','map','screen','monitor','system','metrics','load','resource']
mem_kw = ['heap','alloc','free','virtual','memory','global','local','process','module','library',
          'proc','address','handle','close','exit','terminate','environment','command','error',
          'critical','section','interlocked','tls','fiber','except','unhandled']
file_kw = ['file','read','write','create','open','close','find','directory','path','volume',
           'drive','mapping','view','flush','seek','set','get','lock','unlock','move','copy','delete','temp']
thread_kw = ['thread','event','mutex','semaphore','wait','sleep','signal','critical','sync',
             'create','resume','suspend','priority']

for dll_name in sorted(all_imports.keys()):
    functions = all_imports[dll_name]
    print(f"\n--- {dll_name} ({len(functions)} functions) ---")
    for fn in sorted(functions):
        print(f"  {fn}")

print(f"\n{'='*70}")
print(f"SUMMARY")
print(f"{'='*70}")
print(f"Total DLLs: {len(all_imports)}")
print(f"Total imported functions: {total_funcs}")
for dll_name in sorted(all_imports.keys()):
    print(f"  {dll_name}: {len(all_imports[dll_name])} functions")

# Categorize the effort
print(f"\n{'='*70}")
print(f"EFFORT ANALYSIS FOR ANDROID SHIM")
print(f"{'='*70}")

print("\n[CRITICAL - Display pipeline]")
print("These are the functions that get pixels on screen:")
for dll in ['GDI32.dll', 'gdiplus.dll']:
    if dll in all_imports:
        for fn in sorted(all_imports[dll]):
            print(f"  {dll}: {fn}")

print("\n[CRITICAL - Window/Input pipeline]")
print("These handle the window and user input:")
for dll in ['USER32.dll', 'USER32.DLL']:
    if dll in all_imports:
        for fn in sorted(all_imports[dll]):
            print(f"  {dll}: {fn}")

print("\n[MODERATE - System services]")
for dll in ['KERNEL32.dll', 'ADVAPI32.dll']:
    if dll in all_imports:
        print(f"  {dll}: {len(all_imports[dll])} functions (memory, files, threads, registry)")

print("\n[LOW PRIORITY - Can stub/ignore]")
for dll in ['OLEACC.dll', 'OLEAUT32.dll', 'ole32.dll', 'SHELL32.dll', 'SHLWAPI.dll',
            'COMCTL32.dll', 'VERSION.dll', 'SETUPAPI.dll', 'HID.DLL', 'HPUpdateCheck.dll']:
    if dll in all_imports:
        print(f"  {dll}: {len(all_imports[dll])} functions - likely can return stub/no-op")

# Also check for HID usage - that's the USB connection to physical calc
print(f"\n{'='*70}")
print(f"HID.DLL IMPORTS (USB connection to physical calc - not needed)")
print(f"{'='*70}")
if 'HID.DLL' in all_imports:
    for fn in all_imports['HID.DLL']:
        print(f"  {fn}")
