import sys, struct, re
sys.stdout.reconfigure(errors='replace')

with open('F:/ru/myprojects/april/calc/HP39gII.exe', 'rb') as f:
    data = f.read()

pe_offset = struct.unpack_from('<I', data, 0x3C)[0]
image_base = struct.unpack_from('<I', data, pe_offset + 24 + 28)[0]
entry_rva = struct.unpack_from('<I', data, pe_offset + 24 + 16)[0]
entry_va = image_base + entry_rva
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

def va_to_offset(v):
    return rva_to_offset(v - image_base)

def offset_to_va(off):
    for name, vaddr, vsize, rawptr, rawsize in sections:
        if rawptr <= off < rawptr + rawsize:
            return image_base + vaddr + (off - rawptr)
    return None

text_start = sections[0][3]
text_size = sections[0][4]
text_end = text_start + text_size

print("="*70)
print("PART 1: ENTRY POINT AND STARTUP")
print("="*70)
print(f"Entry point VA: {entry_va:#x} (RVA: {entry_rva:#x})")
entry_off = rva_to_offset(entry_rva)
print(f"Entry point file offset: {entry_off:#x}")

# Dump entry point code
print(f"\nEntry point code:")
for i in range(8):
    off = entry_off + i * 16
    va_val = offset_to_va(off)
    line_bytes = data[off:off+16]
    hex_str = ' '.join(f'{b:02x}' for b in line_bytes)
    print(f"  {va_val:#010x}: {hex_str}")

print()
print("="*70)
print("PART 2: ALL FF 15 (CALL [IAT]) INSTRUCTIONS - ACTUAL WINDOWS API CALLS")
print("="*70)

# Build IAT -> function name mapping
# Parse import directory to build complete IAT mapping
import_rva = struct.unpack_from('<I', data, pe_offset + 24 + 96 + 8)[0]

def read_string_at(offset):
    end = data.index(b'\x00', offset)
    return data[offset:end].decode('ascii', errors='replace')

iat_map = {}  # IAT VA -> (dll_name, func_name)
pos = rva_to_offset(import_rva)
while True:
    ilt_rva = struct.unpack_from('<I', data, pos)[0]
    name_rva = struct.unpack_from('<I', data, pos+12)[0]
    iat_rva = struct.unpack_from('<I', data, pos+16)[0]
    if ilt_rva == 0 and name_rva == 0:
        break
    dll_name = read_string_at(rva_to_offset(name_rva))
    # Parse IAT entries
    lookup_rva = ilt_rva if ilt_rva != 0 else iat_rva
    ilt_pos = rva_to_offset(lookup_rva)
    iat_pos_rva = iat_rva
    idx = 0
    while True:
        entry = struct.unpack_from('<I', data, ilt_pos)[0]
        if entry == 0:
            break
        iat_entry_va = image_base + iat_pos_rva + idx * 4
        if entry & 0x80000000:
            func_name = f"Ordinal_{entry & 0xFFFF}"
        else:
            hint_offset = rva_to_offset(entry)
            func_name = read_string_at(hint_offset + 2)
        iat_map[iat_entry_va] = (dll_name, func_name)
        ilt_pos += 4
        idx += 1
    pos += 20

# Now scan for FF 15 xx xx xx xx patterns
print(f"\nTotal IAT entries mapped: {len(iat_map)}")

api_call_counts = {}
api_call_sites = {}
for pos in range(text_start, text_end - 6):
    if data[pos] == 0xFF and data[pos+1] == 0x15:
        target_va = struct.unpack_from('<I', data, pos+2)[0]
        if target_va in iat_map:
            dll, fname = iat_map[target_va]
            key = f"{dll}:{fname}"
            api_call_counts[key] = api_call_counts.get(key, 0) + 1
            if key not in api_call_sites:
                api_call_sites[key] = []
            if len(api_call_sites[key]) < 5:
                api_call_sites[key].append(offset_to_va(pos))

total_api_calls = sum(api_call_counts.values())
print(f"Total FF 15 [IAT] calls found: {total_api_calls}")

print(f"\nAll Windows API calls sorted by frequency:")
for key, count in sorted(api_call_counts.items(), key=lambda x: -x[1]):
    sites_str = ', '.join(f'{s:#x}' for s in api_call_sites[key][:3])
    print(f"  {count:5d}x  {key:50s}  e.g. {sites_str}")

print()
print("="*70)
print("PART 3: CATEGORIZING API CALLS BY IMPORTANCE")
print("="*70)

# Group by what they do
categories = {
    'MEMORY (must stub)': ['HeapAlloc', 'HeapFree', 'HeapReAlloc', 'HeapSize', 'HeapCreate',
                           'GlobalAlloc', 'GlobalFree', 'GlobalLock', 'GlobalUnlock', 'GlobalReAlloc',
                           'GlobalHandle', 'GlobalFlags', 'LocalAlloc', 'LocalFree', 'LocalReAlloc',
                           'VirtualAlloc', 'VirtualFree', 'VirtualProtect', 'VirtualQuery',
                           'GetProcessHeap'],
    'THREADING (must stub)': ['CreateThread', 'Sleep', 'WaitForSingleObject', 'WaitForMultipleObjects',
                              'EnterCriticalSection', 'LeaveCriticalSection', 'InitializeCriticalSection',
                              'InitializeCriticalSectionAndSpinCount', 'DeleteCriticalSection',
                              'CreateEventW', 'SetEvent', 'CreateMutexW', 'ReleaseMutex',
                              'InterlockedIncrement', 'InterlockedDecrement', 'InterlockedExchange',
                              'TlsAlloc', 'TlsFree', 'TlsGetValue', 'TlsSetValue',
                              'GetCurrentThreadId', 'GetCurrentThread'],
    'DISPLAY/GDI (stub/redirect)': ['BitBlt', 'StretchBlt', 'StretchDIBits', 'CreateCompatibleDC',
                                     'CreateCompatibleBitmap', 'CreateBitmap', 'SelectObject',
                                     'DeleteDC', 'DeleteObject', 'GetDeviceCaps', 'GetObjectW',
                                     'SetBkColor', 'SetTextColor', 'TextOutW', 'ExtTextOutW',
                                     'CreateSolidBrush', 'CreatePen', 'Rectangle', 'GetStockObject',
                                     'SaveDC', 'RestoreDC', 'InvertRgn', 'SetMapMode',
                                     'SetViewportExtEx', 'SetViewportOrgEx', 'SetWindowExtEx',
                                     'OffsetViewportOrgEx', 'ScaleViewportExtEx', 'ScaleWindowExtEx',
                                     'PtVisible', 'RectVisible', 'GetClipBox', 'CreatePolygonRgn',
                                     'CreateRoundRectRgn', 'Escape'],
    'WINDOW/MSG (stub/redirect)': ['CreateWindowExW', 'DestroyWindow', 'ShowWindow', 'UpdateWindow',
                                    'InvalidateRect', 'ValidateRect', 'BeginPaint', 'EndPaint',
                                    'GetDC', 'ReleaseDC', 'GetClientRect', 'GetWindowRect',
                                    'MoveWindow', 'SetWindowPos', 'SetWindowLongW', 'GetWindowLongW',
                                    'PeekMessageW', 'GetMessageW', 'TranslateMessage', 'DispatchMessageW',
                                    'PostMessageW', 'SendMessageW', 'DefWindowProcW',
                                    'RegisterClassW', 'UnregisterClassW',
                                    'SetTimer', 'KillTimer', 'GetKeyState',
                                    'SetFocus', 'GetFocus', 'SetActiveWindow', 'GetActiveWindow',
                                    'EnableWindow', 'IsWindow', 'IsWindowVisible', 'IsWindowEnabled',
                                    'GetParent', 'GetWindow', 'GetTopWindow',
                                    'GetSystemMetrics', 'GetSysColor', 'GetSysColorBrush',
                                    'LoadCursorW', 'LoadIconW', 'SetCursor'],
    'FILE I/O (may need)': ['CreateFileW', 'CreateFileA', 'ReadFile', 'WriteFile', 'CloseHandle',
                             'FindFirstFileW', 'FindNextFileW', 'FindClose',
                             'SetFilePointer', 'SetEndOfFile', 'FlushFileBuffers',
                             'GetFullPathNameW', 'DeleteFileW', 'DeleteFileA',
                             'CreateDirectoryW', 'GetCurrentDirectoryA'],
    'STRING/LOCALE (easy stub)': ['MultiByteToWideChar', 'WideCharToMultiByte',
                                   'CompareStringA', 'CompareStringW', 'GetACP', 'GetOEMCP',
                                   'GetCPInfo', 'IsValidCodePage', 'GetStringTypeA', 'GetStringTypeW',
                                   'LCMapStringA', 'LCMapStringW',
                                   'GetLocaleInfoA', 'GetLocaleInfoW', 'IsValidLocale',
                                   'lstrcmpA', 'lstrcmpW', 'lstrcpyW', 'lstrcatW', 'lstrlenA', 'lstrlenW',
                                   'wsprintfW'],
    'CAN STUB/IGNORE': ['GetVersion', 'GetVersionExA', 'GetVersionExW',
                         'GetModuleHandleA', 'GetModuleHandleW', 'GetModuleFileNameA', 'GetModuleFileNameW',
                         'GetCommandLineW', 'GetStartupInfoA', 'GetStartupInfoW',
                         'GetLastError', 'SetLastError', 'SetErrorMode',
                         'GetTickCount', 'QueryPerformanceCounter', 'QueryPerformanceFrequency',
                         'GetSystemTimeAsFileTime', 'GetSystemInfo',
                         'ExitProcess', 'TerminateProcess', 'GetCurrentProcess', 'GetCurrentProcessId',
                         'IsDebuggerPresent', 'SetUnhandledExceptionFilter', 'UnhandledExceptionFilter',
                         'RtlUnwind', 'RaiseException',
                         'FreeLibrary', 'LoadLibraryA', 'LoadLibraryW', 'LoadLibraryExW', 'GetProcAddress',
                         'FreeResource', 'LoadResource', 'LockResource', 'SizeofResource',
                         'FindResourceW', 'EnumResourceLanguagesW',
                         'GetPrivateProfileIntW', 'WritePrivateProfileStringW',
                         'MulDiv'],
}

for cat_name, funcs in categories.items():
    cat_total = 0
    cat_funcs = []
    for key, count in api_call_counts.items():
        dll, fname = key.split(':', 1)
        if fname in funcs:
            cat_total += count
            cat_funcs.append((fname, count, dll))
    if cat_funcs:
        print(f"\n  [{cat_name}] — {cat_total} total calls")
        for fname, count, dll in sorted(cat_funcs, key=lambda x: -x[1]):
            print(f"    {count:5d}x  {fname}")

# What's left uncategorized?
all_categorized = set()
for funcs in categories.values():
    all_categorized.update(funcs)

print(f"\n  [UNCATEGORIZED]")
for key, count in sorted(api_call_counts.items(), key=lambda x: -x[1]):
    dll, fname = key.split(':', 1)
    if fname not in all_categorized:
        print(f"    {count:5d}x  {key}")

print()
print("="*70)
print("PART 4: THE FRAMEBUFFER - StretchDIBits CALL SITES")
print("="*70)

# Find all StretchDIBits calls and dump context
for key, sites in api_call_sites.items():
    if 'StretchDIBits' in key or 'BitBlt' in key or 'StretchBlt' in key:
        print(f"\n{key} call sites:")
        # Get ALL sites for this function
        all_sites = []
        for pos in range(text_start, text_end - 6):
            if data[pos] == 0xFF and data[pos+1] == 0x15:
                target_va = struct.unpack_from('<I', data, pos+2)[0]
                if target_va in iat_map:
                    d, f = iat_map[target_va]
                    fkey = f"{d}:{f}"
                    if fkey == key:
                        all_sites.append(pos)

        for site_off in all_sites:
            site_va = offset_to_va(site_off)
            print(f"\n  Call at VA {site_va:#x}:")
            # Dump 128 bytes before the call to see argument setup
            start = site_off - 128
            for line_off in range(start, site_off + 8, 16):
                va_val = offset_to_va(line_off)
                line_bytes = data[line_off:line_off+16]
                hex_str = ' '.join(f'{b:02x}' for b in line_bytes)
                marker = " <-- CALL" if line_off <= site_off < line_off + 16 else ""
                print(f"    {va_val:#010x}: {hex_str}{marker}")

print()
print("="*70)
print("PART 5: THE GLOBAL STATE AT 0x00DEC9F8 - FIELD ANALYSIS")
print("="*70)

# Analyze what offsets from 0xDEC9F8 are accessed
# Pattern: mov reg, [0xDEC9F8] followed by mov reg, [reg+offset]
# Or: mov reg, ds:[0xDEC9F8]
fb_ptr_bytes = struct.pack('<I', 0x00DEC9F8)
field_accesses = {}

for m in re.finditer(re.escape(fb_ptr_bytes), data[:text_end]):
    pos = m.start()
    # Look ahead for field access: typically next few instructions access [reg+offset]
    # After "mov ecx/eax/edx, [0xDEC9F8]", look for [reg+xx] patterns
    window = data[pos+4:pos+30]
    # Look for 8b xx xx patterns (mov reg, [reg+disp8]) = 8b [mod=01] [r/m] [disp8]
    for i in range(len(window)-2):
        if window[i] == 0x8b:
            modrm = window[i+1]
            mod = (modrm >> 6) & 3
            if mod == 1:  # disp8
                disp = window[i+2]
                field_accesses[disp] = field_accesses.get(disp, 0) + 1
            elif mod == 2:  # disp32
                if i+5 < len(window):
                    disp = struct.unpack_from('<I', window, i+2)[0]
                    if disp < 0x1000:  # reasonable field offset
                        field_accesses[disp] = field_accesses.get(disp, 0) + 1

print("Fields accessed on the global calc state object (offset: access count):")
for offset, count in sorted(field_accesses.items()):
    if count >= 2:
        print(f"  +{offset:#06x} ({offset:4d}): accessed {count} times")
