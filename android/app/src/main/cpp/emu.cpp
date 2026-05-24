// C++ port of harness/headless/load.py — PE loader + Unicorn boot for the
// HP39gII calc core. See that file (and RESEARCH_NOTES.md) for the why behind
// every magic address; this is a near-mechanical translation.
#include "emu.h"

#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <string>
#include <unordered_map>
#include <vector>

#include <unicorn/unicorn.h>

namespace {

// --- target layout (must match load.py) ----------------------------------
constexpr uint32_t IMAGE_BASE     = 0x00400000;
constexpr uint32_t CALC_THREAD_VA = 0x00406430;  // calc-core thread proc
constexpr uint32_t MAIN_LOOP_VA   = 0x00401730;  // halt here = booted

constexpr uint32_t PAGE        = 0x1000;
constexpr uint32_t STACK_BASE  = 0x00100000;
constexpr uint32_t STACK_SIZE  = 0x00080000;     // 512 KB
constexpr uint32_t TIB_BASE    = 0x00200000;
constexpr uint32_t TIB_SIZE    = PAGE;
constexpr uint32_t HEAP_BASE   = 0x10000000;
constexpr uint32_t HEAP_SIZE   = 0x04000000;     // 64 MB bump arena
constexpr uint32_t TRAMP_BASE  = 0x20000000;     // one slot per import
constexpr uint32_t TRAMP_SIZE  = 0x00010000;
constexpr uint32_t GDT_BASE    = 0x00300000;
constexpr uint32_t GDT_SIZE    = PAGE;
constexpr uint32_t SENTINEL_RET = 0xDEADBEEF;    // fake ret addr -> halt

// Reported as the module path to the guest (kept Windows-shaped on purpose).
constexpr const char *MODULE_PATH = "C:\\HP39gII.exe";

constexpr int VERBOSE_PER_NAME = 3;

uint32_t page_round_up(uint32_t n) { return (n + PAGE - 1) & ~(PAGE - 1); }

// --- minimal PE structures (NDK has no windows.h) -------------------------
#pragma pack(push, 1)
struct DosHeader { uint16_t e_magic; uint8_t pad[58]; uint32_t e_lfanew; };
struct FileHeader {
    uint16_t Machine, NumberOfSections;
    uint32_t TimeDateStamp, PointerToSymbolTable, NumberOfSymbols;
    uint16_t SizeOfOptionalHeader, Characteristics;
};
struct DataDir { uint32_t VirtualAddress, Size; };
struct OptHeader32 {
    uint16_t Magic; uint8_t MajorLinkerVersion, MinorLinkerVersion;
    uint32_t SizeOfCode, SizeOfInitializedData, SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint, BaseOfCode, BaseOfData, ImageBase;
    uint32_t SectionAlignment, FileAlignment;
    uint16_t MajorOSVersion, MinorOSVersion, MajorImageVersion, MinorImageVersion,
             MajorSubsystemVersion, MinorSubsystemVersion;
    uint32_t Win32VersionValue, SizeOfImage, SizeOfHeaders, CheckSum;
    uint16_t Subsystem, DllCharacteristics;
    uint32_t SizeOfStackReserve, SizeOfStackCommit, SizeOfHeapReserve,
             SizeOfHeapCommit, LoaderFlags, NumberOfRvaAndSizes;
    DataDir DataDirectory[16];
};
struct SectionHeader {
    char Name[8]; uint32_t VirtualSize, VirtualAddress, SizeOfRawData,
        PointerToRawData, PointerToRelocations, PointerToLinenumbers;
    uint16_t NumberOfRelocations, NumberOfLinenumbers; uint32_t Characteristics;
};
struct ImportDescriptor {
    uint32_t OriginalFirstThunk, TimeDateStamp, ForwarderChain, Name, FirstThunk;
};
#pragma pack(pop)

// --- boot context ---------------------------------------------------------
struct Ctx {
    uc_engine *uc = nullptr;
    uint32_t heap_ptr = HEAP_BASE;
    uint32_t next_handle = 0x80000001;
    std::string log;
    bool booted = false;
    std::unordered_map<uint32_t, std::string> tramp_to_name;  // tramp addr -> sym
    std::unordered_map<std::string, int> call_counts;

    uint32_t malloc(uint32_t n) {
        n = (n + 15) & ~15u;
        uint32_t p = heap_ptr;
        heap_ptr += n;
        std::vector<uint8_t> zero(n, 0);
        uc_mem_write(uc, p, zero.data(), n);
        return p;
    }
    uint32_t handle() { return next_handle++; }

    void line(const std::string &s) { log += s; log += '\n'; }
    // first N calls of each name print; then a one-time "[silencing]" note.
    void trace(const std::string &name, const std::string &s) {
        int c = ++call_counts[name];
        if (c <= VERBOSE_PER_NAME) line(s);
        else if (c == VERBOSE_PER_NAME + 1) line("  [silencing further " + name + " calls]");
    }
};

// guest memory helpers
uint32_t rd32(uc_engine *uc, uint32_t va) {
    uint32_t v = 0; uc_mem_read(uc, va, &v, 4); return v;
}
void wr32(uc_engine *uc, uint32_t va, uint32_t v) { uc_mem_write(uc, va, &v, 4); }

std::string read_cstr(uc_engine *uc, uint32_t va, size_t max = 128) {
    std::string s; char ch;
    for (size_t i = 0; i < max; i++) {
        if (uc_mem_read(uc, va + i, &ch, 1) != UC_ERR_OK || ch == 0) break;
        s += ch;
    }
    return s;
}
void write_utf16(uc_engine *uc, uint32_t va, const char *ascii, uint32_t max_chars) {
    std::vector<uint8_t> b;
    for (const char *p = ascii; *p && b.size() / 2 < max_chars; p++) {
        b.push_back((uint8_t)*p); b.push_back(0);
    }
    b.push_back(0); b.push_back(0);
    if (!b.empty()) uc_mem_write(uc, va, b.data(), b.size());
}

char hexbuf[160];
const char *fmt(const char *f, ...) {
    va_list ap; va_start(ap, f); vsnprintf(hexbuf, sizeof(hexbuf), f, ap); va_end(ap);
    return hexbuf;
}

// =========================================================================
// Win32 shim. Returns stdcall arg count (for stack cleanup); sets *ret.
// args[0..7] are the 8 dwords at [esp+4..esp+32].
// =========================================================================
int shim_call(Ctx &c, const std::string &name, const uint32_t *a, uint32_t *ret) {
    uc_engine *uc = c.uc;
    auto R = [&](uint32_t v, int argc) { *ret = v; return argc; };

    // --- functions with side effects or non-zero returns -----------------
    if (name == "SetUnhandledExceptionFilter") {
        c.line(fmt("  SetUnhandledExceptionFilter(0x%08x) -> 0", a[0])); return R(0, 1);
    }
    if (name == "CreateMutexW") {
        uint32_t h = c.handle();
        c.line(fmt("  CreateMutexW(sec=0x%x, owned=%u, name=0x%x) -> handle 0x%x", a[0], a[1], a[2], h));
        return R(h, 3);
    }
    if (name == "CreateMutexA") return R(c.handle(), 3);
    if (name == "CreateFileW" || name == "CreateFileA")   return R(0xFFFFFFFF, 7);
    if (name == "GetFileAttributesW" || name == "GetFileAttributesA") return R(0xFFFFFFFF, 1);
    if (name == "GetEnvironmentVariableW") { write_utf16(uc, a[1], "C:\\fake", a[2]); return R(6, 3); }
    if (name == "GetEnvironmentVariableA") return R(0, 3);
    if (name == "RegOpenKeyExW" || name == "RegOpenKeyExA") return R(2, 5);
    if (name == "RegQueryValueExW") return R(2, 6);
    if (name == "RegCloseKey")      return R(0, 1);
    if (name == "CreateThread") {
        uint32_t h = c.handle();
        c.line(fmt("  CreateThread(start=0x%x, param=0x%x, flags=0x%x) -> handle 0x%x (stubbed)", a[2], a[3], a[4], h));
        if (a[5]) wr32(uc, a[5], 0x2000 + (h & 0xFF));
        return R(h, 6);
    }
    if (name == "WaitForSingleObject")    return R(0, 2);
    if (name == "WaitForMultipleObjects") return R(0, 4);
    if (name == "SetEvent" || name == "ResetEvent") return R(1, 1);
    if (name == "CloseHandle") return R(1, 1);
    if (name == "CreateEventW") {
        uint32_t h = c.handle();
        c.line(fmt("  CreateEventW(sec=0x%x, manual=%u, init=%u, name=0x%x) -> handle 0x%x", a[0], a[1], a[2], a[3], h));
        return R(h, 4);
    }
    if (name == "CreateEventA") return R(c.handle(), 4);
    if (name == "InitializeCriticalSection")  return R(0, 1);
    if (name == "InitializeCriticalSectionAndSpinCount") return R(1, 2);
    if (name == "EnterCriticalSection")  return R(0, 1);
    if (name == "LeaveCriticalSection")  return R(0, 1);
    if (name == "DeleteCriticalSection") return R(0, 1);
    if (name == "GetLastError") return R(0, 0);
    if (name == "SetLastError") return R(0, 1);
    if (name == "GetCurrentThreadId")  return R(0x1234, 0);
    if (name == "GetCurrentProcessId") return R(0xC4, 0);
    if (name == "GetCurrentProcess")   return R(0xFFFFFFFF, 0);
    if (name == "GetTickCount")  return R(0, 0);
    if (name == "GetVersion")    return R(0x06000001, 0);
    if (name == "GetVersionExA" || name == "GetVersionExW") return R(1, 1);
    if (name == "Sleep") return R(0, 1);
    if (name == "GetModuleHandleW" || name == "GetModuleHandleA") return R(IMAGE_BASE, 1);
    if (name == "GetModuleFileNameA") {
        std::string p = MODULE_PATH; if (p.size() + 1 > a[2]) p.resize(a[2] ? a[2] - 1 : 0);
        uc_mem_write(uc, a[1], p.c_str(), p.size() + 1);
        return R((uint32_t)p.size(), 3);
    }
    if (name == "GetModuleFileNameW") {
        write_utf16(uc, a[1], MODULE_PATH, a[2]);
        return R((uint32_t)strlen(MODULE_PATH), 3);
    }
    if (name == "GetProcAddress") return R(0, 2);
    if (name == "TlsAlloc") { uint32_t i = c.next_handle++ & 0x3F; return R(i, 0); }
    if (name == "TlsGetValue") return R(0, 1);
    if (name == "TlsSetValue") return R(1, 2);
    if (name == "TlsFree")     return R(1, 1);
    if (name == "FlsAlloc")    return R(c.next_handle++ & 0x3F, 1);
    if (name == "FlsGetValue") return R(0, 1);
    if (name == "FlsSetValue") return R(1, 2);
    if (name == "FlsFree")     return R(1, 1);
    if (name == "EncodePointer" || name == "DecodePointer") return R(a[0], 1);
    if (name == "IsProcessorFeaturePresent") return R(0, 1);
    if (name == "IsDebuggerPresent")         return R(0, 0);
    if (name == "QueryPerformanceCounter")  { uint64_t z = 0; uc_mem_write(uc, a[0], &z, 8); return R(1, 1); }
    if (name == "GetSystemTimeAsFileTime")  { uint64_t z = 0; uc_mem_write(uc, a[0], &z, 8); return R(0, 1); }
    if (name == "InterlockedIncrement") { uint32_t v = rd32(uc, a[0]) + 1; wr32(uc, a[0], v); return R(v, 1); }
    if (name == "InterlockedDecrement") { uint32_t v = rd32(uc, a[0]) - 1; wr32(uc, a[0], v); return R(v, 1); }
    if (name == "InterlockedExchange")  { uint32_t old = rd32(uc, a[0]); wr32(uc, a[0], a[1]); return R(old, 2); }
    if (name == "HeapAlloc")      return R(c.malloc(a[2]), 3);
    if (name == "HeapFree")       return R(1, 3);
    if (name == "HeapCreate")     return R(c.handle(), 3);
    if (name == "GetProcessHeap") return R(0x80001000, 0);
    if (name == "malloc")  return R(c.malloc(a[0]), 1);
    if (name == "free")    return R(0, 1);
    if (name == "calloc")  return R(c.malloc(a[0] * a[1]), 2);
    if (name == "realloc") return R(c.malloc(a[1]), 2);
    if (name == "_msize")  return R(0, 1);
    if (name == "memset")  { std::vector<uint8_t> b(a[2], (uint8_t)a[1]); if (a[2]) uc_mem_write(uc, a[0], b.data(), a[2]); return R(a[0], 3); }
    if (name == "memcpy")  { if (a[2]) { std::vector<uint8_t> b(a[2]); uc_mem_read(uc, a[1], b.data(), a[2]); uc_mem_write(uc, a[0], b.data(), a[2]); } return R(a[0], 3); }

    // --- unhandled: clean the stack with the right stdcall arg count ------
    static const std::unordered_map<std::string, int> STDCALL_ARGC = {
        {"LoadLibraryA",1},{"LoadLibraryW",1},{"FreeLibrary",1},
        {"ExitProcess",1},{"TerminateProcess",2},{"UnhandledExceptionFilter",1},
        {"GetStartupInfoW",1},{"GetStartupInfoA",1},
        {"GetCommandLineA",0},{"GetCommandLineW",0},
        {"GetEnvironmentStringsW",0},{"FreeEnvironmentStringsW",1},
        {"GetStdHandle",1},{"GetFileType",1},{"SetHandleCount",1},
        {"WriteFile",5},{"ReadFile",5},
        {"GetCurrentDirectoryW",2},{"SetCurrentDirectoryW",1},
        {"GetCPInfo",2},{"GetACP",0},{"GetOEMCP",0},
        {"MultiByteToWideChar",6},{"WideCharToMultiByte",8},
        {"LCMapStringW",6},{"LCMapStringA",6},
        {"GetStringTypeW",4},{"GetStringTypeA",5},
        {"IsValidCodePage",1},{"IsValidLocale",2},
        {"GetLocaleInfoW",4},{"GetLocaleInfoA",4},
        {"GetUserDefaultLCID",0},{"GetThreadLocale",0},
        {"GlobalAlloc",2},{"GlobalFree",1},{"GlobalLock",1},{"GlobalUnlock",1},
        {"VirtualAlloc",4},{"VirtualFree",3},{"VirtualProtect",4},{"VirtualQuery",3},
        {"RtlUnwind",4},{"RaiseException",4},
        {"OutputDebugStringA",1},{"OutputDebugStringW",1},
        {"FormatMessageA",7},{"FormatMessageW",7},
        {"GetSystemInfo",1},{"GetComputerNameW",2},
        {"FindFirstFileA",2},{"FindFirstFileW",2},{"FindNextFileW",2},{"FindClose",1},
        {"DeleteFileA",1},{"DeleteFileW",1},
        {"CreateDirectoryW",2},{"CreateDirectoryA",2},
        {"RemoveDirectoryW",1},{"RemoveDirectoryA",1},
        {"RegQueryValueExA",6},{"RegSetValueExW",6},{"RegSetValueExA",6},
        {"RegCreateKeyExW",9},{"RegCreateKeyExA",9},
        {"RegDeleteValueW",2},{"RegDeleteValueA",2},
        {"HidD_GetHidGuid",1},{"HidD_GetPreparsedData",2},{"HidD_FreePreparsedData",1},
        {"HidD_GetAttributes",2},{"HidD_GetManufacturerString",3},{"HidD_GetProductString",3},
        {"HidP_GetCaps",2},
        {"SetupDiGetClassDevsW",4},{"SetupDiGetClassDevsA",4},
        {"SetupDiEnumDeviceInterfaces",5},
        {"SetupDiGetDeviceInterfaceDetailW",6},{"SetupDiGetDeviceInterfaceDetailA",6},
        {"SetupDiDestroyDeviceInfoList",1},
        {"PostMessageW",4},{"SendMessageW",4},
    };
    auto it = STDCALL_ARGC.find(name);
    int argc = (it != STDCALL_ARGC.end()) ? it->second : 0;
    c.trace(name, fmt("  ?? %s(args~=[%u, %u]) -> 0  argc=%d%s", name.c_str(),
                      a[0], a[1], argc, it != STDCALL_ARGC.end() ? "" : "  [argc=?, CDECL]"));
    return R(0, argc);
}

// --- internal (calc-side) function replacements, by VA --------------------
// Returns true if handled; sets *ret. These are cdecl (caller cleans args).
bool internal_call(Ctx &c, uint32_t va, const uint32_t *a, uint32_t *ret) {
    switch (va) {
        case 0x00944630: *ret = 0; c.trace("stub_FUN_00944630", "  [internal] stub_FUN_00944630 -> 0"); return true; // font-metric NULL-deref guard
        case 0x009618ae: *ret = c.malloc(a[0]); c.trace("calc_malloc",  fmt("  [internal] calc_malloc(%u) -> 0x%x",  a[0], *ret)); return true;
        case 0x00972c50: *ret = c.malloc(a[0]); c.trace("msvcrt_malloc", fmt("  [internal] msvcrt_malloc(%u) -> 0x%x", a[0], *ret)); return true;
        case 0x009721a0: *ret = 0;              c.trace("msvcrt_free", "  [internal] msvcrt_free -> 0"); return true;
        case 0x009729e6: { // realloc: fresh alloc + copy up to min(new,4096) from old
            if (a[0] == 0) { *ret = c.malloc(a[1]); return true; }
            uint32_t p = c.malloc(a[1]); uint32_t n = a[1] < 4096 ? a[1] : 4096;
            std::vector<uint8_t> b(n);
            if (uc_mem_read(c.uc, a[0], b.data(), n) == UC_ERR_OK) uc_mem_write(c.uc, p, b.data(), n);
            *ret = p; c.trace("msvcrt_realloc", fmt("  [internal] msvcrt_realloc(0x%x, %u) -> 0x%x", a[0], a[1], p)); return true;
        }
        default: return false;
    }
}

// =========================================================================
// The single code hook: sentinel / main-loop / internal hooks / IAT tramps
// =========================================================================
void on_code(uc_engine *uc, uint64_t address, uint32_t /*size*/, void *user) {
    Ctx &c = *reinterpret_cast<Ctx *>(user);
    uint32_t addr = (uint32_t)address;

    if (addr == SENTINEL_RET) {
        c.line("\n[halt] hit sentinel return address -- calc thread returned cleanly");
        uc_emu_stop(uc); return;
    }
    if (addr == MAIN_LOOP_VA) {
        c.line("\n[halt] reached main-loop entry FUN_00401730 -- calc booted");
        c.booted = true; uc_emu_stop(uc); return;
    }

    uint32_t esp = 0; uc_reg_read(uc, UC_X86_REG_ESP, &esp);
    uint32_t ret_addr = rd32(uc, esp);
    uint32_t a[8]; uc_mem_read(uc, esp + 4, a, 32);

    uint32_t ret = 0;
    if (internal_call(c, addr, a, &ret)) {            // cdecl: pop ret only
        uc_reg_write(uc, UC_X86_REG_EAX, &ret);
        uint32_t nesp = esp + 4; uc_reg_write(uc, UC_X86_REG_ESP, &nesp);
        uc_reg_write(uc, UC_X86_REG_EIP, &ret_addr);
        return;
    }
    if (addr >= TRAMP_BASE && addr < TRAMP_BASE + TRAMP_SIZE) {  // stdcall import
        auto it = c.tramp_to_name.find(addr);
        std::string name = it != c.tramp_to_name.end() ? it->second : fmt("tramp_0x%x", addr);
        int argc = shim_call(c, name, a, &ret);
        uint32_t nesp = esp + 4 + argc * 4;
        uc_reg_write(uc, UC_X86_REG_ESP, &nesp);
        uc_reg_write(uc, UC_X86_REG_EAX, &ret);
        uc_reg_write(uc, UC_X86_REG_EIP, &ret_addr);
    }
}

void on_unmapped(uc_engine *uc, uc_mem_type, uint64_t address, int size, int64_t, void *user) {
    Ctx &c = *reinterpret_cast<Ctx *>(user);
    uint32_t eip = 0; uc_reg_read(uc, UC_X86_REG_EIP, &eip);
    c.line(fmt("\n[fault] unmapped access at 0x%llx (size %d) from EIP=0x%x",
               (unsigned long long)address, size, eip));
}

// --- PE load + import/trampoline table ------------------------------------
uint64_t gdt_entry(uint32_t base, uint32_t limit, uint8_t access, uint8_t flags) {
    return (uint64_t)(limit & 0xFFFF)
         | ((uint64_t)(base & 0xFFFFFF) << 16)
         | ((uint64_t)access << 40)
         | ((uint64_t)((limit >> 16) & 0xF) << 48)
         | ((uint64_t)(flags & 0xF) << 52)
         | ((uint64_t)((base >> 24) & 0xFF) << 56);
}

void setup_fs_segment(uc_engine *uc) {
    uc_mem_map(uc, TIB_BASE, TIB_SIZE, UC_PROT_ALL);
    wr32(uc, TIB_BASE + 0x00, 0xFFFFFFFF);                 // SEH chain head
    wr32(uc, TIB_BASE + 0x04, STACK_BASE + STACK_SIZE);
    wr32(uc, TIB_BASE + 0x08, STACK_BASE);
    wr32(uc, TIB_BASE + 0x18, TIB_BASE);                   // self ptr

    uc_mem_map(uc, GDT_BASE, GDT_SIZE, UC_PROT_ALL);
    uint64_t entries[4] = {
        0,
        gdt_entry(0, 0xFFFFF, 0x9A, 0xC),                  // code
        gdt_entry(0, 0xFFFFF, 0x92, 0xC),                  // data
        gdt_entry(TIB_BASE, TIB_SIZE - 1, 0x92, 0x4),      // fs -> TIB
    };
    for (int i = 0; i < 4; i++) uc_mem_write(uc, GDT_BASE + i * 8, &entries[i], 8);

    uc_x86_mmr gdtr{}; gdtr.base = GDT_BASE; gdtr.limit = 4 * 8 - 1;
    uc_reg_write(uc, UC_X86_REG_GDTR, &gdtr);
    uint32_t cs = 1 << 3, data = 2 << 3, fs = 3 << 3;
    uc_reg_write(uc, UC_X86_REG_CS, &cs);
    uc_reg_write(uc, UC_X86_REG_SS, &data);
    uc_reg_write(uc, UC_X86_REG_DS, &data);
    uc_reg_write(uc, UC_X86_REG_ES, &data);
    uc_reg_write(uc, UC_X86_REG_GS, &data);
    uc_reg_write(uc, UC_X86_REG_FS, &fs);
}

}  // namespace

std::string hp39_boot(const uint8_t *exe, size_t len) {
    Ctx c;
    uc_err err = uc_open(UC_ARCH_X86, UC_MODE_32, &c.uc);
    if (err != UC_ERR_OK) return std::string("uc_open failed: ") + uc_strerror(err);
    uc_engine *uc = c.uc;

    // sandbox regions
    uc_mem_map(uc, STACK_BASE, STACK_SIZE, UC_PROT_ALL);
    uc_mem_map(uc, HEAP_BASE, HEAP_SIZE, UC_PROT_ALL);
    uc_mem_map(uc, TRAMP_BASE, TRAMP_SIZE, UC_PROT_ALL);

    // --- parse PE headers from the raw buffer ---
    if (len < sizeof(DosHeader)) { uc_close(uc); return "exe too small"; }
    const DosHeader *dos = reinterpret_cast<const DosHeader *>(exe);
    if (dos->e_magic != 0x5A4D) { uc_close(uc); return "not a PE (no MZ)"; }
    uint32_t pe_off = dos->e_lfanew;
    const uint32_t *sig = reinterpret_cast<const uint32_t *>(exe + pe_off);
    if (*sig != 0x00004550) { uc_close(uc); return "not a PE (no PE00)"; }
    const FileHeader *fh = reinterpret_cast<const FileHeader *>(exe + pe_off + 4);
    const OptHeader32 *oh = reinterpret_cast<const OptHeader32 *>(exe + pe_off + 4 + sizeof(FileHeader));
    uint32_t image_size = page_round_up(oh->SizeOfImage);

    uc_mem_map(uc, IMAGE_BASE, image_size, UC_PROT_ALL);
    uc_mem_write(uc, IMAGE_BASE, exe, oh->SizeOfHeaders);  // DOS/NT/section table

    const SectionHeader *sec = reinterpret_cast<const SectionHeader *>(
        exe + pe_off + 4 + sizeof(FileHeader) + fh->SizeOfOptionalHeader);
    for (int i = 0; i < fh->NumberOfSections; i++) {
        const SectionHeader &s = sec[i];
        if (s.SizeOfRawData && (size_t)s.PointerToRawData + s.SizeOfRawData <= len)
            uc_mem_write(uc, IMAGE_BASE + s.VirtualAddress, exe + s.PointerToRawData, s.SizeOfRawData);
        // BSS (VirtualSize > SizeOfRawData) is already zero from mem_map.
    }

    // --- walk imports (from mapped guest memory) -> trampolines ---
    uint32_t imp_rva = oh->DataDirectory[1].VirtualAddress;
    uint32_t next_tramp = TRAMP_BASE;
    int n_imports = 0, n_dlls = 0;
    for (uint32_t d = imp_rva; ; d += sizeof(ImportDescriptor)) {
        ImportDescriptor desc; uc_mem_read(uc, IMAGE_BASE + d, &desc, sizeof(desc));
        if (desc.OriginalFirstThunk == 0 && desc.FirstThunk == 0) break;
        n_dlls++;
        uint32_t int_rva = desc.OriginalFirstThunk ? desc.OriginalFirstThunk : desc.FirstThunk;
        uint32_t iat_va  = IMAGE_BASE + desc.FirstThunk;
        for (uint32_t k = 0; ; k++) {
            uint32_t thunk = rd32(uc, IMAGE_BASE + int_rva + k * 4);
            if (thunk == 0) break;
            std::string sym;
            if (thunk & 0x80000000u) sym = fmt("ord%u", thunk & 0xFFFF);
            else sym = read_cstr(uc, IMAGE_BASE + thunk + 2);   // skip Hint word
            c.tramp_to_name[next_tramp] = sym;
            wr32(uc, iat_va + k * 4, next_tramp);               // patch IAT slot
            next_tramp += 0x10;
            n_imports++;
        }
    }

    setup_fs_segment(uc);
    uc_hook h1, h2;
    uc_hook_add(uc, &h1, UC_HOOK_CODE, (void *)on_code, &c, 1, 0);
    uc_hook_add(uc, &h2, UC_HOOK_MEM_UNMAPPED, (void *)on_unmapped, &c, 1, 0);

    c.line(fmt("[load] image 0x%x..0x%x (%u KB)", IMAGE_BASE, IMAGE_BASE + image_size, image_size / 1024));
    c.line(fmt("[load] imports: %d functions across %d DLLs", n_imports, n_dlls));

    // Plant a dummy CAspen_cDlg-like object so FUN_00406430's HWND-bridge step
    // reads zero instead of faulting on NULL. (MFC sets this normally.)
    uint32_t dummy_dlg = c.malloc(0x400);
    wr32(uc, 0x00DEB7E4, dummy_dlg);
    c.line(fmt("[boot] planted dummy dialog at 0x%x (DAT_00DEB7E4)", dummy_dlg));
    // Non-zero perf frequency so _aulldiv doesn't divide by zero.
    uint64_t one = 1; uc_mem_write(uc, 0x00DFDCA8, &one, 8);
    c.line("[boot] set perf frequency at DAT_00DFDCA8 = 1");

    // thread call stack: push arg(NULL), push sentinel ret addr
    uint32_t esp = STACK_BASE + STACK_SIZE - 0x100;
    esp -= 4; wr32(uc, esp, 0);
    esp -= 4; wr32(uc, esp, SENTINEL_RET);
    uc_reg_write(uc, UC_X86_REG_ESP, &esp);
    uint32_t ebp = 0; uc_reg_write(uc, UC_X86_REG_EBP, &ebp);

    c.line("\n[run] starting at FUN_00406430 (calc-core thread)\n");
    err = uc_emu_start(uc, CALC_THREAD_VA, 0, 10ULL * 1000000, 2000000);
    if (err != UC_ERR_OK && !c.booted) {
        uint32_t eip = 0; uc_reg_read(uc, UC_X86_REG_EIP, &eip);
        c.line(fmt("\n[error] %s at EIP=0x%x", uc_strerror(err), eip));
    }

    uint32_t fin_eip = 0, fin_esp = 0;
    uc_reg_read(uc, UC_X86_REG_EIP, &fin_eip);
    uc_reg_read(uc, UC_X86_REG_ESP, &fin_esp);
    c.line(fmt("\n[stop] EIP=0x%x ESP=0x%x", fin_eip, fin_esp));
    c.line(fmt("[stop] heap consumed: %u bytes", c.heap_ptr - HEAP_BASE));
    uc_close(uc);
    return c.log;
}
