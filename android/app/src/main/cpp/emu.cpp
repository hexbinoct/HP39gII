// C++ port of harness/headless/load.py — PE loader + Unicorn boot for the
// HP39gII calc core. See that file (and RESEARCH_NOTES.md) for the why behind
// every magic address; this is a near-mechanical translation.
#include "emu.h"

#include <cctype>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <string>
#include <unordered_map>
#include <vector>

#include <sys/stat.h>   // mkdir/stat — back the guest filesystem with real files

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
constexpr uint32_t SENTINEL_RET = 0xDEADBEEF;    // boot thread ret addr -> halt

// Second sentinel: return address pushed when the host calls into emulated
// code (call_emu). Must be mapped so Unicorn can fetch a byte there.
constexpr uint32_t SENTINEL_HOST_RET = 0x21000000;

// Calc-internal function VAs (verified against Ghidra; image is non-ASLR).
constexpr uint32_t FN_ENQUEUE_EVENT = 0x00941210;  // __thiscall(ecx=queue, evt, payload)
constexpr uint32_t FN_PRESS_KEY     = 0x0043BE90;  // __cdecl(keycode)
constexpr uint32_t FN_RELEASE_KEY   = 0x0043BED0;  // __cdecl(keycode)
constexpr uint32_t FN_TICK          = 0x00944270;  // __fastcall(ecx=state) process+repaint
constexpr uint32_t FN_DRAIN_QUEUE   = 0x00942310;  // __thiscall(ecx=queue, arg)

constexpr uint32_t ADDR_EVENT_QUEUE = 0x00DECA08;  // -> queue object
constexpr uint32_t ADDR_HOST_BRIDGE = 0x00DECA00;  // -> host bridge struct
constexpr uint32_t ADDR_STATE       = 0x00DEC9F8;  // -> CDesktop root
constexpr uint32_t STATE_FB_PTR_OFS = 0x14;
constexpr uint32_t FB_BYTES         = 10922;       // 86 bytes/row * 127 rows
constexpr uint32_t FB_PITCH         = 86;

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

    // --- guest filesystem (so the calc can create/read its own aplet data) ---
    // Without this the calc never builds its apps' runtime state and Symb/Plot/
    // Num NULL-deref. fs_root is a real persistent dir (the app's filesDir);
    // open_files maps a Win32 HANDLE to the backing stdio stream.
    std::string fs_root;
    std::unordered_map<uint32_t, FILE *> open_files;

    bool quiet = false;  // true after boot: stop appending the verbose trace

    void line(const std::string &s) { if (!quiet) { log += s; log += '\n'; } }
    // first N calls of each name print; then a one-time "[silencing]" note.
    void trace(const std::string &name, const std::string &s) {
        if (quiet) return;
        int c = ++call_counts[name];
        if (c <= VERBOSE_PER_NAME) line(s);
        else if (c == VERBOSE_PER_NAME + 1) line("  [silencing further " + name + " calls]");
    }
};

// Persistent VM: boot once, then inject keys / read framebuffer across JNI calls.
Ctx *g = nullptr;

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
// Guest filesystem helpers. The calc stores each aplet's state in a file
// under %APPDATA% (which we report as "C:\fake"). We map that tree onto a
// real directory (fs_root) so CreateFile/Read/Write actually persist.
// =========================================================================
constexpr uint32_t INVALID_HANDLE = 0xFFFFFFFF;
constexpr uint32_t GENERIC_WRITE  = 0x40000000;

// Read a NUL-terminated UTF-16LE string from guest memory as UTF-8.
std::string read_wstr(uc_engine *uc, uint32_t va, size_t max = 300) {
    std::string s;
    for (size_t i = 0; i < max; i++) {
        uint16_t ch = 0;
        if (uc_mem_read(uc, va + i * 2, &ch, 2) != UC_ERR_OK || ch == 0) break;
        if (ch < 0x80) {
            s += (char)ch;
        } else if (ch < 0x800) {
            s += (char)(0xC0 | (ch >> 6));
            s += (char)(0x80 | (ch & 0x3F));
        } else {
            s += (char)(0xE0 | (ch >> 12));
            s += (char)(0x80 | ((ch >> 6) & 0x3F));
            s += (char)(0x80 | (ch & 0x3F));
        }
    }
    return s;
}

// "C:\fake\HP39gII\&function.hpapp" -> "<fs_root>/HP39gII/&function.hpapp".
std::string guest_to_real(Ctx &c, std::string p) {
    for (char &ch : p) if (ch == '\\') ch = '/';
    // strip the reported APPDATA prefix (case-insensitive), else any "C:/".
    auto strip = [&](const char *pre) -> bool {
        size_t n = strlen(pre);
        if (p.size() < n) return false;
        for (size_t i = 0; i < n; i++)
            if (tolower((unsigned char)p[i]) != tolower((unsigned char)pre[i])) return false;
        p = p.substr(n);
        return true;
    };
    if (!strip("c:/fake")) strip("c:");
    if (!p.empty() && p[0] != '/') p = "/" + p;
    return c.fs_root + p;
}

// mkdir -p for the parent directories of a real path (under fs_root).
void ensure_parent_dirs(const std::string &real) {
    size_t pos = real.find('/', 1);
    while (pos != std::string::npos) {
        std::string dir = real.substr(0, pos);
        mkdir(dir.c_str(), 0775);   // ignore EEXIST
        pos = real.find('/', pos + 1);
    }
}

bool file_exists(const std::string &real) {
    struct stat st;
    return stat(real.c_str(), &st) == 0;
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
    if (name == "CreateFileW") {
        std::string real = guest_to_real(c, read_wstr(uc, a[0]));
        uint32_t disp = a[4];                 // 1=NEW 2=ALWAYS 3=EXISTING 4=OPEN_ALWAYS 5=TRUNC
        bool exists = file_exists(real);
        const char *mode = nullptr;
        switch (disp) {
            case 3: if (!exists) { c.trace("CreateFileW", fmt("  CreateFileW('%s', OPEN_EXISTING) -> NOT FOUND", real.c_str())); return R(INVALID_HANDLE, 7); }
                    mode = (a[1] & GENERIC_WRITE) ? "rb+" : "rb"; break;
            case 1: if (exists) return R(INVALID_HANDLE, 7); mode = "wb+"; break;
            case 5: if (!exists) return R(INVALID_HANDLE, 7); mode = "wb+"; break;
            case 2: mode = "wb+"; break;
            case 4: mode = exists ? "rb+" : "wb+"; break;
            default: mode = exists ? "rb+" : "wb+"; break;
        }
        ensure_parent_dirs(real);
        FILE *fp = fopen(real.c_str(), mode);
        if (!fp) return R(INVALID_HANDLE, 7);
        uint32_t h = c.handle();
        c.open_files[h] = fp;
        c.trace("CreateFileW", fmt("  CreateFileW('%s', disp=%u) -> handle 0x%x", real.c_str(), disp, h));
        return R(h, 7);
    }
    if (name == "CreateFileA") return R(INVALID_HANDLE, 7);
    if (name == "ReadFile") {
        auto it = c.open_files.find(a[0]);
        if (it == c.open_files.end()) return R(0, 5);
        std::vector<uint8_t> buf(a[2]);
        size_t got = a[2] ? fread(buf.data(), 1, a[2], it->second) : 0;
        if (got) uc_mem_write(uc, a[1], buf.data(), got);
        if (a[3]) wr32(uc, a[3], (uint32_t)got);    // lpNumberOfBytesRead
        return R(1, 5);
    }
    if (name == "WriteFile") {
        auto it = c.open_files.find(a[0]);
        if (it == c.open_files.end()) { if (a[3]) wr32(uc, a[3], 0); return R(0, 5); }
        std::vector<uint8_t> buf(a[2]);
        if (a[2]) uc_mem_read(uc, a[1], buf.data(), a[2]);
        size_t put = a[2] ? fwrite(buf.data(), 1, a[2], it->second) : 0;
        fflush(it->second);
        if (a[3]) wr32(uc, a[3], (uint32_t)put);    // lpNumberOfBytesWritten
        return R(1, 5);
    }
    if (name == "SetFilePointer") {
        auto it = c.open_files.find(a[0]);
        if (it == c.open_files.end()) return R(INVALID_HANDLE, 4);
        int32_t dist = (int32_t)a[1];
        int whence = a[3] == 1 ? SEEK_CUR : a[3] == 2 ? SEEK_END : SEEK_SET;
        fseek(it->second, dist, whence);
        return R((uint32_t)ftell(it->second), 4);
    }
    if (name == "GetFileSize") {
        auto it = c.open_files.find(a[0]);
        if (it == c.open_files.end()) return R(INVALID_HANDLE, 2);
        long cur = ftell(it->second);
        fseek(it->second, 0, SEEK_END);
        long sz = ftell(it->second);
        fseek(it->second, cur, SEEK_SET);
        if (a[1]) wr32(uc, a[1], 0);                // high dword
        return R((uint32_t)sz, 2);
    }
    if (name == "CreateDirectoryW") {
        std::string real = guest_to_real(c, read_wstr(uc, a[0]));
        ensure_parent_dirs(real + "/.");
        mkdir(real.c_str(), 0775);
        return R(1, 2);
    }
    if (name == "DeleteFileW") {
        remove(guest_to_real(c, read_wstr(uc, a[0])).c_str());
        return R(1, 1);
    }
    if (name == "GetFileAttributesW") {
        std::string real = guest_to_real(c, read_wstr(uc, a[0]));
        struct stat st;
        if (stat(real.c_str(), &st) != 0) return R(INVALID_HANDLE, 1);  // INVALID_FILE_ATTRIBUTES
        return R(S_ISDIR(st.st_mode) ? 0x10u : 0x80u, 1);               // DIRECTORY : NORMAL
    }
    if (name == "GetFileAttributesA") return R(INVALID_HANDLE, 1);
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
    // ReleaseMutex(hMutex): 1 stdcall arg. Without an explicit handler it falls
    // through to the argc=0 default, leaking its arg on the stack -> ESP drift
    // that corrupts the caller's RET. Only the modal "wait for key" path
    // (FUN_00401670, reached via e.g. F5) calls it, so arithmetic/ON looked fine
    // while F5 jumped to EIP=0 and wedged the VM.
    if (name == "ReleaseMutex") return R(1, 1);
    if (name == "SetEvent" || name == "ResetEvent") return R(1, 1);
    if (name == "CloseHandle") {
        auto it = c.open_files.find(a[0]);
        if (it != c.open_files.end()) { fclose(it->second); c.open_files.erase(it); }
        return R(1, 1);
    }
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
        case 0x00944630: { // FUN_00944630: size a widget's {top,height} from the current font.
            // Faithful reimpl. Decompiled logic:
            //   sel  = FUN_00942490(widget)   // 1=small, 2=large, else host_bridge[+0x584]
            //   font = (&PTR_00C18D00)[sel-1]  // decrement-with-wrap (FUN_00935660/680)
            //   h    = font[0]                 // first byte of font record = line height
            //   widget[+8] = screen_height - h - 0x11 ; widget[+0x10] = h + 1
            // The original NULL-derefs when no font is loaded (host_bridge[+0x584]=0 makes
            // the index wrap to a wild table[] entry). We previously no-op'd it, which is
            // exactly why the edit-line region collapsed to ~4px and clipped typed glyphs to
            // their tops. The system fonts ARE embedded in .rdata at static table 0xC18D00:
            //   index 1 -> table[0] line-height 12 (small), index 2 -> table[1] h=16 (large).
            // Reimplement faithfully, reading those real heights, with every pointer guarded.
            uc_engine *u = c.uc;
            uint32_t widget = 0; uc_reg_read(u, UC_X86_REG_ECX, &widget);
            uint32_t flags = rd32(u, widget + 0x2c);
            uint32_t sel;
            if ((flags >> 0xc) & 1) sel = 1;
            else if ((flags >> 0xd) & 1) sel = 2;
            // Default path: host_bridge[+0x584] is the default font index. On a real
            // boot it's the h=16 font (2); during our boot it's still 0 when this
            // fires (our +0x584=2 hack runs post-boot), so fall back to 2 to match the
            // native edit-line height (separator row 94 instead of a cramped 98).
            else { uint32_t b = rd32(u, ADDR_HOST_BRIDGE); uint32_t v = b ? rd32(u, b + 0x584) : 2; sel = v ? v : 2; }
            uint32_t idx;
            if (sel == 0) { uint32_t b = rd32(u, ADDR_HOST_BRIDGE); uint32_t cnt = b ? rd32(u, b + 0x584) : 1; if (!cnt) cnt = 1; idx = cnt - 1; }
            else idx = sel - 1;
            if (idx > 1) idx = 1;  // only table[0]/table[1] are real embedded fonts
            uint32_t font_ptr = rd32(u, 0x00C18D00 + idx * 4);
            uint32_t height = 16;
            if (font_ptr) { uint8_t h = 0; if (uc_mem_read(u, font_ptr, &h, 1) == UC_ERR_OK && h) height = h; }
            uint32_t state = rd32(u, ADDR_STATE);
            uint32_t screen_h = state ? rd32(u, state + 0x10) : 127;
            if (screen_h == 0) screen_h = 127;
            wr32(u, widget + 8, screen_h - height - 0x11);
            wr32(u, widget + 0x10, height + 1);
            *ret = 0;
            c.trace("fix_FUN_00944630", fmt("  [internal] fix_FUN_00944630 widget=0x%x h=%u top=%u", widget, height, screen_h - height - 0x11));
            return true;
        }
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

    if (addr == SENTINEL_HOST_RET) {  // host call_emu returned
        uc_emu_stop(uc); return;
    }
    if (addr == SENTINEL_RET) {
        c.line("\n[halt] hit sentinel return address -- calc thread returned cleanly");
        uc_emu_stop(uc); return;
    }
    if (addr == MAIN_LOOP_VA && !c.booted) {  // only halt the initial boot here
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

std::string hp39_boot(const uint8_t *exe, size_t len, const char *data_dir) {
    if (g) { if (g->uc) uc_close(g->uc); delete g; }   // re-boot resets the VM
    g = new Ctx();
    Ctx &c = *g;
    c.fs_root = (data_dir && *data_dir) ? data_dir : "/data/local/tmp/hp39gii";
    mkdir(c.fs_root.c_str(), 0775);   // the persistent store the calc writes its apps into
    uc_err err = uc_open(UC_ARCH_X86, UC_MODE_32, &c.uc);
    if (err != UC_ERR_OK) return std::string("uc_open failed: ") + uc_strerror(err);
    uc_engine *uc = c.uc;

    // sandbox regions
    uc_mem_map(uc, STACK_BASE, STACK_SIZE, UC_PROT_ALL);
    uc_mem_map(uc, HEAP_BASE, HEAP_SIZE, UC_PROT_ALL);
    uc_mem_map(uc, TRAMP_BASE, TRAMP_SIZE, UC_PROT_ALL);
    uc_mem_map(uc, SENTINEL_HOST_RET & ~0xFFFu, PAGE, UC_PROT_ALL);
    uint8_t ret_op = 0xC3; uc_mem_write(uc, SENTINEL_HOST_RET, &ret_op, 1);

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

    // Post-boot fixup: host_bridge[+0x584] is the default FONT INDEX (normally set
    // when fonts load from calc.settings, which we stub). Left at 0 it makes
    // FUN_00935660's decrement-with-wrap underflow to 0xFFFFFFFF and crash the widget
    // sizer (FUN_00944630). System fonts are embedded in .rdata (table @0xC18D00):
    // index 1 -> h=12 (small), index 2 -> h=16 (large). Native sizes default-path
    // widgets with the height-16 font, so set the default index to 2 to match.
    if (c.booted) {
        uint32_t bridge = rd32(uc, ADDR_HOST_BRIDGE);
        wr32(uc, bridge + 0x584, 2);
        c.line("[boot] set host_bridge[+0x584] = 2 (default font index -> embedded h=16 font)");
    }
    c.quiet = true;  // keep the VM live; stop accumulating the verbose trace
    return c.log;
}

bool hp39_booted() { return g && g->booted; }

namespace {

// Call into emulated code from the host (mirrors m3's call_emu). Pushes args
// right-to-left, then the host sentinel; sets ECX; runs until the sentinel is
// hit. Callees clean their own args (stdcall/fastcall) or not (cdecl) — we do
// NOT restore ESP, exactly like the Python harness.
uint32_t call_emu(Ctx &c, uint32_t fn, uint32_t ecx, const uint32_t *args, int nargs) {
    uc_engine *uc = c.uc;
    uint32_t esp = 0; uc_reg_read(uc, UC_X86_REG_ESP, &esp);
    for (int i = nargs - 1; i >= 0; i--) { esp -= 4; wr32(uc, esp, args[i]); }
    esp -= 4; wr32(uc, esp, SENTINEL_HOST_RET);
    uc_reg_write(uc, UC_X86_REG_ESP, &esp);
    uc_reg_write(uc, UC_X86_REG_ECX, &ecx);
    uc_emu_start(uc, fn, 0, 5ULL * 1000000, 10000000);
    uint32_t eax = 0; uc_reg_read(uc, UC_X86_REG_EAX, &eax);
    return eax;
}

// What the main loop does after a wake: pre-drain state-flag fixups, then
// drain the event queue and repaint.
void drain_and_tick(Ctx &c) {
    uc_engine *uc = c.uc;
    uint32_t queue  = rd32(uc, ADDR_EVENT_QUEUE);
    uint32_t bridge = rd32(uc, ADDR_HOST_BRIDGE);
    uint32_t arg    = rd32(uc, bridge + 0x20);
    uint32_t state  = rd32(uc, ADDR_STATE);

    uint32_t f2c = rd32(uc, state + 0x2c); wr32(uc, state + 0x2c, f2c & 0xfffffbffu);
    uint32_t f90 = rd32(uc, state + 0x90); if (!(f90 & 0x10)) wr32(uc, state + 0x90, f90 | 0x10);

    uint32_t a1 = arg;       call_emu(c, FN_DRAIN_QUEUE, queue, &a1, 1);
    uint32_t a0 = 0;         call_emu(c, FN_TICK,        state, &a0, 1);
}

}  // namespace

void hp39_inject_key(int keycode) {
    if (!g || !g->booted) return;
    Ctx &c = *g;
    uc_engine *uc = c.uc;

    // 16-byte event payload: type=1 at [0], keycode at [4].
    uint32_t payload = c.malloc(16);
    uint8_t evt[16] = {0}; evt[0] = 1; evt[4] = (uint8_t)keycode;
    uc_mem_write(uc, payload, evt, 16);

    uint32_t queue = rd32(uc, ADDR_EVENT_QUEUE);
    uint32_t enq[2] = {0, payload};      call_emu(c, FN_ENQUEUE_EVENT, queue, enq, 2);
    uint32_t kc = (uint32_t)keycode;
    call_emu(c, FN_PRESS_KEY, 0, &kc, 1);
    drain_and_tick(c);
    call_emu(c, FN_RELEASE_KEY, 0, &kc, 1);
    drain_and_tick(c);
}

bool hp39_get_framebuffer(uint8_t *out) {
    if (!g || !g->booted) return false;
    uc_engine *uc = g->uc;
    uint32_t state  = rd32(uc, ADDR_STATE);
    uint32_t fb_ptr = rd32(uc, state + STATE_FB_PTR_OFS);
    std::vector<uint8_t> fb(FB_BYTES);
    if (uc_mem_read(uc, fb_ptr, fb.data(), FB_BYTES) != UC_ERR_OK) return false;

    // 3 pixels packed per byte (3+3+2 bits); displayed level = bits >> 1 (0..3).
    // Map 0..3 -> 0/85/170/255 for an 8-bit grayscale bitmap.
    static const uint8_t LUT[4] = {0, 85, 170, 255};
    for (int row = 0; row < HP39_FB_H; row++) {
        const uint8_t *rd = &fb[row * FB_PITCH];
        uint8_t *wr = &out[row * HP39_FB_W];
        for (int bi = 0; bi < FB_PITCH; bi++) {
            int x = bi * 3; uint8_t b = rd[bi];
            if (x < HP39_FB_W)     wr[x]     = LUT[((b >> 5) & 7) >> 1];
            if (x + 1 < HP39_FB_W) wr[x + 1] = LUT[((b >> 2) & 7) >> 1];
            if (x + 2 < HP39_FB_W) wr[x + 2] = LUT[((b << 1) & 7) >> 1];
        }
    }
    return true;
}
