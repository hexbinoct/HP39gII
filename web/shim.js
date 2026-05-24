// Port of harness/headless/load.py — Win32 shim + internal hooks.
// Same handlers, same arg counts, same return values. The only difference
// is JS idioms (Uint8Array <-> bytes, no Python struct module).

// All callable from JS as `handlers["FuncName"](shim, args)` -> [retVal, argc]

import {
  STACK_BASE, STACK_SIZE, HEAP_BASE, IMAGE_BASE, EXE_PATH_FAKE,
  readU32, writeU32, writeU64,
} from "./loader.js";

export class Shim {
  constructor(emu) {
    this.emu = emu;
    this.heapPtr = HEAP_BASE;
    this.nextHandle = 0x80000001;
    this.log = [];
    this.callCounts = Object.create(null);
    this.verbosePerName = 0; // suppress chatter by default
  }

  malloc(n) {
    n = (n + 15) & ~15;
    const p = this.heapPtr;
    this.heapPtr += n;
    this.emu.mem_write(p, new Uint8Array(n));  // zero
    return p >>> 0;
  }

  handle() {
    const h = this.nextHandle;
    this.nextHandle = (this.nextHandle + 1) >>> 0;
    return h;
  }

  trace(msg, name = null) {
    this.log.push(msg);
    if (this.verbosePerName <= 0) return;
    if (name === null) { console.log(msg); return; }
    const c = (this.callCounts[name] = (this.callCounts[name] || 0) + 1);
    if (c <= this.verbosePerName) console.log(msg);
    else if (c === this.verbosePerName + 1) console.log(`  [silencing further ${name} calls]`);
  }
}

// Handler signature: (shim, args:[number]) -> [returnValue:number, stdcallArgCount:number]
export const HANDLERS = {};
export const HANDLER_ARGC = {};   // mirror table for trampoline-emit time
function reg(name, argc, fn) {
  HANDLERS[name] = (shim, args) => [fn(shim, args.slice(0, argc)) >>> 0, argc];
  HANDLER_ARGC[name] = argc;
}

// --- KERNEL32 basics ---
reg("SetUnhandledExceptionFilter", 1, (s, a) => { s.trace(`SetUnhandledExceptionFilter(0x${a[0].toString(16)}) -> 0`); return 0; });
reg("UnhandledExceptionFilter",    1, () => 0);
reg("TerminateProcess",            2, () => 0);
reg("ExitProcess",                 1, () => 0);
reg("GetLastError",                0, () => 0);
reg("SetLastError",                1, () => 0);
reg("GetCurrentThreadId",          0, () => 0x1234);
reg("GetCurrentProcessId",         0, () => 0xC4);
reg("GetCurrentProcess",           0, () => 0xFFFFFFFF);
reg("GetTickCount",                0, () => 0);
reg("GetVersion",                  0, () => 0x06000001);
reg("GetVersionExA",               1, () => 1);
reg("GetVersionExW",               1, () => 1);
reg("Sleep",                       1, () => 0);

// --- Synchronization ---
reg("CreateMutexW", 3, (s) => { const h = s.handle(); s.trace(`CreateMutexW -> 0x${h.toString(16)}`); return h; });
reg("CreateMutexA", 3, (s) => s.handle());
reg("CreateEventW", 4, (s) => { const h = s.handle(); s.trace(`CreateEventW -> 0x${h.toString(16)}`); return h; });
reg("CreateEventA", 4, (s) => s.handle());
reg("CreateThread", 6, (s, a) => {
  const h = s.handle();
  s.trace(`CreateThread(start=0x${a[2].toString(16)}, param=0x${a[3].toString(16)}) -> 0x${h.toString(16)} (not started)`);
  if (a[5]) writeU32(s.emu, a[5], 0x2000 + (h & 0xff));
  return h;
});
reg("WaitForSingleObject",      2, () => 0);
reg("WaitForMultipleObjects",   4, () => 0);
reg("SetEvent",                 1, () => 1);
reg("ResetEvent",               1, () => 1);
reg("CloseHandle",              1, () => 1);
reg("InitializeCriticalSection",          1, () => 0);
reg("InitializeCriticalSectionAndSpinCount", 2, () => 1);
reg("EnterCriticalSection",     1, () => 0);
reg("LeaveCriticalSection",     1, () => 0);
reg("DeleteCriticalSection",    1, () => 0);
reg("InterlockedIncrement", 1, (s, a) => {
  const v = (readU32(s.emu, a[0]) + 1) >>> 0;
  writeU32(s.emu, a[0], v);
  return v;
});
reg("InterlockedDecrement", 1, (s, a) => {
  const v = (readU32(s.emu, a[0]) - 1) >>> 0;
  writeU32(s.emu, a[0], v);
  return v;
});
reg("InterlockedExchange", 2, (s, a) => {
  const old = readU32(s.emu, a[0]);
  writeU32(s.emu, a[0], a[1] >>> 0);
  return old;
});

// --- Heap ---
reg("HeapAlloc",       3, (s, a) => s.malloc(a[2]));
reg("HeapFree",        3, () => 1);
reg("HeapCreate",      3, (s) => s.handle());
reg("GetProcessHeap",  0, () => 0x80001000);
reg("malloc",  1, (s, a) => s.malloc(a[0]));
reg("free",    1, () => 0);
reg("calloc",  2, (s, a) => s.malloc(a[0] * a[1]));
reg("realloc", 2, (s, a) => s.malloc(a[1]));
reg("_msize",  1, () => 0);
reg("memset", 3, (s, a) => {
  const buf = new Uint8Array(a[2]).fill(a[1] & 0xFF);
  s.emu.mem_write(a[0], buf);
  return a[0];
});
reg("memcpy", 3, (s, a) => {
  if (a[2] > 0) s.emu.mem_write(a[0], s.emu.mem_read(a[1], a[2]));
  return a[0];
});

// --- Modules / loader ---
reg("GetModuleHandleW", 1, () => IMAGE_BASE);
reg("GetModuleHandleA", 1, () => IMAGE_BASE);
reg("GetProcAddress",   2, () => 0);
reg("LoadLibraryW",     1, () => 0);
reg("LoadLibraryA",     1, () => 0);
reg("FreeLibrary",      1, () => 1);
reg("GetModuleFileNameA", 3, (s, a) => {
  const bytes = new TextEncoder().encode(EXE_PATH_FAKE + "\0");
  const n = Math.min(bytes.length, a[2]);
  s.emu.mem_write(a[1], bytes.subarray(0, n));
  return n - 1;
});
reg("GetModuleFileNameW", 3, (s, a) => {
  const str = EXE_PATH_FAKE + "\0";
  const bytes = new Uint8Array(str.length * 2);
  for (let i = 0; i < str.length; i++) bytes[i * 2] = str.charCodeAt(i) & 0xff;
  const n = Math.min(bytes.length, a[2] * 2);
  s.emu.mem_write(a[1], bytes.subarray(0, n));
  return Math.floor(n / 2) - 1;
});

// --- TLS / FLS ---
reg("TlsAlloc",     0, (s) => (s.nextHandle++ & 0x3F));
reg("TlsGetValue",  1, () => 0);
reg("TlsSetValue",  2, () => 1);
reg("TlsFree",      1, () => 1);
reg("FlsAlloc",     1, (s) => (s.nextHandle++ & 0x3F));
reg("FlsGetValue",  1, () => 0);
reg("FlsSetValue",  2, () => 1);
reg("FlsFree",      1, () => 1);
reg("EncodePointer", 1, (_, a) => a[0]);
reg("DecodePointer", 1, (_, a) => a[0]);

// --- Misc ---
reg("IsProcessorFeaturePresent", 1, () => 0);
reg("IsDebuggerPresent",         0, () => 0);
reg("QueryPerformanceCounter",   1, (s, a) => { writeU64(s.emu, a[0], 0n); return 1; });
reg("QueryPerformanceFrequency", 1, (s, a) => { writeU64(s.emu, a[0], 1n); return 1; });
reg("GetSystemTimeAsFileTime",   1, (s, a) => { writeU64(s.emu, a[0], 0n); return 0; });

// --- Files (stubbed: nothing found) ---
reg("CreateFileW",          7, () => 0xFFFFFFFF);
reg("CreateFileA",          7, () => 0xFFFFFFFF);
reg("GetFileAttributesW",   1, () => 0xFFFFFFFF);
reg("GetFileAttributesA",   1, () => 0xFFFFFFFF);
reg("GetEnvironmentVariableW", 3, (s, a) => {
  // calc indexes buffer[returned_len] — fake a short APPDATA so the index is valid
  const fake = "C:\\fake";
  const bytes = new Uint8Array((fake.length + 1) * 2);
  for (let i = 0; i < fake.length; i++) bytes[i * 2] = fake.charCodeAt(i);
  s.emu.mem_write(a[1], bytes.subarray(0, Math.min(bytes.length, a[2] * 2)));
  return fake.length;
});
reg("GetEnvironmentVariableA", 3, () => 0);

reg("RegOpenKeyExW",   5, () => 2); // ERROR_FILE_NOT_FOUND
reg("RegOpenKeyExA",   5, () => 2);
reg("RegQueryValueExW", 6, () => 2);
reg("RegCloseKey",     1, () => 0);

// Fallback argc table for unhandled stdcall callees — same purpose as
// load.py's STDCALL_ARGC: even when the handler does nothing, the arg count
// must be correct or stack drift accumulates and trips __report_gsfailure.
export const STDCALL_ARGC = Object.assign(Object.create(null), {
  // KERNEL32
  "LoadLibraryA": 1, "LoadLibraryW": 1, "FreeLibrary": 1,
  "ExitProcess": 1, "TerminateProcess": 2, "UnhandledExceptionFilter": 1,
  "GetStartupInfoW": 1, "GetStartupInfoA": 1,
  "GetCommandLineA": 0, "GetCommandLineW": 0,
  "GetEnvironmentStringsW": 0, "FreeEnvironmentStringsW": 1,
  "GetStdHandle": 1, "GetFileType": 1, "SetHandleCount": 1,
  "WriteFile": 5, "ReadFile": 5,
  "GetCurrentDirectoryW": 2, "SetCurrentDirectoryW": 1,
  "GetCPInfo": 2, "GetACP": 0, "GetOEMCP": 0,
  "MultiByteToWideChar": 6, "WideCharToMultiByte": 8,
  "LCMapStringW": 6, "LCMapStringA": 6,
  "GetStringTypeW": 4, "GetStringTypeA": 5,
  "IsValidCodePage": 1, "IsValidLocale": 2,
  "GetLocaleInfoW": 4, "GetLocaleInfoA": 4,
  "GetUserDefaultLCID": 0, "GetThreadLocale": 0,
  "GlobalAlloc": 2, "GlobalFree": 1, "GlobalLock": 1, "GlobalUnlock": 1,
  "VirtualAlloc": 4, "VirtualFree": 3, "VirtualProtect": 4, "VirtualQuery": 3,
  "RtlUnwind": 4, "RaiseException": 4,
  "OutputDebugStringA": 1, "OutputDebugStringW": 1,
  "FormatMessageA": 7, "FormatMessageW": 7,
  "GetSystemInfo": 1, "GetComputerNameW": 2,
  "FindFirstFileA": 2, "FindFirstFileW": 2, "FindNextFileW": 2, "FindClose": 1,
  "CreateFileA": 7, "CreateFileW": 7,
  "DeleteFileA": 1, "DeleteFileW": 1,
  "CreateDirectoryW": 2, "CreateDirectoryA": 2,
  "RemoveDirectoryW": 1, "RemoveDirectoryA": 1,
  "CloseHandle": 1,
  "RegOpenKeyExW": 5, "RegOpenKeyExA": 5,
  "RegQueryValueExW": 6, "RegQueryValueExA": 6,
  "RegSetValueExW": 6, "RegSetValueExA": 6,
  "RegCloseKey": 1, "RegCreateKeyExW": 9, "RegCreateKeyExA": 9,
  "RegDeleteValueW": 2, "RegDeleteValueA": 2,
  "HidD_GetHidGuid": 1, "HidD_GetPreparsedData": 2, "HidD_FreePreparsedData": 1,
  "HidD_GetAttributes": 2, "HidD_GetManufacturerString": 3, "HidD_GetProductString": 3,
  "HidP_GetCaps": 2,
  "SetupDiGetClassDevsW": 4, "SetupDiGetClassDevsA": 4,
  "SetupDiEnumDeviceInterfaces": 5,
  "SetupDiGetDeviceInterfaceDetailW": 6, "SetupDiGetDeviceInterfaceDetailA": 6,
  "SetupDiDestroyDeviceInfoList": 1,
  "PostMessageW": 4, "SendMessageW": 4,
});

// --- Internal hooks: replace calc-side functions (bypass MSVCRT) ---
// Map { va: { name, cdeclHandler(shim, args) -> retValue } }
export const INTERNAL_HOOKS = Object.create(null);
function hookInternal(va, name, fn) { INTERNAL_HOOKS[va >>> 0] = { name, fn }; }

hookInternal(0x009618ae, "calc_malloc",   (s, a) => s.malloc(a[0]));
hookInternal(0x00972c50, "msvcrt_malloc", (s, a) => s.malloc(a[0]));
hookInternal(0x009721a0, "msvcrt_free",   () => 0);
hookInternal(0x009729e6, "msvcrt_realloc", (s, a) => {
  if (a[0] === 0) return s.malloc(a[1]);
  const newP = s.malloc(a[1]);
  try {
    const copyN = Math.min(a[1], 4096);
    s.emu.mem_write(newP, s.emu.mem_read(a[0], copyN));
  } catch (_) {}
  return newP;
});
// FUN_00944630 NULL-derefs when no font is loaded; no-op it.
hookInternal(0x00944630, "stub_FUN_00944630", () => 0);
