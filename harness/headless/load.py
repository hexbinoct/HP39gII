"""
M1: PE loader + Unicorn boot for HP39gII.exe calc core.

Goal: run FUN_00406430 (the calc-core thread proc) in a Unicorn x86 sandbox
with no Windows underneath. Hook every IAT call, stub a minimum of Win32
functions, halt at the entry to the main loop FUN_00401730. Print a trace
that lets us tick off the predicted landmarks from RESEARCH_NOTES.

Run:   python harness/headless/load.py
"""
from __future__ import annotations

import os
import struct
import sys
from dataclasses import dataclass, field
from typing import Callable

import pefile
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE, UC_HOOK_MEM_UNMAPPED, UcError
from unicorn.x86_const import (
    UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDX,
    UC_X86_REG_ESP, UC_X86_REG_EBP, UC_X86_REG_EIP,
    UC_X86_REG_CS, UC_X86_REG_DS, UC_X86_REG_ES, UC_X86_REG_SS,
    UC_X86_REG_FS, UC_X86_REG_GS, UC_X86_REG_GDTR,
)

# --- target binary ---
# Locate HP39gII.exe. Override with HP39GII_EXE; otherwise try, in order:
# next to this script (Android/Termux layout), then the project root two
# levels up (Windows checkout layout: harness/headless/load.py).
def _find_exe() -> str:
    if os.environ.get("HP39GII_EXE"):
        return os.environ["HP39GII_EXE"]
    here = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        os.path.join(here, "HP39gII.exe"),
        os.path.join(here, "..", "..", "HP39gII.exe"),
    ]
    for c in candidates:
        if os.path.isfile(c):
            return os.path.abspath(c)
    return candidates[0]  # fall back to script-dir path for a clear error

EXE_PATH        = _find_exe()
IMAGE_BASE      = 0x00400000
CALC_THREAD_VA  = 0x00406430   # the "calc core thread" we drive into
MAIN_LOOP_VA    = 0x00401730   # halt before stepping into here for M1

# --- sandbox memory layout (well clear of the PE image at 0x00400000-0x00A10000) ---
PAGE            = 0x1000
STACK_BASE      = 0x00100000
STACK_SIZE      = 0x00080000        # 512 KB
TIB_BASE        = 0x00200000
TIB_SIZE        = PAGE
HEAP_BASE       = 0x10000000
HEAP_SIZE       = 0x04000000        # 64 MB bump arena
TRAMP_BASE      = 0x20000000        # one address per imported function
TRAMP_SIZE      = 0x00010000        # room for ~16K imports (we have ~360)
GDT_BASE        = 0x00300000
GDT_SIZE        = PAGE
SENTINEL_RET    = 0xDEADBEEF        # fake return address — hitting this halts emu


def page_round_up(n: int) -> int:
    return (n + PAGE - 1) & ~(PAGE - 1)


# =============================================================================
# Win32 shim — minimum surface to keep init walking past each IAT call
# =============================================================================

@dataclass
class Shim:
    """Tracks heap, handles, and an event log."""
    uc: Uc
    heap_ptr: int = HEAP_BASE
    next_handle: int = 0x80000001
    log: list[str] = field(default_factory=list)
    call_counts: dict[str, int] = field(default_factory=dict)
    verbose_per_name: int = 3  # print first N calls of each name, then go silent

    def malloc(self, n: int) -> int:
        n = (n + 15) & ~15
        p = self.heap_ptr
        self.heap_ptr += n
        self.uc.mem_write(p, b"\x00" * n)
        return p

    def handle(self) -> int:
        h = self.next_handle
        self.next_handle += 1
        return h

    def trace(self, msg: str, name: str | None = None) -> None:
        self.log.append(msg)
        if name is None:
            print(msg); return
        c = self.call_counts.get(name, 0) + 1
        self.call_counts[name] = c
        if self.verbose_per_name <= 0:
            return
        if c <= self.verbose_per_name:
            print(msg)
        elif c == self.verbose_per_name + 1:
            print(f"  [silencing further {name} calls]")


# Each handler: fn(shim, args:list[int]) -> (return_value:int, stdcall_arg_count:int)
HandlerRet = tuple[int, int]
Handler = Callable[[Shim, list[int]], HandlerRet]

HANDLERS: dict[str, Handler] = {}

# Internal hooks: replace calc-side functions (e.g. its malloc wrapper) with
# our own implementations, bypassing the binary's bundled MSVCRT entirely.
# Map VA -> (name, cdecl_handler(shim, args) -> ret_value)
INTERNAL_HOOKS: dict[int, tuple[str, Callable[[Shim, list[int]], int]]] = {}


def hook_internal(va: int, name: str):
    def wrap(fn):
        INTERNAL_HOOKS[va] = (name, fn)
        return fn
    return wrap


# FUN_00944630 sizes a widget's {top, height} from the current font. Decompiled:
#   font_sel = FUN_00942490(widget)        # 1=small, 2=large, else host_bridge[+0x584]
#   font     = (&PTR_00C18D00)[font_sel-1] # decrement-with-wrap (FUN_00935660/680)
#   h        = font[0]                      # first byte of the font record = line height
#   widget[+8]    = screen_height - h - 0x11   # top edge
#   widget[+0x10] = h + 1                       # widget height
# The ORIGINAL NULL-derefs when no font is loaded: host_bridge[+0x584]=0 makes the
# index wrap to 0xFFFFFFFF -> wild table[] entry -> crash. We previously no-op'd it,
# which is exactly why the edit-line region collapsed to ~4px and clipped typed
# glyphs to their tops. The system fonts ARE embedded in .rdata at the static table
# 0xC18D00 (table[0] line-height=12 "small", table[1] line-height=16 "large"), so we
# faithfully reimplement the real computation, reading those real heights and
# guarding every pointer so it can never fault. Result: the edit line gets its
# correct ~17px height (top=94 for the height-16 font, matching the native frame).
# fastcall: widget pointer is in ECX, no stack args.
FONT_TABLE_VA = 0x00C18D00

def _u32(uc, addr):
    try:
        return struct.unpack("<I", uc.mem_read(addr, 4))[0]
    except UcError:
        return 0

@hook_internal(0x00944630, "fix_FUN_00944630")
def _fix_944630(shim, a):
    uc = shim.uc
    widget = uc.reg_read(UC_X86_REG_ECX)
    flags = _u32(uc, widget + 0x2c)
    # FUN_00942490: choose the font selector for this widget.
    if (flags >> 0xc) & 1:
        sel = 1
    elif (flags >> 0xd) & 1:
        sel = 2
    else:
        # Default path. host_bridge[+0x584] is the default font index; on a real
        # boot it's the h=16 font (2). During OUR boot it is still 0 at the moment
        # this fires (fonts not yet loaded, and our +0x584=2 hack runs post-boot),
        # so fall back to 2 to match the native edit-line height (separator row 94).
        bridge = _u32(uc, 0x00DECA00)
        sel = (_u32(uc, bridge + 0x584) if bridge else 2) or 2
    # FUN_00935660: decrement-with-wrap to turn the selector into a table index.
    if sel == 0:
        bridge = _u32(uc, 0x00DECA00)
        count = (_u32(uc, bridge + 0x584) if bridge else 1) or 1
        idx = count - 1
    else:
        idx = sel - 1
    # Only table[0] and table[1] are real embedded fonts in this image; clamp.
    if idx < 0 or idx > 1:
        idx = 1
    font_ptr = _u32(uc, FONT_TABLE_VA + idx * 4)
    height = 16
    if font_ptr:
        try:
            height = uc.mem_read(font_ptr, 1)[0] or 16
        except UcError:
            height = 16
    state = _u32(uc, 0x00DEC9F8)
    screen_h = _u32(uc, state + 0x10) if state else 127
    if screen_h == 0:
        screen_h = 127
    uc.mem_write(widget + 8, struct.pack("<I", (screen_h - height - 0x11) & 0xFFFFFFFF))
    uc.mem_write(widget + 0x10, struct.pack("<I", (height + 1) & 0xFFFFFFFF))
    return 0


@hook_internal(0x009618ae, "calc_malloc")  # operator new wrapper
def _calc_malloc(shim, a):
    return shim.malloc(a[0])

@hook_internal(0x00972c50, "msvcrt_malloc")  # static-linked _malloc
def _crt_malloc(shim, a):
    return shim.malloc(a[0])

@hook_internal(0x009721a0, "msvcrt_free")
def _crt_free(shim, a):
    return 0

@hook_internal(0x009729e6, "msvcrt_realloc")
def _crt_realloc(shim, a):
    # naive: fresh alloc; copy from old up to new size (we don't know old size)
    if a[0] == 0:
        return shim.malloc(a[1])
    # copy min(new_size, 4096) bytes from old to new — good enough until we hit
    # a realloc that actually grows large
    new = shim.malloc(a[1])
    try:
        data = bytes(shim.uc.mem_read(a[0], min(a[1], 4096)))
        shim.uc.mem_write(new, data)
    except UcError:
        pass
    return new


def reg(name: str, argc: int):
    """Decorator: register a stdcall Win32 shim. `argc` = number of stack args."""
    def wrap(fn: Callable[[Shim, list[int]], int]) -> Callable[[Shim, list[int]], HandlerRet]:
        def handler(shim: Shim, args: list[int]) -> HandlerRet:
            return fn(shim, args[:argc]), argc
        HANDLERS[name] = handler
        return handler
    return wrap


@reg("SetUnhandledExceptionFilter", 1)
def _seuhf(shim, a):
    shim.trace(f"  SetUnhandledExceptionFilter(0x{a[0]:08x}) -> 0")
    return 0  # no previous filter

@reg("CreateMutexW", 3)
def _cm(shim, a):
    h = shim.handle()
    shim.trace(f"  CreateMutexW(sec=0x{a[0]:x}, owned={a[1]}, name=0x{a[2]:x}) -> handle 0x{h:x}")
    return h

@reg("CreateMutexA", 3)
def _cma(shim, a):
    return _cm.__wrapped__(shim, a) if False else (shim.handle(), 3)[0]

# --- guest filesystem ------------------------------------------------------
# The calc keeps each aplet's runtime state in a file under %APPDATA%
# ("C:\fake"). With no real FS those reads fail, the apps' data is never built,
# and Symb/Plot/Num NULL-deref. Back it with an in-memory FS (reset per boot);
# the calc creates its own default app files during boot. The Android port does
# the same against the app's real filesDir (emu.cpp). Keep the two in sync.
_INVALID = 0xFFFFFFFF
_GENERIC_WRITE = 0x40000000
_FS: dict[str, bytearray] = {}     # normalized path -> contents
_FS_OPEN: dict[int, dict] = {}     # handle -> {path, pos}
_FS_DIRS: set[str] = set()


def _read_wstr(uc, addr, maxlen=300):
    out = []
    for i in range(maxlen):
        ch = struct.unpack("<H", uc.mem_read(addr + i * 2, 2))[0]
        if ch == 0:
            break
        out.append(chr(ch))
    return "".join(out)


def _fs_norm(p):
    return p.replace("/", "\\").lower().rstrip("\\")


@reg("CreateFileW", 7)
def _cfw(shim, a):
    path = _fs_norm(_read_wstr(shim.uc, a[0]))
    disp = a[4]                              # 1=NEW 2=ALWAYS 3=EXISTING 4=OPEN_ALWAYS 5=TRUNC
    exists = path in _FS
    if disp == 3 and not exists:
        return _INVALID
    if disp == 1 and exists:
        return _INVALID
    if disp in (2, 5) or (disp in (1, 4) and not exists):
        _FS[path] = bytearray()
    _FS.setdefault(path, bytearray())
    h = shim.handle()
    _FS_OPEN[h] = {"path": path, "pos": 0}
    return h

@reg("CreateFileA", 7)
def _cfa(shim, a):
    return _INVALID

@reg("ReadFile", 5)
def _rf(shim, a):
    f = _FS_OPEN.get(a[0])
    if f is None:
        return 0
    data = _FS.get(f["path"], bytearray())
    chunk = bytes(data[f["pos"]:f["pos"] + a[2]])
    if chunk:
        shim.uc.mem_write(a[1], chunk)
    f["pos"] += len(chunk)
    if a[3]:
        shim.uc.mem_write(a[3], struct.pack("<I", len(chunk)))
    return 1

@reg("WriteFile", 5)
def _wf(shim, a):
    f = _FS_OPEN.get(a[0])
    if f is None:
        if a[3]:
            shim.uc.mem_write(a[3], struct.pack("<I", 0))
        return 0
    data = _FS.setdefault(f["path"], bytearray())
    chunk = bytes(shim.uc.mem_read(a[1], a[2])) if a[2] else b""
    end = f["pos"] + len(chunk)
    if end > len(data):
        data.extend(b"\x00" * (end - len(data)))
    data[f["pos"]:end] = chunk
    f["pos"] = end
    if a[3]:
        shim.uc.mem_write(a[3], struct.pack("<I", len(chunk)))
    return 1

@reg("SetFilePointer", 4)
def _sfp(shim, a):
    f = _FS_OPEN.get(a[0])
    if f is None:
        return _INVALID
    dist = a[1] - 0x100000000 if a[1] >= 0x80000000 else a[1]   # signed
    size = len(_FS.get(f["path"], b""))
    f["pos"] = {0: dist, 1: f["pos"] + dist, 2: size + dist}.get(a[3], dist)
    return f["pos"] & 0xFFFFFFFF

@reg("GetFileSize", 2)
def _gfs(shim, a):
    f = _FS_OPEN.get(a[0])
    size = len(_FS.get(f["path"], b"")) if f else 0
    if a[1]:
        shim.uc.mem_write(a[1], struct.pack("<I", 0))
    return size & 0xFFFFFFFF

@reg("CreateDirectoryW", 2)
def _cdw(shim, a):
    _FS_DIRS.add(_fs_norm(_read_wstr(shim.uc, a[0])))
    return 1

@reg("DeleteFileW", 1)
def _dfw(shim, a):
    _FS.pop(_fs_norm(_read_wstr(shim.uc, a[0])), None)
    return 1

@reg("GetFileAttributesW", 1)
def _gfaw(shim, a):
    path = _fs_norm(_read_wstr(shim.uc, a[0]))
    if path in _FS_DIRS:
        return 0x10        # FILE_ATTRIBUTE_DIRECTORY
    if path in _FS:
        return 0x80        # FILE_ATTRIBUTE_NORMAL
    return _INVALID        # INVALID_FILE_ATTRIBUTES

@reg("GetFileAttributesA", 1)
def _gfaa(shim, a):
    return _INVALID

@reg("GetEnvironmentVariableW", 3)
def _gevw(shim, a):
    # The calc indexes buffer[returned_len] and walks for nulls. Fake APPDATA.
    fake = "C:\\fake"
    data = (fake + "\x00").encode("utf-16-le")[: a[2] * 2]
    shim.uc.mem_write(a[1], data)
    return len(fake)

@reg("GetEnvironmentVariableA", 3)
def _geva(shim, a):
    return 0

@reg("RegOpenKeyExW", 5)
def _rokw(shim, a):
    return 2  # ERROR_FILE_NOT_FOUND

@reg("RegOpenKeyExA", 5)
def _roka(shim, a):
    return 2

@reg("RegQueryValueExW", 6)
def _rqv(shim, a):
    return 2

@reg("RegCloseKey", 1)
def _rck(shim, a):
    return 0

@reg("CreateThread", 6)
def _ct(shim, a):
    h = shim.handle()
    shim.trace(f"  CreateThread(start=0x{a[2]:x}, param=0x{a[3]:x}, flags=0x{a[4]:x}) -> handle 0x{h:x} (stubbed: thread not started)")
    if a[5]:  # lpThreadId output
        shim.uc.mem_write(a[5], struct.pack("<I", 0x2000 + (h & 0xFF)))
    return h

@reg("WaitForSingleObject", 2)
def _wfso(shim, a):
    return 0  # WAIT_OBJECT_0

@reg("WaitForMultipleObjects", 4)
def _wfmo(shim, a):
    return 0  # signal index 0

@reg("SetEvent", 1)
def _se(shim, a):
    return 1

@reg("ResetEvent", 1)
def _re(shim, a):
    return 1

@reg("CloseHandle", 1)
def _ch(shim, a):
    _FS_OPEN.pop(a[0], None)
    return 1

@reg("CreateEventW", 4)
def _ce(shim, a):
    h = shim.handle()
    shim.trace(f"  CreateEventW(sec=0x{a[0]:x}, manual={a[1]}, init={a[2]}, name=0x{a[3]:x}) -> handle 0x{h:x}")
    return h

@reg("CreateEventA", 4)
def _cea(shim, a):
    h = shim.handle()
    shim.trace(f"  CreateEventA(...) -> handle 0x{h:x}")
    return h

@reg("InitializeCriticalSection", 1)
def _ics(shim, a):
    return 0

@reg("InitializeCriticalSectionAndSpinCount", 2)
def _icsasc(shim, a):
    return 1  # success

@reg("EnterCriticalSection", 1)
def _ecs(shim, a):
    return 0

@reg("LeaveCriticalSection", 1)
def _lcs(shim, a):
    return 0

@reg("DeleteCriticalSection", 1)
def _dcs(shim, a):
    return 0

@reg("GetLastError", 0)
def _gle(shim, a):
    return 0

@reg("SetLastError", 1)
def _sle(shim, a):
    return 0

@reg("GetCurrentThreadId", 0)
def _gcti(shim, a):
    return 0x1234

@reg("GetCurrentProcessId", 0)
def _gcpi(shim, a):
    return 0xC4

@reg("GetCurrentProcess", 0)
def _gcp(shim, a):
    return 0xFFFFFFFF  # pseudo-handle

@reg("GetTickCount", 0)
def _gtc(shim, a):
    return 0

@reg("GetVersion", 0)
def _gv(shim, a):
    return 0x06000001  # major=1, minor=0, build=6 — anything plausible

@reg("GetVersionExA", 1)
def _gvexa(shim, a):
    return 1

@reg("GetVersionExW", 1)
def _gvexw(shim, a):
    return 1

@reg("Sleep", 1)
def _sleep(shim, a):
    return 0

@reg("GetModuleHandleW", 1)
def _gmhw(shim, a):
    # Returning 0 makes the CRT init think a DLL isn't loaded yet and it spins.
    # Pretend any requested module is loaded by returning a non-zero pseudo-handle.
    return IMAGE_BASE  # the loaded exe itself, good enough

@reg("GetModuleHandleA", 1)
def _gmha(shim, a):
    return IMAGE_BASE

@reg("GetModuleFileNameA", 3)
def _gmfna(shim, a):
    # (HMODULE hModule, LPSTR lpFilename, DWORD nSize) -> chars copied
    path = (EXE_PATH + "\x00").encode("ascii", "replace")[: a[2]]
    shim.uc.mem_write(a[1], path)
    return len(path) - 1

@reg("GetModuleFileNameW", 3)
def _gmfnw(shim, a):
    path = (EXE_PATH + "\x00").encode("utf-16-le")[: a[2] * 2]
    shim.uc.mem_write(a[1], path)
    return len(path) // 2 - 1

@reg("GetProcAddress", 2)
def _gpa(shim, a):
    # Pretend nothing is dynamically resolvable. CRT will fall back to defaults.
    return 0

@reg("TlsAlloc", 0)
def _tlsa(shim, a):
    idx = shim.next_handle & 0x3F  # TLS slots are < 64 historically
    shim.next_handle += 1
    return idx

@reg("TlsGetValue", 1)
def _tlsg(shim, a):
    return 0

@reg("TlsSetValue", 2)
def _tlss(shim, a):
    return 1

@reg("TlsFree", 1)
def _tlsf(shim, a):
    return 1

@reg("FlsAlloc", 1)
def _flsa(shim, a):
    return shim.next_handle & 0x3F

@reg("FlsGetValue", 1)
def _flsg(shim, a):
    return 0

@reg("FlsSetValue", 2)
def _flss(shim, a):
    return 1

@reg("FlsFree", 1)
def _flsf(shim, a):
    return 1

@reg("EncodePointer", 1)
def _ep(shim, a):
    return a[0]

@reg("DecodePointer", 1)
def _dp(shim, a):
    return a[0]

@reg("IsProcessorFeaturePresent", 1)
def _ipfp(shim, a):
    return 0

@reg("IsDebuggerPresent", 0)
def _idp(shim, a):
    return 0

@reg("QueryPerformanceCounter", 1)
def _qpc(shim, a):
    shim.uc.mem_write(a[0], b"\x00" * 8)
    return 1

@reg("GetSystemTimeAsFileTime", 1)
def _gstaft(shim, a):
    shim.uc.mem_write(a[0], b"\x00" * 8)
    return 0

@reg("InterlockedIncrement", 1)
def _ii(shim, a):
    v = struct.unpack("<I", shim.uc.mem_read(a[0], 4))[0] + 1
    shim.uc.mem_write(a[0], struct.pack("<I", v & 0xFFFFFFFF))
    return v & 0xFFFFFFFF

@reg("InterlockedDecrement", 1)
def _id(shim, a):
    v = struct.unpack("<I", shim.uc.mem_read(a[0], 4))[0] - 1
    shim.uc.mem_write(a[0], struct.pack("<I", v & 0xFFFFFFFF))
    return v & 0xFFFFFFFF

@reg("InterlockedExchange", 2)
def _ie(shim, a):
    old = struct.unpack("<I", shim.uc.mem_read(a[0], 4))[0]
    shim.uc.mem_write(a[0], struct.pack("<I", a[1] & 0xFFFFFFFF))
    return old


def _heap_alloc(shim, a):
    # HeapAlloc(hHeap, dwFlags, dwBytes) — flag 8 = HEAP_ZERO_MEMORY (we already zero)
    p = shim.malloc(a[2])
    shim.trace(f"  HeapAlloc(.., bytes={a[2]}) -> 0x{p:x}")
    return p

@reg("HeapAlloc", 3)
def _ha(shim, a):
    return _heap_alloc(shim, a)

@reg("HeapFree", 3)
def _hf(shim, a):
    return 1

@reg("HeapCreate", 3)
def _hc(shim, a):
    return shim.handle()

@reg("GetProcessHeap", 0)
def _gph(shim, a):
    return 0x80001000  # fake heap handle (distinct from CreateMutex range)


# -- C runtime (malloc / free / memset / memcpy / etc) --
# FUN_009618ae is the calc's malloc wrapper. It calls into MSVCRT's malloc which
# routes through HeapAlloc; if that path doesn't engage, we may need to hook
# direct malloc imports from the CRT IAT (msvcrt has its own import list bound in).

@reg("malloc", 1)
def _malloc(shim, a):
    p = shim.malloc(a[0])
    return p

@reg("free", 1)
def _free(shim, a):
    return 0

@reg("calloc", 2)
def _calloc(shim, a):
    return shim.malloc(a[0] * a[1])

@reg("realloc", 2)
def _realloc(shim, a):
    # naive: just allocate fresh; old data not copied. Will fix if anything cares.
    return shim.malloc(a[1])

@reg("_msize", 1)
def _msize(shim, a):
    return 0

@reg("memset", 3)
def _memset(shim, a):
    shim.uc.mem_write(a[0], bytes([a[1] & 0xFF]) * a[2])
    return a[0]

@reg("memcpy", 3)
def _memcpy(shim, a):
    shim.uc.mem_write(a[0], bytes(shim.uc.mem_read(a[1], a[2])))
    return a[0]


# Fallback stdcall arg counts so unhandled Win32 calls still clean up the stack
# correctly. Critical: even when we return 0, the wrong count leaves ESP drifted
# and downstream stack-cookie checks blow up. Add functions here as they appear.
STDCALL_ARGC: dict[str, int] = {
    # KERNEL32
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
    # HID
    "HidD_GetHidGuid": 1, "HidD_GetPreparsedData": 2, "HidD_FreePreparsedData": 1,
    "HidD_GetAttributes": 2, "HidD_GetManufacturerString": 3, "HidD_GetProductString": 3,
    "HidP_GetCaps": 2,
    # SetupAPI
    "SetupDiGetClassDevsW": 4, "SetupDiGetClassDevsA": 4,
    "SetupDiEnumDeviceInterfaces": 5,
    "SetupDiGetDeviceInterfaceDetailW": 6, "SetupDiGetDeviceInterfaceDetailA": 6,
    "SetupDiDestroyDeviceInfoList": 1,
    # USER32 / GDI32 (calc core shouldn't reach these, but the conn-kit thread might)
    "PostMessageW": 4, "SendMessageW": 4,
}


def default_handler(name: str, shim: Shim, args: list[int]) -> HandlerRet:
    argc = STDCALL_ARGC.get(name, 0)
    suffix = "" if name in STDCALL_ARGC else "  [argc=?, ASSUMING CDECL]"
    shim.trace(f"  ?? {name}(args~={args[:4]}) -> 0  argc={argc}{suffix}", name=name)
    return 0, argc


# =============================================================================
# Loader
# =============================================================================

@dataclass
class LoadedImage:
    pe: pefile.PE
    image_end: int
    iat_to_name: dict[int, str]      # IAT slot VA -> "DLL!Func"
    name_to_trampoline: dict[str, int]
    trampoline_to_name: dict[int, str]


def load_pe_into(uc: Uc) -> LoadedImage:
    pe = pefile.PE(EXE_PATH, fast_load=False)

    # one big chunk covering the whole image (rounded to a page)
    image_size = page_round_up(pe.OPTIONAL_HEADER.SizeOfImage)
    uc.mem_map(IMAGE_BASE, image_size)
    # PE headers (so anything reading the DOS/NT header doesn't fault)
    uc.mem_write(IMAGE_BASE, pe.header)

    for s in pe.sections:
        va = IMAGE_BASE + s.VirtualAddress
        raw = s.get_data()
        if raw:
            uc.mem_write(va, raw)
        # virtual size > raw size (BSS): the rest is already 0 from mem_map

    # walk imports → build trampoline table
    iat_to_name: dict[int, str] = {}
    name_to_tramp: dict[str, int] = {}
    tramp_to_name: dict[int, str] = {}
    next_tramp = TRAMP_BASE

    for dll in pe.DIRECTORY_ENTRY_IMPORT:
        dll_name = dll.dll.decode("ascii", "replace")
        for imp in dll.imports:
            sym = (imp.name or b"?").decode("ascii", "replace") if imp.name else f"ord{imp.ordinal}"
            full = f"{dll_name}!{sym}"
            iat_va = imp.address  # already VA, not RVA
            iat_to_name[iat_va] = sym
            name_to_tramp[sym] = next_tramp
            tramp_to_name[next_tramp] = sym
            # write trampoline address back into IAT slot
            uc.mem_write(iat_va, struct.pack("<I", next_tramp))
            # the trampoline page just needs to exist as code; we'll never actually
            # run an instruction there — the code hook intercepts on entry.
            next_tramp += 0x10

    return LoadedImage(pe, IMAGE_BASE + image_size, iat_to_name, name_to_tramp, tramp_to_name)


def _gdt_entry(base: int, limit: int, access: int, flags: int) -> int:
    """Pack an 8-byte x86 GDT descriptor."""
    return (
        (limit & 0xFFFF)
        | ((base & 0xFFFFFF) << 16)
        | ((access & 0xFF) << 40)
        | (((limit >> 16) & 0xF) << 48)
        | ((flags & 0xF) << 52)
        | (((base >> 24) & 0xFF) << 56)
    )


def setup_fs_segment(uc: Uc) -> None:
    """
    Create a minimal TIB at TIB_BASE and build a GDT so FS:[0] resolves to it.
    UC_X86_REG_FS_BASE is a no-op in 32-bit mode (Unicorn 2.x), so we must go
    through a real GDT entry.
    """
    uc.mem_map(TIB_BASE, TIB_SIZE)
    uc.mem_write(TIB_BASE + 0x00, struct.pack("<I", 0xFFFFFFFF))   # SEH chain head
    uc.mem_write(TIB_BASE + 0x04, struct.pack("<I", STACK_BASE + STACK_SIZE))
    uc.mem_write(TIB_BASE + 0x08, struct.pack("<I", STACK_BASE))
    uc.mem_write(TIB_BASE + 0x18, struct.pack("<I", TIB_BASE))     # self ptr

    uc.mem_map(GDT_BASE, GDT_SIZE)
    # All ring-3 to keep RPL consistent. Access bytes:
    #   code (0xFA): present, ring3, code, exec/read
    #   data (0xF2): present, ring3, data, read/write
    # Flags 0xC = 4K granularity + 32-bit. Flat 4GB segments for code/data.
    # FS is a small (TIB-sized) data segment based at TIB_BASE.
    entries = [
        0,
        _gdt_entry(0, 0xFFFFF, 0x9A, 0xC),         # 1: code, ring0
        _gdt_entry(0, 0xFFFFF, 0x92, 0xC),         # 2: data, ring0
        _gdt_entry(TIB_BASE, TIB_SIZE - 1, 0x92, 0x4),  # 3: fs at TIB, ring0
    ]
    for i, e in enumerate(entries):
        uc.mem_write(GDT_BASE + i * 8, struct.pack("<Q", e))

    uc.reg_write(UC_X86_REG_GDTR, (0, GDT_BASE, len(entries) * 8 - 1, 0))
    # Reload every segment register so Unicorn refreshes the cached descriptors
    # (base/limit/flags) from our new GDT. Selectors: index<<3 | RPL=0.
    sel_code = 1 << 3
    sel_data = 2 << 3
    sel_fs   = 3 << 3
    uc.reg_write(UC_X86_REG_CS, sel_code)
    uc.reg_write(UC_X86_REG_SS, sel_data)
    uc.reg_write(UC_X86_REG_DS, sel_data)
    uc.reg_write(UC_X86_REG_ES, sel_data)
    uc.reg_write(UC_X86_REG_GS, sel_data)
    uc.reg_write(UC_X86_REG_FS, sel_fs)


# =============================================================================
# Hook: trampoline dispatcher
# =============================================================================

def install_iat_dispatcher(uc: Uc, img: LoadedImage, shim: Shim) -> None:
    _FS.clear(); _FS_OPEN.clear(); _FS_DIRS.clear()   # fresh guest filesystem per boot
    def on_code(uc, address, size, user_data):
        if address == SENTINEL_RET:
            shim.trace(f"\n[halt] hit sentinel return address — calc thread returned cleanly")
            uc.emu_stop()
            return
        if address == MAIN_LOOP_VA:
            shim.trace(f"\n[halt] reached main-loop entry FUN_00401730 -- calc booted")
            uc.emu_stop()
            return
        # Internal hook: replace calc-side functions (cdecl) with our shim
        internal = INTERNAL_HOOKS.get(address)
        if internal is not None:
            name, fn = internal
            esp = uc.reg_read(UC_X86_REG_ESP)
            ret_addr = struct.unpack("<I", uc.mem_read(esp, 4))[0]
            args = list(struct.unpack("<8I", uc.mem_read(esp + 4, 32)))
            ret = fn(shim, args)
            shim.trace(f"  [internal] {name}({args[:2]}) -> 0x{ret:x}", name=name)
            uc.reg_write(UC_X86_REG_EAX, ret & 0xFFFFFFFF)
            uc.reg_write(UC_X86_REG_ESP, esp + 4)
            uc.reg_write(UC_X86_REG_EIP, ret_addr)
            return
        if TRAMP_BASE <= address < TRAMP_BASE + TRAMP_SIZE:
            name = img.trampoline_to_name.get(address, f"trampoline_0x{address:x}")
            # read up to 8 args from [esp+4 .. esp+32]
            esp = uc.reg_read(UC_X86_REG_ESP)
            ret_addr = struct.unpack("<I", uc.mem_read(esp, 4))[0]
            args = list(struct.unpack("<8I", uc.mem_read(esp + 4, 32)))
            handler = HANDLERS.get(name)
            if handler is None:
                ret, argc = default_handler(name, shim, args)
            else:
                ret, argc = handler(shim, args)
                shim.call_counts[name] = shim.call_counts.get(name, 0) + 1
            # simulate stdcall return: pop ret addr, pop args, jump to ret addr
            new_esp = esp + 4 + argc * 4
            uc.reg_write(UC_X86_REG_ESP, new_esp)
            uc.reg_write(UC_X86_REG_EAX, ret & 0xFFFFFFFF)
            uc.reg_write(UC_X86_REG_EIP, ret_addr)
    uc.hook_add(UC_HOOK_CODE, on_code)


def install_fault_logger(uc: Uc, shim: Shim) -> None:
    def on_unmapped(uc, access, address, size, value, user_data):
        eip = uc.reg_read(UC_X86_REG_EIP)
        esp = uc.reg_read(UC_X86_REG_ESP)
        shim.trace(f"\n[fault] unmapped access at 0x{address:x} (size {size}) from EIP=0x{eip:x}")
        _dump_caller_chain(uc, esp)
        return False
    uc.hook_add(UC_HOOK_MEM_UNMAPPED, on_unmapped)


def _dump_caller_chain(uc: Uc, esp: int, depth: int = 8) -> None:
    """Print likely return addresses from the stack — code addresses that fall
    inside the loaded image."""
    print(f"  [stack at ESP=0x{esp:x}]")
    try:
        words = struct.unpack(f"<{depth*4}I", uc.mem_read(esp, depth * 16))
    except UcError:
        return
    for i, w in enumerate(words):
        tag = ""
        if IMAGE_BASE <= w < IMAGE_BASE + 0x00A10000:
            tag = "  <- likely return addr in image"
        print(f"    +0x{i*4:02x}: 0x{w:08x}{tag}")


# =============================================================================
# Run
# =============================================================================

def main() -> int:
    uc = Uc(UC_ARCH_X86, UC_MODE_32)

    # map regions
    uc.mem_map(STACK_BASE, STACK_SIZE)
    uc.mem_map(HEAP_BASE, HEAP_SIZE)
    uc.mem_map(TRAMP_BASE, TRAMP_SIZE)

    img = load_pe_into(uc)
    setup_fs_segment(uc)

    shim = Shim(uc=uc)
    install_iat_dispatcher(uc, img, shim)
    install_fault_logger(uc, shim)

    print(f"[load] {EXE_PATH}")
    print(f"[load] image 0x{IMAGE_BASE:x}..0x{img.image_end:x} ({(img.image_end-IMAGE_BASE)//1024} KB)")
    print(f"[load] imports: {len(img.iat_to_name)} functions across {len(img.pe.DIRECTORY_ENTRY_IMPORT)} DLLs")
    print(f"[load] handlers registered: {len(HANDLERS)}")

    # Plant a dummy CAspen_cDlg-like object at DAT_00DEB7E4 so that
    # FUN_00406430's HWND-bridge step (MOV EDX,[ECX+0x20] where ECX=
    # [DAT_00DEB7E4]) reads zero instead of faulting on a NULL pointer.
    # Real app: MFC sets this when the dialog constructs.
    dummy_dlg = shim.malloc(0x400)   # 1 KB, zeroed
    uc.mem_write(0x00DEB7E4, struct.pack("<I", dummy_dlg))
    print(f"[boot] planted dummy dialog object at 0x{dummy_dlg:x} (DAT_00DEB7E4)")

    # Plant a non-zero "performance frequency" so FUN_0043bf10's _aulldiv
    # doesn't divide by zero. Real app: QueryPerformanceFrequency() init.
    uc.mem_write(0x00DFDCA8, struct.pack("<Q", 1))
    print(f"[boot] set perf frequency at DAT_00DFDCA8 = 1")

    # build stack for the thread call: push arg (NULL), push sentinel ret addr
    esp = STACK_BASE + STACK_SIZE - 0x100
    esp -= 4; uc.mem_write(esp, struct.pack("<I", 0))             # lpParameter = NULL
    esp -= 4; uc.mem_write(esp, struct.pack("<I", SENTINEL_RET))  # return addr
    uc.reg_write(UC_X86_REG_ESP, esp)
    uc.reg_write(UC_X86_REG_EBP, 0)

    print(f"\n[run] starting at FUN_00406430 (calc-core thread)\n")
    try:
        # cap at ~2M instructions and 10s wall to avoid spinning
        uc.emu_start(CALC_THREAD_VA, 0, timeout=10 * 1_000_000, count=2_000_000)
    except UcError as e:
        eip = uc.reg_read(UC_X86_REG_EIP)
        esp = uc.reg_read(UC_X86_REG_ESP)
        print(f"\n[error] UcError {e} at EIP=0x{eip:x}")
        _dump_caller_chain(uc, esp)

    print(f"\n[stop] EIP=0x{uc.reg_read(UC_X86_REG_EIP):x} ESP=0x{uc.reg_read(UC_X86_REG_ESP):x}")
    print(f"[stop] heap consumed: {shim.heap_ptr - HEAP_BASE} bytes")
    print(f"[stop] events logged: {len(shim.log)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
