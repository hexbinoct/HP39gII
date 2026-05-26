# HP 39gII Calculator Reverse Engineering — Research Notes

**Started:** 2026-04-03/04
**Last updated:** 2026-05-26 (Android app shipping; edit-line render bug fixed)
**Goal:** Extract the pure calculator engine from `HP39gII.exe` (Windows emulator) and run it on Android (primary target) or in a browser, with our own input/output — no MFC dependency. Browser via BoxedWine is the planned phase-1 POC; Android is the end target.

> ## ⭐ Current status (2026-05-26) — read this first
>
> The bulk of this file is a chronological research log; here's where things
> actually stand now (much of the "what's next" / section 14 material below is
> historical and was written before any code existed).
>
> - **Headless harness (Windows host): DONE.** `HP39gII.exe` boots under Unicorn
>   with no Windows underneath; "1+1=2" etc. render correctly. See the M1–M3
>   milestone log below.
> - **Android app: SHIPPING (Phases A–C done, in git).** Native C++ port of the
>   PE loader + Unicorn 2.1.4 via NDK/JNI; live framebuffer + an interactive
>   keypad skinned as a physical HP 39gII replica. Boots and computes on a real
>   device / emulator. Details are in the commit history (Phase A/B/C commits +
>   the keypad-skin commit), not re-transcribed here.
> - **Edit-line clipping bug (2026-05-26): FIXED.** Typed expressions on the edit
>   line were vertically clipped (only glyph tops showed). Root cause: our boot
>   had **no-op'd `FUN_00944630`** (the widget sizer that derives height from the
>   current font's line-height), because it NULL-derefed when no font is loaded.
>   The system fonts are actually embedded in `.rdata` (static table `0xC18D00`:
>   table[0] line-height 12, table[1] line-height 16); the crash was just an
>   index underflow (`host_bridge[+0x584]=0` → wraps to a wild table entry). Fix:
>   faithfully reimplement `FUN_00944630` in both `harness/headless/load.py` and
>   `android/.../emu.cpp`, reading the real embedded height with guarded pointers.
>   `FUN_00944630` sizes the edit line exactly once at boot via the default-font
>   path while `+0x584` is still 0, so the fallback now defaults to font index **2**
>   (the h=16 font) → separator lands at row 94, pixel-identical to the native
>   device dump `fb14_after_key_1.bin`. Also bumped the post-boot `+0x584` hack 1→2.
>   **This supersedes the older M2/M3 notes below that describe `FUN_00944630` as
>   a no-op and `+0x584 = 1`.** Probes used: `harness/headless/probe_{fonts,editline,
>   editline_zoom,944630_calls}.py`.
> - **Web port: deferred / dead-end on unicorn.js 1.x** (see the 2026-05-17 entry).
>   Revisit only by building Unicorn 2.x → WASM.

**Tooling status (2026-05-16):** Ghidra 12.0.4 at `F:\ru\myprojects\may\ghidra_12.0.4_PUBLIC` has the binary loaded and auto-analyzed (MFC RTTI applied). GhidraMCP 1.4 extension installed and HTTP server live on `127.0.0.1:8080`. Claude Code MCP server `ghidra` registered. See `GHIDRA_SETUP.md` for details.

## Findings via Ghidra MCP (2026-05-16 session)

- **`CAspen_cApp::InitInstance` @ `0x00401130`** — sets `m_pszAppName = "HP 39gII"`, calls `SetRegistryKey("Hewlett-Packard")`, constructs the 336-byte `CAspen_cDlg` via `FUN_004052b0`, stores it at `m_pMainWnd` (+0x20), runs message pump via `FUN_00964663`.
- **Shutdown / save-window-state @ `0x00402390`** — writes `HKCU\SOFTWARE\Hewlett-Packard\HP 39gII` keys: `left`, `top`, `Titlebar`, `Skin`, `Key`.
- **Save-as-image handler @ `FUN_0040a5c0`** — `CFileDialog::DoModal` with PNG/BMP/JPG/GIF/TIFF filter; this is the screenshot save, not the main dialog.
- **`CAspen_cDlg` ctor @ `FUN_004052b0`** — `CDialog::CDialog(this, 0x66, parent)` (resource ID 102), embeds `CBrush` at +0xa0, `CStatic` at +0xb4, icon at +0xa8, dialog size 0x108 bytes (+0x10c slack for MFC fields).
- **RTTI strings located:** `.?AVCAspen_cApp@@` @ `0x00DD700C`, `.?AVCAspen_cDlg@@` @ `0x00DD732C` (xrefs hidden by MFC RTTI typedescriptors — vftables not yet resolved by symbol).

### Connectivity Kit / USB-HID subsystem (NOT keyboard) — clarification

Initial hot trail of functions in `0x00401670`/`0x00401730`/`0x004157e0` looked like the calc input path because they touch the global state `DAT_00DEC9F8`, but on inspection they are the **PC-link Connectivity Kit worker thread**:

- `FUN_00401730` is a `WaitForMultipleObjects(3, [evt1, evt2, evt3], ...)` loop on 3 HANDLEs (`DAT_00DFDCA4`, `DAT_00DEB7E8`, `DAT_00DEB7EC`) protected by mutex `DAT_00DEB828`. Per-iteration it calls CPU step `FUN_00944270`, pokes flag bits at `DAT_00DEC9F8+0x2c` / `+0x90`, and dispatches packets via `FUN_004157e0`.
- `FUN_004157e0` is a **packet-protocol dispatcher** — reads bytes with `FUN_00407e10` (pipe read) and switches on the first byte: `0xeb`, `0xec`, `0xee`, `0xf0`, `0xf4`, `0xf5`, `0xf6`, `0xf7`, `0xf8`, `0xed`, `0xef`, `0xfa`, `0xfb`, `0xfc`, `0xff`. Matches the calc's USB HID protocol with the HP Connectivity Kit.
- Confirms presence of HID API imports (`HidD_*`, `HidP_*`, `SetupDi*`) — calc emulates the device side of the USB link too.

**Implication for porting:** This subsystem can be entirely stubbed/dropped on Android — it only matters for PC↔calc file transfer. The 3 HANDLEs are the link's pipe-data-available events, not keypress events.

### Heartbeat investigation — calc appears to be PURELY event-driven

- `SetTimer` is **not** imported. No periodic Windows timer drives the calc.
- The only worker thread we've located is the connectivity-kit thread (FUN_00401730), and it does NOT step a CPU emulator — it processes USB HID packets.
- `FUN_00944270` (which initially looked like "step CPU") is actually **"process pending state flags + repaint dirty widgets"**, ending in a call to `FUN_009439d0`.
- `FUN_009439d0` is the **widget-tree paint walker** using the calc's own RTTI: it iterates children via `FUN_00973029(parent, ..., &Cbitmap::RTTI_Type_Descriptor, &Cwindow::RTTI_Type_Descriptor, 0)`, then for each child calls vtable+0x1c (paint self) and recurses with vtable+0x20. Confirms the calc has its own `Cwindow`/`Cbitmap` widget hierarchy.
- Many widget classes inherit `FUN_009439d0` directly (~25 vtable slots reference it).

**Model:** Input event (key press) runs the calc synchronously through whatever state changes it triggers, then `FUN_00944270` repaints dirty widgets into the framebuffer, then control returns to the Windows message pump. **No background ticking needed** — exactly the model required for clean headless porting.

### Second global struct: DAT_00DECA00 — host↔core bridge

- `+0x4`, `+0x5`, `+0x7` (bytes) — host-state flags read by `FUN_00944270` to derive calc state bits at `DAT_00DEC9F8+0x90`.
- `+0x10` — pointer to some host substruct (offset +0x10 reads a link-mode flag).
- `+0x1d4` (dword) — current language ID (1=EN, 2=ZH, 3=FR, 4=DE, 5=ES, 6=NL, 7=PT). Defaulted from Windows LCID by `FUN_004087b0`.
- `+0x588` — wide-string buffer (file/text being sent over connectivity kit).
- `+0x9c` — overridable callback pointer (set to `&DAT_00a83398` in message-box code).
- `+0xba4` / `+0xba8` — generic host callback fn-ptr + arg, invoked once per connectivity-kit loop iteration.

This struct is the seam Android must implement. For the headless harness: zero-init most of it, leave callbacks NULL, set language to 1 (English).

### Widget API discoveries

- **String-table API:** `FUN_0040b860(packed_id)` — `packed_id = (lang_id << 24) | string_id`. Returns `wchar_t*` from `PTR_PTR_00a76b9c`, an array of 7 per-language string tables. Lang 0 means "use current". Falls back across all 7 tables if entry missing.
- **CMessageBox builder:** `FUN_0040d750(out_widget, parent, ..., width_basis_widget, lookup_text, flag_a, flag_b)` — constructs a `CMessageBox` widget (sets `*out_widget = CMessageBox::vftable`), formats text via `FUN_0040d3f0/0040d430`, sizes from `DAT_00DEC9F8+0xc` (screen width), copies framebuffer ptr from `+0x5c` into widget at `+0x14`, then `FUN_009438d0` registers it in the widget tree.
- **Show-localized-message-box convenience:** `FUN_004068f0(packed_id, parent_widget, p3, p4)` — universal "post error/info dialog" entry, called from ~28 sites everywhere. NOT key injection.
- **First two widget vtables located by name:** `CMessageBox::vftable`, `Cbitmap::vftable`.
- **Framebuffer geometry slots (confirmed):** `DAT_00DEC9F8 + 0x0c` = screen width (256), `+0x10` = screen height (127), `+0x1c` = active draw context, `+0x5c` = framebuffer base.

### Skin file format (text-based, parsed by FUN_0048d010)

Loaded from disk via `CreateFileW("<exe_dir>\\<name>.skin")`. Plain ASCII text:
- `#` introduces a line comment
- Whitespace-separated tokens; supports `"..."` quoted strings and `{...}` blocks for hotspot modifier lists
- Token parser: `FUN_0048c720` (keyword match), `FUN_0048c760` (read integer/string), `FUN_0048c8c0` (read pair)
- The dialog/skin object stores parsed hotspots in `param_1[0x14]` (array base) with count `param_1[0x13]`
- **Each hotspot record is 76 bytes (0x4c)** — fields include +0x4/+0x8/+0xc/+0x10 (bounding box, min/max-swapped after parse), +0x14 (single vs drag flag), nine dwords at +0x20..+0x44 initialized to 0xFFFFFFFF (likely the keycode list — primary + modifier variants), and +0x48 (ushort = optional ASCII character emitted directly).

The skin loader does NOT call into the calc core — it just builds a Windows-side lookup table. So the hotspot→keycode mapping lives in this 76-byte struct.

### Calc-core initializer thread (FUN_00406430) — overturns "no heartbeat" claim

OnInitDialog spawns TWO threads at the end:
- `CreateThread(NULL, 0x4000, FUN_00406430, ...)` — 16KB stack, the **calc core thread**
- `CreateThread(NULL, 0x400, LAB_00401960, ...)` — 1KB stack, smaller helper

`FUN_00406430` is the calc-core init + main loop entry. It:
1. Creates the master mutex `DAT_00DEB828`.
2. Allocates the 4 global state structs via `FUN_009618ae(size)`:
   - `DAT_00DECA04` = 0x54 bytes (slot [0x14] is a signed counter)
   - `DAT_00DECA08` = 0x88 bytes
   - `DAT_00DEC9F8` = 0x98 bytes, then **`FUN_00945540(0x100, 0x7f)`** initializes it with screen dims `0x100 × 0x7f = 256 × 127` (framebuffer geometry confirmed at the source).
   - `DAT_00DECA00` = 3000 bytes (host bridge, init by `FUN_004135c0`)
   - `DAT_00DEC9FC` = 0xB18C bytes (~45 KB — probably ROM image / paged memory)
   - `DAT_00DEC9F4` = 0xB180 bytes (~45 KB — sibling ROM/RAM region)
3. Stores dialog HWND into `DAT_00DECA00 + 0xbb4` (the **core→dialog bridge** for the core to ask the host to update screen, set caret, etc.).
4. Sets ready flag `DAT_00DECA00 + 8 = 1`.
5. Restores any saved state at `DAT_00DECA00 + 0x14`.
6. **Tail-calls into `FUN_00401730`** — the function I previously labeled "conn-kit loop" is actually the **calc main loop**.

So the calc IS heartbeat-driven, but it's a **wait-driven heartbeat** (`WaitForMultipleObjects` on 3 events), not a periodic timer. Per wake it does state housekeeping + widget repaint via `FUN_00944270`. Input injection = `SetEvent` on the key-wake handle. This is still very friendly for headless porting — the harness just signals the same handle.

The second thread (`LAB_00401960`, 1KB stack) wasn't auto-recognized as a function by Ghidra — likely a tiny watchdog/signal helper.

---

## INPUT API — REVISED after empirical verification

Initially I thought `press_key` + `release_key` was the whole input API. Wrong — those alone set/clear the 64-bit keymask bit (verified by reading the memory location) but the calc thread does NOTHING in response unless an event has ALSO been enqueued into the event queue. The dialog's `FUN_00401C40` does both, in this order:

```c
EventQueue* queue = *(EventQueue**)0x00DECA08;     // global event queue ptr
uint8_t payload[8] = {0};
payload[0] = 1;
payload[4] = (uint8_t)keycode;
enqueue_event(queue, 0, payload);    // FUN_00941210 __thiscall, ret 0x8
press_key(keycode);                  // FUN_0043BE90 __cdecl, sets bit + SetEvent
// ... later ...
release_key(keycode);                // FUN_0043BED0 __cdecl, clears bit
```

The enqueue is a 128-byte (8-slot × 16-byte) ring buffer at `DAT_00DECA08`. Slot layout:
- byte +0x80 = head index, byte +0x81 = tail index (modulo 8 via `& 0x80000007` with sign rotation)
- each entry: dword event_type, dword payload[0..3], dword payload[4..7], 4 bytes padding

**Ghidra trap:** the auto-decompile of `FUN_00401C40` showed the call as `FUN_00941210(0, &local_8)` because Ghidra hid the implicit `this` (ECX) argument and the call's stack args were re-ordered. Only by reading the disassembly directly (look at the `MOV ECX, [0x00DECA08]` before the `CALL`) was the real signature recovered.

### Verified empirically (2026-05-17 session)

Wrote `harness/probe.cpp` (DLL injected into HP39gII.exe) + `harness/inject.cpp`. After fixing two bugs (cdecl not fastcall; missing enqueue_event call), driving the input API from the DLL produced:
- ✓ 64-bit keymask updates exactly as expected (bit 42 set on press(42), etc.)
- ✓ Framebuffer at `DAT_00DEC9F8 + 0x14` changes after each key press (5 distinct MD5s for the "1 + 1 ENTER" sequence)
- ✓ Image base 0x00400000 with no ASLR (delta = 0), so VAs from Ghidra map 1:1 at runtime
- ✓ State allocation matches predictions: width=256, height=127, pitch=86, fb size=10922

## INPUT API — original (kept for reference)

The calc takes input through a **64-bit keyboard matrix bitmask** at `DAT_00DFDC88` (low 32 bits) / `DAT_00DFDC8C` (high 32 bits), wired to wake handle `DAT_00DFDCA4`. Up to 64 keycodes (0..63), one bit per key, mirroring the original i.MX233 memory-mapped keyboard register.

### Keyboard module (architecture-neutral, what Android calls into)

| Function | VA | Signature | Role |
|---|---|---|---|
| `keyboard_init` | `FUN_0043BE50` | `void()` | Zeroes the bitmask at `DAT_00DFDC88..8C`, sets sentinels at `DAT_00DFDC90..93`, creates wake event `DAT_00DFDCA4` (auto-reset). |
| `press_key` | `FUN_0043BE90` | `void(int keycode_in_ECX)` | `bitmask |= (1ULL << keycode); SetEvent(wake)`. Note: arg passed in register, Ghidra missed it. |
| `release_key` | `FUN_0043BED0` | `void(int keycode_in_ECX)` | `bitmask &= ~(1ULL << keycode)`. Does NOT call SetEvent — the wake on press is enough, the loop will see the cleared bit. |

That's it. Three functions, one bitmask, one event. **This is the entire input API of the calculator OS.**

### Dialog-side wrappers (Windows-specific — replaceable on Android)

| Function | VA | Role |
|---|---|---|
| `FUN_00401620` | thin press wrapper, takes keycode in ECX, special-cases `0x2e`, calls press_key, then has leftover `sprintf("%d\r\n")` debug code |
| `FUN_00401C40` | `(HBITMAP highlight_bmp, int keycode)` — **the dialog's "press-this-key" dispatcher**. Tracks one held key at `DAT_00DD72E8`. Releases any previously-held key, deletes its highlight bitmap, stores new state, then calls press wrapper. Pass `(NULL, -1)` to just release. |
| `FUN_00401D20 / 01DE0 / 01EA0` | mouse handlers on the skin (LButtonDown / LButtonUp / MouseMove) — call `FUN_00401C40` after hotspot lookup |
| `FUN_00403090 / 030D0 / 03110` | Windows keyboard handlers (KeyDown / KeyUp / Char) — call `FUN_00401C40` after VK→calc-keycode mapping |

### USB-remote keypress (Connectivity Kit)

When a key arrives over the USB HID protocol (packet code `0xF0` in `FUN_004157E0`), it goes through `FUN_00414240`:
- writes keycode to `DAT_00DECA00 + 0xc`
- polls `FUN_00941210` with `Sleep(1)` until ready
- calls press_key then release_key back-to-back (simulated click)

### State variables touched by the input path

- `DAT_00DFDC88` (uint32) — keymask low
- `DAT_00DFDC8C` (uint32) — keymask high
- `DAT_00DFDC90..93` (4 bytes) — sentinels, `+0x90 = 0xFF` init (last-pressed scancode? "no key" marker?)
- `DAT_00DFDCA4` (HANDLE) — wake event (auto-reset)
- `DAT_00DD72E8` (int32) — dialog-only: currently-held key (`-1` = none, only one at a time)
- `DAT_00DEB82C` (HBITMAP) — dialog-only: currently-displayed "button pressed" highlight overlay
- `DAT_00DEB830`, `DAT_00DEC8F4`, `DAT_00DEC8F9`, `DAT_00DEC8FA` — recording/macro flags

### Headless harness sketch (for Android / browser)

```c
// once at startup
calc_main_thread();   // runs FUN_00406430 → FUN_00401730 forever

// to press "1" (replace KEYCODE_1 with the actual value once mapped):
press_key(KEYCODE_1);   // FUN_0043BE90
WaitForSingleObject(some_done_signal, 100);  // or just sleep a frame
release_key(KEYCODE_1); // FUN_0043BED0
// framebuffer at DAT_00DEC9F8 + 0x5C now contains the updated screen — dump it

// to do "1+1=" :
press_key(KEYCODE_1); ...release; press(PLUS); release; press(1); release; press(ENTER); release;
// read framebuffer, find the "2" rendered on screen
```

### Keycode table (extracted from `Small 39gII.skin`)

The skin file is plain text; `key=[ascii,] keycode, x1, y1, x2, y2, {win_vk_codes}` lines give us the full mapping. 51 keys numbered 0..50 (fits in the 64-bit mask).

| Keycode | Key | Notes |
|---|---|---|
| 0..5 | F1..F6 soft menu row | VK_F1..VK_F6 |
| 6, 7, 8 | Apps row (left of joypad) | VK_F7..VK_F9 |
| 9 | ↑ Up | VK_UP |
| 10 | → Right | VK_RIGHT |
| 11, 12, 13 | (below joypad) | VK_F10..VK_F12 |
| 14 | ← Left | VK_LEFT |
| 15 | ↓ Down | VK_DOWN |
| 16..19 | (4 keys row 4) | no VK |
| 20 | Backspace / Del | VK_DELETE, VK_BACK |
| 21..25 | (5 keys row 5) | no VK |
| 26..30 | (5 keys: ?, ?, `(`, `)`, `/`) | ASCII labels on 28-30 |
| 31..35 | (5 keys: ?, `7`, `8`, `9`, `*`) | |
| 36 | Tab/menu | VK_TAB |
| 37..40 | `4`, `5`, `6`, `-` | |
| 41 | Shift/Ctrl modifier | VK_CONTROL |
| 42..45 | **`1`**, **`2`**, **`3`**, **`+`** | |
| 46 | ON / Cancel | VK_ESCAPE |
| 47 | **`0`** | |
| 48 | (separator?) | |
| 49 | `.` decimal | VK_NUMPAD_SUBTRACT (numpad minus repurposed) |
| 50 | **ENTER** | VK_RETURN |

---

## Headless harness (calc-OS-only, no Windows) — **M1 done 2026-05-17**

Goal: load `HP39gII.exe` into a Unicorn x86 sandbox and run the calc core with
zero Windows underneath. Same "1+1=ENTER" framebuffer as the native probe is
the eventual M3 target. After M3, the artifact (PE + tiny shim + Unicorn) ports
straight to Wasm/Android.

**Files:**
- `harness/headless/load.py` — PE loader + Unicorn sandbox + Win32 shim
- `harness/headless/tests/test_m1_landmarks.py` — landmark regression test

### M1 deliverables (working)

- **PE loader** — maps `HP39gII.exe` into Unicorn at `0x00400000` (image base
  matches, no ASLR, no relocations needed). Image span 0x400000–0xE10000.
- **Segment setup** — `UC_X86_REG_FS_BASE` is a no-op in Unicorn 32-bit, so we
  build a 4-entry GDT (null + ring-0 code + ring-0 data + FS-at-TIB), write
  GDTR, and **explicitly reload CS/SS/DS/ES/FS/GS** so cached segment
  descriptors (base/limit/flags) refresh from our GDT. Skipping the segment
  reload makes SS keep a stale 16-bit cache → all stack accesses truncate to
  the low 16 bits and PUSH faults at the first instruction.
- **IAT dispatcher** — every imported function gets a unique trampoline address
  in `[0x20000000, 0x20010000)`. The IAT slot is patched to that address. A
  Unicorn code hook traps on entry: read return addr + 8 args from stack, run
  our handler, simulate stdcall return (set EAX, pop ret-addr + args, jump).
  362 imports across 15 DLLs.
- **Internal hooks** — replace the binary's bundled MSVCRT entirely. Hooks at
  `0x009618ae` (`operator new` wrapper), `0x00972c50` (static `_malloc`),
  `0x009721a0` (`_free`), `0x009729e6` (`_realloc`). With these in place we
  never enter MSVCRT init at all, which otherwise calls LoadLibraryA, fails
  (no real DLLs), and reaches ExitProcess.
- **Win32 shim surface** — ~70 stdcall handlers (CreateMutex, CreateEvent,
  CreateThread, Wait*, Tls*, Reg*, CreateFile, Find*, Get/Set Locale, etc.).
  Critical: every shimmed function must declare its arg count even when it just
  returns 0, otherwise stack drift accumulates and trips the binary's
  `__report_gsfailure` stack-cookie check at the next function epilogue.

### Verified landmarks (assertion test passes)

Running `FUN_00406430` (the calc-core thread proc) directly:

1. `SetUnhandledExceptionFilter(0x00406420)` — SEH filter install
2. `CreateMutexW(NULL, TRUE, NULL)` → handle stored at `0x00DEB828`
3. Six state-struct mallocs **in the exact predicted order and sizes**:
   - `calc_malloc(84)` → `DAT_00DECA04` (0x54)
   - `calc_malloc(136)` → `DAT_00DECA08` (0x88)
   - `calc_malloc(152)` → `DAT_00DEC9F8` (0x98) — root CDesktop
   - `msvcrt_malloc(10922)` — **the framebuffer** (127 × 86, predicted size)
   - `msvcrt_realloc(., 10930)` — 8-byte tail padding from `ADD EAX, 0x8`
   - (silenced) `calc_malloc(3000)` → `DAT_00DECA00`
   - (silenced) `calc_malloc(0xB18C)` → `DAT_00DEC9FC`
4. `CreateThread(start=0x407be0)` — the conn-kit thread. Stubbed (handle
   returned but no thread actually started — we don't need USB HID).
5. Init falls through HID/SetupDi enumeration (all returning empty) into
   `APPDATA` lookup, `CreateDirectoryW(...)` for the config dir, then
   `FindFirstFileW/FindNextFileW/FindClose` scanning for saved skins/state.
6. Eventually faults at `EIP=0x0094463e` reading address 0: `FUN_00944630`
   dereferences `PTR_DAT_00c18d00[FUN_00942490()]`, which is NULL. That table
   is populated by a calc-side init that runs before the thread does in the
   real app — first thing for M2 to chase.

200 IAT/internal events, 128 KB heap consumed before the fault — solidly into
late-init, well past every M1 landmark.

### Next: M2

Continue the boot from the `0x94463e` NULL-deref. Two paths:
- find what populates `PTR_DAT_00c18d00` and call it manually before the calc
  thread starts (most likely a font/widget-init function called from
  `CAspen_cDlg::OnInitDialog` before it spawns the calc thread), or
- hook `FUN_00935680` to return a non-NULL pointer to a synthetic table.

After M2: M3 = inject `enqueue_event + press_key + release_key` for the
"1+1=ENTER" sequence, dump framebuffer at `DAT_00DEC9F8+0x14`, decode via the
existing 3-px/byte formula, emit PNG, diff against the native-harness gold.

### M2 done 2026-05-17 — calc boots to main loop entry

Test: `harness/headless/tests/test_m2_boot.py` — asserts `emu_start` returns
cleanly at `FUN_00401730` and the framebuffer pointer is reachable.

Three obstacles fixed (each chased by a single fault → root cause → minimal
patch):

1. **`FUN_00944630` NULL-deref via PTR_DAT_00c18d00.** Root cause:
   `DAT_00DECA00 + 0x584` (the "current font count") is 0 because we never
   loaded `calc.settings`. `FUN_00935660(&0)` then sets the index to
   `(0 + (-1)) = 0xFFFFFFFF`; `[0xFFFFFFFF*4 + 0xc18d00]` wraps to
   `[0xc18cfc]` which holds 0. **Fix:** internal hook stubs `FUN_00944630`
   to no-op (it sets two widget width/height fields; nothing on the boot
   path needs those values).
   > **SUPERSEDED 2026-05-26:** the no-op was wrong — those width/height
   > fields ARE the edit-line region size, so no-op'ing them clipped typed
   > glyphs. `FUN_00944630` is now faithfully reimplemented (reads the real
   > embedded font height). See the Current-status banner at the top.
2. **`DAT_00DEB7E4` NULL pointer.** `FUN_00406430` reads `[ptr+0x20]` to
   grab the dialog HWND and stash it in `DAT_00DECA00 + 0xbb4` for the
   core→dialog bridge. In the real app, MFC sets this when the dialog
   constructs; in our headless world there's no dialog. **Fix:** pre-allocate
   a zeroed 1 KB dummy object and plant its address into `DAT_00DEB7E4`
   before starting the thread. The bridge then "publishes" HWND = 0, which
   is fine — no caller in the boot path dereferences it.
3. **`_aulldiv` divide-by-zero in `FUN_0043bf10` (elapsed-time helper).**
   The 64-bit divide uses `DAT_00DFDCA8` (perf frequency) as the divisor,
   which was never initialized. Normally set by `QueryPerformanceFrequency`
   at app startup. **Fix:** pre-write `1` to that QWORD before boot. The
   elapsed-time helper now returns nonsense values but doesn't fault, and
   nothing on the boot path actually inspects the result.

Boot trace (~204 IAT/internal events, 131 KB heap consumed):
`SetUnhandledExceptionFilter` → `CreateMutexW` → 6 state-struct mallocs
→ framebuffer alloc + realloc → conn-kit `CreateThread` (stubbed) →
HID/SetupDi enumeration (empty) → `APPDATA` lookup + dir creation →
`FindFirstFileW` scanning for saved skins/state → `FUN_00944630` (now
stubbed) → `CreateEventW` (keyboard wake event) → 2nd
`SetUnhandledExceptionFilter` → **halt at `FUN_00401730`**.

The pattern that emerged: every M2 fault was a piece of host-side state the
*Windows shell* would have set up but we skipped by entering the calc thread
directly. The fix is always one of: stub the function, plant a value at a
well-known global, or both.

### M3 done 2026-05-17 — "1+1=ENTER" runs headless, framebuffer matches native shape

**Result:** with zero Windows underneath (only Unicorn emulating x86 + our
~70-function Win32 shim), the calc executes "1+1=ENTER" and renders the
expected display: "1+1" on the left edit line, "2" on the right answer column,
with the "RAD"/"Function" header and "STO ▸" soft menu.

The end-to-end M3 PNG of the ENTER frame is at
`harness/headless/frames/04_ENTER.png` (3× upscaled).

5 distinct framebuffer MD5s observed (versus 5 in the native session — see
2026-05-17 probe entry above):

```
  boot  : ea473a93d7b9314110d987b9f85af3cd   (0 nonzero)
  1     : d0e1fab0dd04f2857096ef392bc87d53   (2579)
  +     : f7856b151d7c90efaecac32c55cead95   (2579)
  1     : 8e7780c60e8cefd38b2a6b3c5139a84b   (2582)
  ENTER : 487d5e277790c68f3c09c117fac7b119   (2611)  -- "2" drawn
```

#### What M3 needed beyond M2

A "step the calc one tick" mechanism, because there is no thread running the
main loop — we call into emulated functions directly from the host. Per key,
this is exactly what the main loop does after a wake:

```python
# build event payload {1, keycode}, enqueue into the 8-slot ring at DAT_00DECA08
enqueue_event(queue=*DAT_00DECA08, evt_type=0, payload)   # FUN_00941210
press_key(keycode)                                          # FUN_0043BE90 — sets keymask bit
# pre-drain flag fixups (clear state[+0x2c] bit 10, set state[+0x90] bit 4)
drain_queue(queue, host_bridge[+0x20])                     # FUN_00942310
tick(state, 0)                                              # FUN_00944270 — paint
release_key(keycode)                                        # FUN_0043BED0 — clears keymask bit
drain_queue(...); tick(...)                                 # second pass for release
```

#### Three more "missing host-side state" fixes M3 needed (same pattern as M2):

1. **`DAT_00DECA00 + 0x584 = 1`** (font count). Otherwise `FUN_00935660`
   underflows the index from 0 to 0xFFFFFFFF, all over the widget code.
   Normally read from `calc.settings`.
   > **SUPERSEDED 2026-05-26:** `+0x584` is the default font *index*, not a
   > count, and the correct value is **2** (the embedded h=16 font) so the
   > edit line is sized right. See the Current-status banner at the top.
2. **Pre-drain state-flag manipulations.** Before calling drain, the main
   loop clears `state[+0x2c] & 0x400` and sets `state[+0x90] | 0x10`. Without
   these the calc's "fresh input pending" path doesn't engage.
3. **Calling convention correction (RESEARCH_NOTES error).** The earlier
   table said `press_key`/`release_key` take keycode in ECX; **wrong**. The
   actual disassembly is `MOV ECX, [ESP+4]` — it's __cdecl with one stack
   arg. The native probe's working code did pass the keycode on the stack;
   the table was the bug.

#### Calling-convention helper (`m3_one_plus_one.py:call_emu`)

Since we're driving emulated functions from the host with a mix of fastcall,
thiscall, stdcall, and cdecl, the harness has a single `call_emu(uc, fn_va,
ecx, stack_args)` helper that:
- sets ECX,
- pushes stack args right-to-left,
- pushes a sentinel return address,
- starts emu_start at the function VA,
- halts on the sentinel.

The sentinel address must be **mapped** (Unicorn fetches an instruction byte
before the code hook fires); we map a 4KB page at `0x21000000` and place a
single `RET` (`0xC3`) byte there as a safety net.

#### Files

- `harness/headless/load.py` — PE loader + Unicorn boot + Win32 shim (M1-M2)
- `harness/headless/m3_one_plus_one.py` — boot wrapper + key-injection runner
- `harness/headless/tests/test_m1_landmarks.py` — assertion: init landmarks
- `harness/headless/tests/test_m2_boot.py` — assertion: reaches main loop
- `harness/headless/tests/test_m3_one_plus_one.py` — assertion: 5 distinct frames
- `harness/headless/frames/*.{pgm,png}` — captured framebuffer dumps

### What's next

The headless calc artifact (`HP39gII.exe` + `load.py` + `m3_one_plus_one.py`)
is now portable. Three plausible directions:

1. **Browser POC.** Compile Unicorn to WASM (already exists as `unicorn.js`),
   port the shim to JS, embed the EXE as a `Uint8Array`. ~10MB initial
   download + ~5MB Unicorn engine; fits one Web page.
2. **Android.** Unicorn has native ARM64/AArch64 builds; JNI surface is tiny
   (key in → framebuffer out). The shim ports to Kotlin/C without changes.
3. **Coverage breadth.** Drive more keys (full keyboard map already in
   notes), exercise apps, graphing, equation writer — turn this into a
   regression-grade headless test suite for the calc-OS behavior.

---

## Web port attempt 2026-05-17 — **dead end on AlexAltea unicorn.js (1.0.1)**

We tried direction (1) using AlexAltea/unicorn.js — Unicorn 1.0.1 compiled
to asm.js via emscripten (~2017). The Phase A scaffolding works (page loads,
PE parses, keypad renders), but **Phase B is blocked by engine bugs** in 1.x.

**What got built and works:**
- `web/index.html` — calculator face, 256×127 canvas, 51-key keypad, status pane
- `web/pe-loader.js` — PE parser in pure JS (matches `pefile` output exactly:
  362 imports across 15 DLLs, correct VAs and section layout)
- `web/shim.js` — ~70 Win32 handlers + `STDCALL_ARGC` + `INTERNAL_HOOKS`
  (line-for-line port of `load.py`)
- `web/loader.js` — GDT/FS setup, IAT trampolines, code-hook dispatcher
- `web/main.js` — orchestrator, fetches the binary, drives boot
- `web/_node_*.cjs` — Node harness scripts using `vm.runInContext` to run
  the same JS files outside the browser for fast iteration

**Two bugs that defeated us, both confirmed via reduced-case Node tests:**

1. **`reg_write` from inside a HOOK_CODE callback doesn't propagate to the
   next basic block.** Smoke test: hook fires at a RET, writes `EAX=0x1000`;
   then `ADD EAX, 1` in the caller's block runs with the old (zero) EAX.
   Confirmed by reading EAX from inside subsequent hooks — the
   *register-read view* shows our write, but TCG-executed instructions
   don't. Likely a bug in 1.x's TCG-temp / saved-register sync at block
   boundaries.

2. **Bytes written into the PE image region don't change what the engine
   executes.** We hit this trying to install internal hooks. Wrote
   `MOV EAX, 0xDEADBEEF; RET` at `calc_malloc` (0x009618ae). The bytes
   read back correctly, but after the call EAX was still 0 — the engine
   executed the *original* calc_malloc body. Same when we tried a 5-byte
   `JMP rel32` redirect to a fresh trampoline. Translation cache
   invalidation issue, apparently.

   IAT trampolines at a freshly mem_map'd region (TRAMP_BASE = 0x20000000)
   do work — `CreateMutexW`'s `0x80000001` handle reached the calc's
   `DEB828` storage correctly via a `MOV EAX, [slot]; RET imm16` stub.
   The bug is specific to bytes overwritten *inside an already-mapped
   region* (the PE image).

**Approaches that did NOT work (so we don't try them again):**
- Setting EAX via `reg_write` from a HOOK_CODE callback (bug #1).
- `RET`-style trampolines at TRAMP_BASE that splice args by `reg_write`-ing
  ESP (same bug).
- Resume-loop pattern: catch the bug-induced early stop, re-enter
  `emu_start` from the new EIP (works for a few iterations, then EAX stays
  stale).
- Self-modifying code at calc-image hook entries (bug #2).
- 5-byte `JMP rel32` redirection from calc-image into a fresh trampoline
  region (bug #2 — the JMP itself isn't honored).

**Approaches we'd try if forced to ship on 1.x:**
- Pre-rewrite the loaded image to redirect CALLs *before* execution starts,
  so the engine sees the patched bytes on first translation. Might dodge
  bug #2. Untested; we abandoned 1.x first.

**Conclusion:** AlexAltea's 1.x is too buggy for this binary. Going forward:
- **Web (deferred)** → build Unicorn 2.x to WASM ourselves via emscripten.
  The JS loader/shim/UI we just wrote are mostly correct and slot in on top
  of a working engine.
- **Android (next)** → uses native libunicorn 2.x via NDK. No WASM, no
  bugs. The Python harness `harness/headless/load.py` ports to C with
  minimal logical changes.

### Next-session todo (2026-05-17 → next)

1. User does Termux test before the session: install `unicorn` + `pefile`
   via pip, copy `harness/headless/` to phone, run `m3_one_plus_one.py`,
   verify framebuffer renders. Half-hour task.
2. User creates an empty-activity Android Studio project before the
   session. We pick it up from there and:
   - Add NDK + CMake glue
   - Cross-compile Unicorn 2.x (or use a maintained prebuilt)
   - Port `load.py` → `loader.c` (PE map, GDT, IAT trampolines, shim
     handlers — straight translation now that all the unknowns are solved)
   - Wire a minimal JNI bridge: `boot()`, `inject_key(int kc)`,
     `get_framebuffer() -> ByteArray`
   - Compose UI: 256×127 canvas + 51-key keypad (layout already in
     `web/main.js`'s `KEYS` array)
3. *Later:* return to the web port and build Unicorn 2.x → WASM with
   emscripten. The JS scaffolding (`web/*.js`) is preserved and reusable.

---

### "1+1=" milestone — concrete call sequence

```c
press_key(42); release_key(42);   // "1"
press_key(45); release_key(45);   // "+"
press_key(42); release_key(42);   // "1"
press_key(50); release_key(50);   // ENTER
// framebuffer at DAT_00DEC9F8 + 0x5C now shows "1+1\n2"
```

### Pixel encoding — CONFIRMED via FUN_009462d0 and empirical decode (2026-05-17 session)

The accessor `get_pixel(self, x, y) = ((byte << 8) >> (shift + 8)) & 7` where `(byte_offset, shift)` is a per-column lookup at `DAT_00C1B9E8` (2 bytes per X coordinate).

**Per-byte layout (3 pixels packed in 3+3+2 bits):**

| Pixel | Position | Bits | Value range |
|---|---|---|---|
| 0 | x=byte_idx*3   | bits [7:5] = `(byte >> 5) & 7` | 0-7 (3-bit) |
| 1 | x=byte_idx*3+1 | bits [4:2] = `(byte >> 2) & 7` | 0-7 (3-bit) |
| 2 | x=byte_idx*3+2 | bits [1:0] = `(byte << 1) & 7` | 0/2/4/6 (2-bit ×2) |

For width=256 / pitch=86: 85 bytes hold 3 pixels each (255 pixels) + 1 extra byte for pixel 255. Total 86×8=688 bits encoding 256 pixels = 2.69 bits/pixel average.

**Display mapping:** `displayed_level = internal_pixel >> 1` → 4 grayscale levels (0..3), indexed into a 4-color palette built in `FUN_009489f0`. Palette includes `0xAAAAAA` and `0x555555` (mid-grays), plus skin's `screenfore` (black) and `screenback` (greenish-gray) — these are the visible LCD colors.

**The clever trick:** internal precision is 3 bits per pixel (8 levels) for most pixels, allowing smooth dithering / blending; the 2-bit-only pixels (every 3rd one) lose half precision internally, but since the final display only has 4 levels (after `>>1`), the visible loss is ZERO. A genuinely elegant embedded encoding.

**Verified end-to-end:** `harness/decode_fb.ps1` decodes any dumped framebuffer to PGM + ASCII using this formula. `harness/diff_fb.ps1` highlights what changed between two dumps. Running these on the 5 dumps from the "1+1=ENTER" probe session showed clearly recognizable digits drawn one keystroke at a time and a full result-area redraw on ENTER.

### Framebuffer layout — CONFIRMED via FUN_00948950

`FUN_00945540(state, 256, 127)` (called from the calc-init thread) configures the calc state struct as a `CDesktop` (inheriting `Cwindow` → `Cbitmap`) and allocates the framebuffer via `FUN_00948950`:

```c
void FUN_00948950(CDesktop *self) {
    int pitch = (self->width + 2) / 3;       // ceil(width / 3)
    size_t size = self->height * pitch;
    self->pitch = pitch;                     // at offset +0x28
    self->framebuffer = malloc(size);        // at offset +0x14
    memset(self->framebuffer, 0, size);
}
```

For the calc (256 × 127):
- **pitch = (256 + 2) / 3 = 86 bytes/row**
- **size = 127 × 86 = 10,922 bytes**

The `(width+2)/3` formula means **3 pixels are packed per byte** → ~2.67 bits/pixel → almost certainly **2 bits per pixel (4 grayscale levels) with 2 padding bits per byte**. The calc has 4 shades, not the 2 our earlier notes claimed.

#### Definitive `DAT_00DEC9F8` (CDesktop) layout

| Offset | Type | Field | Confirmed by |
|---|---|---|---|
| `+0x00` | vtable* | CDesktop::vftable | FUN_00945540 |
| `+0x0C` | int32 | width = 256 | FUN_009454d0 sets from arg |
| `+0x10` | int32 | height = 127 | FUN_009454d0 sets from arg |
| `+0x14` | uint8* | **framebuffer base (10,922 bytes)** | FUN_00948950 malloc |
| `+0x28` | int32 | pitch = 86 (bytes/row) | FUN_00948950 |
| `+0x5C` | uint8* | "active draw target" (usually == +0x14, redirected during offscreen ops) | FUN_0040d750 reads this |
| `+0x90` | uint32 | runtime flag bits (0x10, 0xc bits manipulated by FUN_00944270) | |
| `+0x2c` | uint32 | another flag word (bits 0x400 / 0x800) | |
| `+0x1c` | ptr | another draw-context ptr (saved/restored around blits) | FUN_0040ca40 |

Inheritance climb (via vtable overwrites in FUN_009454d0):
```
*self = Cbitmap::vftable;   → ... init Cbitmap fields ...
*self = Cwindow::vftable;   → ... init Cwindow fields ...
*self = CDesktop::vftable;  (final, by caller FUN_00945540)
```

So the root calc state struct IS a widget (the CDesktop). The whole calc is a widget tree rooted there. **The "global state" is literally the root window.**

### Other skin metadata (useful for the Android renderer)

- `MATRIX=256,127,86,20` — calc display is 256×127 pixels, positioned at skin coords (86, 20).
- `screen=21,58,256,147` — display+annunciator area on skin (height 147 includes the annunciator row above the 127-px LCD).
- `screenfore=000000` `screenback=9eA495` — pixel colors: black foreground, greenish-gray HP LCD background.
- `indic=N,x,y,w,h` — annunciator indicator positions (shift, alpha, busy, transmit, low-battery, etc.), all at y=58 just above the LCD.

---

## 1. What is HP39gII.exe?

- **File:** `HP39gII.exe` — 10,454,232 bytes (10.0 MB), dated Nov 10 2013
- **Format:** PE32 executable (GUI) Intel 80386, for MS Windows, 4 sections
- **Image base:** `0x00400000`
- **Entry point VA:** `0x00971CF8` (file offset `0x5710F8`)
- **Internal codename:** "Aspen" (`CAspen_cApp`, `CAspen_cDlg`)
- **NOT an ARM emulator** — the entire calculator (OS, apps, CAS, PPL interpreter) was recompiled natively for x86 from C++ source
- The physical HP 39gII uses a Freescale i.MX233 ARM SoC, but this exe has zero ARM code
- Built with MSVC, uses MFC (Microsoft Foundation Classes) statically linked
- Contains **Giac/Xcas v0.4.0** (open-source CAS engine, GPL) as the math backend

---

## 2. PE Sections

| Section | Virtual Address | Virtual Size | Raw Offset | Raw Size | Flags |
|---------|----------------|-------------|------------|----------|-------|
| `.text` | `0x00001000` | `0x0062BA99` (6.5MB) | `0x00000400` | `0x0062BC00` | CODE, EXEC, READ |
| `.rdata` | `0x0062D000` | `0x003A9A82` (3.8MB) | `0x0062C000` | `0x003A9C00` | INIT_DATA, READ |
| `.data` | `0x009D7000` | `0x0002BA3C` | `0x009D5C00` | `0x00014800` | INIT_DATA, READ, WRITE |
| `.rsrc` | `0x00A03000` | `0x0000C0D8` | `0x009EA400` | `0x0000C200` | INIT_DATA, READ |

**Note:** `.data` virtual size (`0x2BA3C` = 178KB) is much larger than raw size (`0x14800` = 82KB). The difference is BSS (uninitialized data, allocated at runtime). The global calculator state object lives in this BSS area.

---

## 3. The Architecture — Two Layers

### Layer 1: Calculator Core (platform-independent, the bulk of the 10MB)
All apps, graphers, evaluators, the HP PPL interpreter, the equation writer, and the Giac CAS. This code writes to an in-memory **256×127 pixel framebuffer** and reads key events. It has its own widget system (CChoose, CMessageBox, CEqw2, CTerminal, etc.) that renders to the framebuffer, NOT to Windows.

### Layer 2: Windows Shell (thin MFC wrapper)
- `CAspen_cApp` — MFC application entry, WinMain
- `CAspen_cDlg` — Main dialog window, loads skin BMP, handles Windows messages, maps mouse clicks to calculator key codes
- `CVirtualLCD` — A CWnd-derived class that receives the framebuffer and paints it to the Windows window via `StretchDIBits`/`BitBlt`
- `CScreenShotDlg`, `CAboutDlg` — auxiliary dialogs

**The connection between layers is minimal:**
1. Framebuffer: calc core writes pixels → `CVirtualLCD` blits to screen
2. Input: Windows mouse/keyboard events → translated to calculator key codes → fed to core
3. Indicators: annunciator row (shift, alpha, battery, etc.)

---

## 4. The Global Calculator State Object

**Address:** `0x00DEC9F8` (in BSS, runtime-only — not in the file on disk)

This is THE calculator. A single global pointer referenced **675 times** throughout `.text`. Every part of the core reads/writes through it.

### Key field offsets (by access frequency):

| Offset | Dec | Accesses | Likely Purpose |
|--------|-----|----------|----------------|
| `+0x5C` | 92 | **392** | Almost certainly the framebuffer pointer or primary display context |
| `+0x24` | 36 | 74 | Possibly key state or operational flags |
| `+0x0C` | 12 | 47 | Frequently accessed — internal state |
| `+0x2C` | 44 | 45 | Bitfield operations observed (AND mask `0xFF...`) |
| `+0x10` | 16 | 24 | |
| `+0x18` | 24 | 17 | |
| `+0x90` | 144 | 17 | |
| `+0x50` | 80 | 14 | |
| `+0x0174` | 372 | 8 | |
| `+0x30` | 48 | 8 | |

---

## 5. The Framebuffer

### Screen dimensions
- **256 × 127 pixels** — matches the real HP 39gII LCD
- Skin file confirms: `MATRIX=256,127,86,20` and `screen=29,38,512,294` (the 256×127 is scaled to 512×294 on the skin)

### Screen region descriptors (found at file offset `0x680DA0` in `.rdata`):
```
{0, 256, 127, 0x00DEC9F8}  — full screen
{0, 256, 111, 0x00DEC9F8}  — main area (below indicator row)
{111, 256, 16, 0x00DEC9F8} — indicator/softkey row
```
The pointer `0x00DEC9F8` appears in these structs — confirming it's the central display context.

### Framebuffer format
- Likely **2-color grayscale** (not full 8-bit grayscale)
- Evidence from `StretchDIBits` call site (VA `0x948B20`): the code sets up a `BITMAPINFO` struct on the stack with:
  - `biSize = 40` (standard BITMAPINFOHEADER)
  - Color table: `0x00AAAAAA` (light gray) and `0x00555555` (dark gray)
  - These are the two LCD pixel shades — matching the real calculator's greenish-gray LCD
- Framebuffer size candidates found in code: 32,512 bytes (256×127×1) found 4 times, 32,768 bytes (256×128 padded) found 128 times

### StretchDIBits — the ONE place the framebuffer reaches Windows
- Called from exactly **1 location**: VA `0x00948B20` (file offset `0x948B20`)
- This is where the framebuffer pixel data is sent to the screen via GDI
- In our custom build, this is the single interception point for display output

### BitBlt call sites (5 total):
- `0x402A2E`, `0x4094B6`, `0x409D41`, `0x409E9D`, `0x40AAC8`
- These handle the skin/window compositing, not the calculator LCD content

### StretchBlt call sites (2 total):
- `0x4094E9`, `0x40AE5B`

---

## 6. CVirtualLCD Class

- **RTTI type_info at:** file `0x9D66A4`, VA `0x00DD7AA4`
- **Vtable at:** file `0x62E47C`, VA `0x00A2F47C`
- **20 virtual functions**, 16 shared with CAspen_cDlg (inherited from CWnd base class)
- **4 unique functions** (the display-specific ones):

| Slot | VA | Purpose |
|------|-----|---------|
| 0 | `0x0040A8D0` | Destructor — cleans up DCs and bitmaps (fields at +0x54, +0x5C, +0x60) |
| 1 | `0x0040AA30` | **Paint/Blit function** — calls BitBlt with SRCCOPY (`0x00CC0020`), this is where framebuffer goes to screen |
| 3 | `0x009627F6` | Message handler (likely WM_PAINT or similar) |
| 10 | `0x0040AF30` | Window procedure / creation related |

### CVirtualLCD::vfunc1 (Paint) — VA `0x0040AA30`
Key sequence:
1. Gets bitmap handles from object fields `+0x60` and `+0x5C`
2. Calls `SelectObject` to select bitmap into DC
3. Reads display dimensions from globals at `0x00DFDE2C`, `0x00DFDE30`, `0x00DFDE34`
4. Pushes `0x00CC0020` (SRCCOPY) 
5. Calls `BitBlt` (at `0x40AAC8`) to blit framebuffer to window DC
6. Releases DC

---

## 7. CAspen_cDlg Class (The Windows Shell)

- **RTTI at:** file `0x9D5F2C`
- **Vtable at:** VA `0x00A2E484`
- 30 virtual functions (many inherited from CWnd/CDialog MFC base)

---

## 8. Windows API Dependency Analysis

### Total: 976 `FF 15` (call [IAT]) instructions across the entire 6.5MB .text section

That's only 976 Windows API calls in ~193,000 total CALL instructions = **0.5% Windows dependency**.

### By category:

| Category | Call Count | Notes |
|----------|-----------|-------|
| **Can stub/ignore** | 198 | GetLastError, GetModuleHandle, GetVersion, etc. |
| **Window/MSG** | 151 | SendMessageW(31), GetParent(13), GetWindowLongW(10), etc. |
| **Threading** | 136 | CriticalSection(48), InterlockedXxx(23), Sleep(9), CreateThread(3) |
| **String/Locale** | 66 | WideChar/MultiByte, strcmp, locale info |
| **Display/GDI** | 60 | DeleteObject(11), CreateCompatibleDC(8), BitBlt(5), StretchDIBits(1) |
| **Memory** | 60 | HeapAlloc/Free, GlobalAlloc/Lock, VirtualAlloc |
| **File I/O** | 52 | WriteFile(11), ReadFile(8), CreateFileW(5) |
| **Uncategorized** | 253 | Menus, registry, clipboard, COM — mostly stub-able |

### Top 10 most-called APIs:
1. `GetLastError` — 52× (return 0)
2. `SendMessageW` — 31× (MFC internal, needs some handling)
3. `LeaveCriticalSection` — 28× (map to mutex unlock)
4. `EnterCriticalSection` — 20× (map to mutex lock)
5. `GetProcAddress` — 18× (dynamic loading, needs real impl)
6. `GetModuleHandleW` — 15× (return fake handle)
7. `SetLastError` — 15× (no-op)
8. `InterlockedDecrement` — 15× (atomic dec)
9. `GetSubMenu` — 13× (MFC menus, stub)
10. `GetParent` — 13× (MFC windowing, stub)

### DLL import summary:
| DLL | Functions Imported | Functions Actually Called |
|-----|-------------------|-------------------------|
| KERNEL32.dll | 151 | Many — memory, threads, files |
| USER32.dll | 127 | Window management, messages |
| GDI32.dll | 35 | Display: BitBlt, StretchDIBits |
| gdiplus.dll | 11 | Image save (screenshots only) |
| ADVAPI32.dll | 9 | Registry (settings persistence) |
| HID.DLL | 5 | USB to physical calc (not needed) |
| SETUPAPI.dll | 4 | Device enumeration (not needed) |
| HPUpdateCheck.dll | 2 | Update checker (not needed) |
| Others | ~18 | Mostly stub-able |

---

## 9. RTTI Class Map — The Full Architecture

### Calculator Core Classes (TO PRESERVE):
**Graphers:** `FunctionGrapher`, `ParametricGrapher`, `PolarGrapher`, `SequenceGrapher`, `SolveGrapher`, `StatGrapher`, `Stat1VarGrapher`, `Stat1VarBarGrapher`, `Stat1VarBoxWhiskGrapher`, `Stat1VarHistGrapher`, `Stat1VarLineGrapher`, `Stat1VarNPPGrapher`, `Stat1VarParetoGrapher`, `Stat2VarGrapher`, `CInferPlot`, `CStreamerPlot`, `ABCPlotter`, `Grapher`

**Evaluators:** `FunctionEvaluator`, `ParametricEvaluator`, `PolarEvaluator`, `AccelEvaluator`, `CobwebEvaluator`, `StaircaseEvaluator`, `OwnedHPEvaluator`, `Evaluator`, `EvalTeller`

**UI Widgets (render to framebuffer, NOT Windows):** `CChoose`, `CCharChooser`, `CTerminal`, `CEqw2` (equation writer), `CMessageBox`, `CLabel`, `CLabelString`, `CEQList`, `CStatEditor`, `CNumView`, `ABCNumView`, `CDebWindow`, `PatWindow`

**Internal types:** `Cbitmap`, `Cdialog`, `Cimage`, `Clist`, `Cmenu`, `Ctext`, `Cwindow` — these are the calc's OWN UI primitives (lowercase 'C' prefix), not MFC

**Display:** `CVirtualLCD`

### MFC/Windows Classes (TO REPLACE):
`CWinApp`, `CWinThread`, `CWnd`, `CDialog`, `CCmdTarget`, `CObject`, `CDC`, `CPaintDC`, `CClientDC`, `CBrush`, `CPen`, `CGdiObject`, `CBitmap` (MFC one), `CMenu`, `CStatic`, `CSliderCtrl`, `CFileDialog`, `CFileFind`, `CHandleMap`, `CMapPtrToPtr`, `CObArray`, `CPtrArray`, `CByteArray`, `CWordArray`, `CAfxStringMgr`, plus various AFX_* internal MFC state classes

### Windows Shell Classes (TO REPLACE):
`CAspen_cApp`, `CAspen_cDlg`, `CScreenShotDlg`, `CAboutDlg`, `CCommandLine`, `CDesktop`

---

## 10. HP PPL Commands Found in Binary

The full HP PPL (Programming Language) command set is implemented:
`ARC`, `ARC_P`, `BLIT`, `BLIT_P`, `BREAK`, `CASE`, `CHOOSE`, `CONTINUE`, `DEFAULT`, `DIMGROB`, `DIMGROB_P`, `DISPLAY`, `EDITMAT`, `ELSE`, `EXPORT`, `FOR`, `FREEZE`, `GETKEY`, `GROBH`, `GROBH_P`, `GROBW`, `GROBW_P`, `IF`, `IFERR`, `INPUT`, `LINE`, `LINE_P`, `LOCAL`, `MAKEMAT`, `MSGBOX`, `NEXT`, `PIXOFF`, `PIXOFF_P`, `PIXON`, `PIXON_P`, `PRINT`, `RECT`, `RECT_P`, `REPEAT`, `RETURN`, `STARTAPP`, `STARTVIEW`, `SUBGROB`, `SUBGROB_P`, `TEXTOUT`, `TEXTOUT_P`, `THEN`, `UNTIL`, `WAIT`, `WHILE`

---

## 11. Skin Files

Four skins provided: Small, Compact, Medium, Large — all `.skin` text files + `.bmp` images.

### Key skin file fields (from `Large 39gII.skin`):
```
picture=hp39gII_l.bmp          ← background image
size=1033,576                   ← window size
screen=29,38,512,294            ← LCD area on skin (256×127 scaled to 512×294)
screenfore=000000               ← LCD foreground color (black pixels)
screenback=9eA495               ← LCD background color (greenish-gray)
MATRIX=256,127,86,20            ← actual LCD resolution + position
key=N,x1,y1,x2,y2,{vkcode}     ← button hitboxes + virtual key codes
```

### Button mapping (51 keys defined):
- Keys 0-5: F1-F6 softkeys (VK codes {112}-{117} = F1-F6)
- Keys 6-8: Apps/Symb/Num softkeys (F7-F9)
- Keys 9-10, 14-15: Arrow keys (VK 37-40)
- Keys 16-50: Calculator keypad (digits, operators, special)
- Key 46: ESC ({27})
- Key 50: Enter ({13})
- Key 36: Tab ({9})

---

## 12. Approach / Plan

### Current plan: Two-phase approach

**Phase 1 — Proof of concept with BoxedWine:**
Run the full `HP39gII.exe` in BoxedWine (Wine compiled to WebAssembly). This should render the calculator in a browser canvas with full functionality, proving the concept.

**Phase 2 — Extract and optimize:**
- Use BoxedWine's x86 emulation + Wine's KERNEL32 (memory, threads, strings)
- Replace GDI32's `StretchDIBits` with a stub that writes framebuffer to JS-accessible buffer
- Replace USER32's message loop with direct key injection from web UI
- Strip out all MFC windowing code
- Result: lean calculator running in browser with custom HTML/CSS touch interface

### Alternative approaches considered:
- **v86** (full PC emulator): Too heavy, boots entire OS
- **Unicorn.js** (CPU emulator only): Too low-level, need to stub everything manually
- **Native C shim + WASM**: Write ~30 API stubs, load PE sections, compile to WASM — clean but requires more reverse engineering of init/input entry points
- **Android via Wine/Box86**: Run via Winlator on Android — works today but clunky
- **Full reverse engineering and port**: Decompile 6.5MB x86, rewrite in C — massive multi-month effort

### Key technical insight for Phase 2:
The Windows API calls go through the IAT (Import Address Table) via `FF 15 xx xx xx xx` indirect calls. The IAT is a table of function pointers. By replacing entries in this table, we can redirect any Windows API call to our own stub — without modifying any of the calculator's code. This is the cleanest interception mechanism.

---

## 13. Files in the calc directory

```
HP39gII.exe           — The main emulator executable (10MB)
HP39gII*.dll (6)      — Language DLLs (CHS, DEU, ESP, FRA, ITA, NLD)
HPUpdateCheck.dll     — Update checker DLL
*.skin (4)            — Calculator skin definitions (Small/Compact/Medium/Large)
hp39gII_*.bmp (4)     — Calculator body images for each skin size
Users_Guide_*.pdf (7) — User guides in 7 languages
Emulator_Help_*.pdf   — Emulator help in 7 languages
analyze*.py           — Our analysis scripts (can be deleted)
```

---

## 14. Notes for Future AI Session

**Context:** The user wants to extract the HP 39gII calculator engine from the Windows emulator exe and run it independently — first as a web demo (browser), eventually as an Android app. The goal is the complete authentic calculator experience (all apps, graphing, HP PPL programming, equation writer — everything), not just the Giac CAS math engine.

**What we established:**
1. The exe is pure x86 (no ARM) — HP recompiled everything for Windows
2. The architecture is cleanly two-layered: calc core (platform-independent) + thin MFC shell
3. Only 976 out of ~193,000 function calls go to Windows APIs (0.5%)
4. The framebuffer is 256×127 pixels, 2-shade grayscale, written by the core to a buffer at the global state object `0xDEC9F8 + 0x5C`
5. StretchDIBits at VA `0x948B20` is the single point where framebuffer reaches Windows
6. The IAT-based call mechanism (`FF 15`) allows clean interception of all Windows API calls

**What we haven't done yet:**
- Haven't tried running in BoxedWine
- Haven't identified the exact calculator initialization function (what to call after WinMain to start the calc core)
- Haven't identified the exact key input injection point (where key events enter the core, separate from the Windows message loop)
- Haven't confirmed the framebuffer pixel format (likely 1-bit per pixel packed, or 1-byte per pixel)
- Haven't built any actual code yet — all research/analysis so far

**Recommended next steps:**
1. **(Unblocked as of 2026-05-16)** Use the Ghidra MCP connection to:
   - Decompile `WinMain` and follow `CAspen_cApp::InitInstance` to find the calc-core boot function (the "init entry point")
   - Read the `CAspen_cDlg` window message handler to find where mouse/key events get translated to calc key codes and pushed into the core (the "input injection point")
   - Confirm framebuffer pixel packing by decompiling the `StretchDIBits` setup at VA `0x948B20` and the paint function at `0x0040AA30`
   - Enumerate xrefs to the global state object `0x00DEC9F8` to map field semantics (especially `+0x5C` framebuffer ptr, `+0x24` flags, `+0x2C` bitfields)
2. Set up BoxedWine in parallel and try running HP39gII.exe in a browser as a working baseline
3. Build the custom stripped-down version with IAT hooking
4. Create web UI with calculator skin and touch-friendly buttons; then port to Android
