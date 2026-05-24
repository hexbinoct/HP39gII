# HP 39gII — Reverse-Engineering the Calculator OS

Extracting the calculator engine out of the official **HP 39gII** Windows emulator
(`HP39gII.exe`) and running it under raw CPU emulation — no Windows, no MFC, no GUI —
so the same calculator core can be driven on **Android** and **in the browser** with our
own input and display.

This repo is the reverse-engineering work and the emulation harness. It does **not**
contain HP's binaries (see [Getting the binary](#getting-the-binary)).

---

## Why this is interesting

`HP39gII.exe` is a 10 MB MFC Windows app: the calculator is a self-contained engine
buried inside a desktop GUI shell. Instead of rewriting the calculator's math, this
project **runs HP's original x86 calculator code unmodified** inside a
[Unicorn Engine](https://www.unicorn-engine.org/) sandbox, with a hand-written Win32
shim standing in for the operating system. Map the PE, fake just enough of Windows to
keep the code happy, and drive the calculator core directly.

The payoff: the *exact* behavior of the real calculator — every rounding quirk and
display glyph — on platforms HP never shipped to.

## Status / milestones

| # | Milestone | Status |
|---|-----------|--------|
| M1 | PE loader + Unicorn x86 boot, IAT trampolines, Win32 shim | ✅ |
| M2 | Calc core boots headless, reaches main message loop | ✅ |
| M3 | Drive "1 + 1 = ENTER", dump & decode framebuffer | ✅ |
| — | **Boots under Unicorn on Android (Termux)** | ✅ |
| — | Native Android app (NDK + JNI + Compose) | 🔜 |
| — | Browser port (Unicorn 2.x → WASM via Emscripten) | 🔜 |

## Live output

These are real 256×127 framebuffers decoded straight out of the emulated calculator —
HP's own rendering code, driven headless through `1 + 1 = ENTER` (upscaled 4×):

| Boot | Press `1` | Press `+` | Press `1` | Press `ENTER` |
|------|-----------|-----------|-----------|---------------|
| ![boot](docs/screenshots/01_initial.png) | ![1](docs/screenshots/02_key_1.png) | ![+](docs/screenshots/03_key_plus.png) | ![1](docs/screenshots/04_key_1_again.png) | ![=](docs/screenshots/05_key_enter.png) |

The final frame shows `1 + 1` evaluating to `2` on the entry line — produced entirely by
the original firmware, no GUI, no Windows.

## How it works

- **`harness/headless/load.py`** — the core. Maps the PE at its image base, sets up a
  GDT/TIB so 32-bit segment registers work, hooks every Import Address Table entry, and
  implements ~69 Win32 / CRT shim handlers (heap, threads, mutexes, file probes). Boots
  the calc-core thread and halts at the main loop entry.
- **`harness/headless/m3_one_plus_one.py`** — boots headless, then calls directly into
  emulated functions to inject keys and dump the 256×127 framebuffer to PGM, with MD5s
  for comparison against the native reference.
- **`harness/`** — native Windows probes (`inject.cpp`, `probe.cpp`) used to capture
  "gold" framebuffer output from the real emulator for differential validation.
- **`analyze_*.py`** — Ghidra-assisted analysis scripts mapping out the core, imports,
  display, framebuffer, and startup paths.
- **`web/`** — early browser port experiment (asm.js Unicorn). See `RESEARCH_NOTES.md`
  for why this is being redone with Unicorn 2.x → WASM.
- **`RESEARCH_NOTES.md`** — the full reverse-engineering logbook: struct layouts,
  function addresses, the widget/paint model, skin format, and dead-ends.

## Getting the binary

This project needs `HP39gII.exe` from HP's free emulator, which is **not** redistributed
here (it's HP's copyrighted software). Obtain it from HP's official download for the
HP 39gII connectivity/emulator package, then place `HP39gII.exe` either:

- next to `harness/headless/load.py`, or
- at the repo root, or
- anywhere, and point to it: `HP39GII_EXE=/path/to/HP39gII.exe`

## Running the headless harness

```bash
pip install unicorn pefile
python harness/headless/load.py          # boot to main loop (M1/M2)
python harness/headless/m3_one_plus_one.py   # drive 1+1= and dump the screen (M3)
```

### On Android (Termux)

```bash
pkg install python clang cmake make pkg-config
pip install --no-binary :all: unicorn    # build Unicorn against bionic libc
pip install pefile
python load.py
```

> The pip-prebuilt `libunicorn.so` is glibc-linked and won't load under Termux's bionic
> libc — building from source fixes the `Failed to load the Unicorn dynamic library` error.

## Legal

This repository contains only original reverse-engineering code and notes. HP, HP 39gII,
and the calculator firmware/emulator are property of HP Inc. No HP binaries, manuals, or
skin assets are included. This work is for interoperability and educational purposes.

## License

MIT — see [LICENSE](LICENSE). Applies to the code in this repository only, not to any
HP-owned material you supply separately.
