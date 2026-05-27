# HP 39gII on Android

A native Android app (Kotlin + NDK/JNI) that runs HP's original x86 calculator
core on your phone via Unicorn Engine. On-screen keypad in, live 256×127
framebuffer out — HP's own code, no Windows.

> You must supply your own `HP39gII.exe` (HP's copyrighted binary is **not**
> included). See [Getting the binary](../README.md#getting-the-binary).

## What you need

- **Android Studio** (easiest) — or the Android SDK + NDK r28c on the command line.
- A phone with **USB debugging** enabled, *or* the Android Studio emulator.
- Your copy of **`HP39gII.exe`**.
- On **Windows**, **Docker** (only needed for the one-time Unicorn build below).

## Build & run — 3 steps

### 1. Build the Unicorn native library (one time)

The app statically links Unicorn 2.1.4. The prebuilt archives aren't committed,
so generate them once:

- **Windows:** use Docker — see [`docker/README.md`](docker/README.md).
- **macOS / Linux:** run `docker/build-unicorn-native.sh` (no Docker needed).

This produces `app/src/main/cpp/prebuilt/<abi>/libunicorn.a`. You only redo this
if you change Unicorn.

### 2. Drop in your `HP39gII.exe`

Copy your binary to exactly this path (create the `assets` folder if missing):

```
android/app/src/main/assets/HP39gII.exe
```

It gets bundled into the APK at build time. If it's missing, the app launches but
shows `HP39gII.exe missing from assets/`.

### 3. Build the app and install it on your phone

**Android Studio:** open the `android/` folder, plug in your phone (or start an
emulator), and press **Run ▶**.

**Command line** (phone connected, USB debugging on):

```bash
cd android
./gradlew installDebug        # Windows: gradlew.bat installDebug
```

The app installs as **HP39gII**. Launch it and tap away — `1 + 1 = ENTER`
shows `2`, computed by HP's own firmware.

## Notes & troubleshooting

- **ABIs:** real phones are `arm64-v8a`; the Android Studio emulator is `x86_64`.
  Build Unicorn for whichever you target (the Docker build produces both).
- **`HP39gII.exe missing from assets/`** — step 2 wasn't done, or the filename
  case is wrong (must be exactly `HP39gII.exe`).
- **Linker / `libunicorn.a` not found** — step 1 wasn't done for your target ABI;
  check `app/src/main/cpp/prebuilt/<abi>/`.
- **What works today:** interactive keypad + live display (Phase C), plotting
  defined functions (e.g. `F1(X)=SIN(X)`), and CAS commands like `ifactor(24)`
  → `2^3*3` — all computed by HP's own firmware.
