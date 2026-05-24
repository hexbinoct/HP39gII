# Building Unicorn for the HP39gII Android app

The app statically links **Unicorn Engine 2.1.4** (x86 guest only) into its
native library. The prebuilt archives are **not** committed — you generate them
once into `app/src/main/cpp/prebuilt/<abi>/libunicorn.a` (+ `prebuilt/include/`).

Two architectures are produced: `arm64-v8a` (real devices) and `x86_64`
(the Android Studio emulator).

## Why a build step is needed

Unicorn embeds QEMU, whose `configure` script needs POSIX tools (`strings`,
`pkg-config`, a real shell). Those are present on macOS/Linux but not on a bare
Windows host, where the build fails to generate `config-host.h`. So:

| Host OS | Recommended path |
|---------|------------------|
| Windows | **Docker** (builds inside Linux) |
| macOS / Linux | **Native script** (no Docker needed) |

Either path produces identical archives.

## Option A — Docker (any host, required on Windows)

Requires Docker. From the repo root:

```bash
docker build -t hp39-unicorn android/docker
docker run --rm -v "$(pwd)/android/app/src/main/cpp/prebuilt":/host hp39-unicorn
```

On Windows PowerShell, replace `$(pwd)` with the absolute path, e.g.
`-v "F:/.../android/app/src/main/cpp/prebuilt":/host`.

The image downloads the Android NDK r28c and cross-compiles Unicorn; the
`docker run` copies the resulting `.a` files + headers onto your host.

## Option B — Native (macOS / Linux, no Docker)

Requires `cmake` (≥3.22), `ninja`, `git`, `pkg-config`, `binutils`, and an
Android NDK.

```bash
export ANDROID_NDK_HOME=/path/to/android-ndk-r28c   # or pass as $1
android/docker/build-unicorn-native.sh
```

## After building

`app/src/main/cpp/prebuilt/` will contain:

```
include/                 # Unicorn headers (unicorn/unicorn.h, ...)
arm64-v8a/libunicorn.a   # all-in-one static archive
x86_64/libunicorn.a
```

Then just build the app in Android Studio (or `./gradlew assembleDebug`).
`CMakeLists.txt` picks up the archives automatically.
