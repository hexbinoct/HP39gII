#!/usr/bin/env bash
# Build Unicorn (x86 guest) -> Android static libs WITHOUT Docker.
#
# For macOS / Linux, where QEMU's configure step works natively (it needs
# `strings`, `pkg-config`, a POSIX shell — all present there, but NOT on a
# bare Windows host, which is why Windows users get the Docker path instead).
#
# Requires: cmake (>=3.22), ninja, git, pkg-config, binutils, and the Android
# NDK. Point ANDROID_NDK_HOME at your NDK, or pass it as the first argument.
#
#   ./build-unicorn-native.sh [/path/to/android-ndk]
#
# Output: app/src/main/cpp/prebuilt/<abi>/libunicorn.a  + prebuilt/include/
set -euo pipefail

NDK="${1:-${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-}}}"
if [[ -z "$NDK" || ! -d "$NDK" ]]; then
  echo "ERROR: Android NDK not found. Set ANDROID_NDK_HOME or pass the path:" >&2
  echo "  ./build-unicorn-native.sh /path/to/android-ndk-r28c" >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PREBUILT="$SCRIPT_DIR/../app/src/main/cpp/prebuilt"
WORK="$(mktemp -d)"
ABIS=("arm64-v8a" "x86_64")

echo "Cloning Unicorn 2.1.4..."
git clone --depth 1 --branch 2.1.4 \
    https://github.com/unicorn-engine/unicorn.git "$WORK/unicorn"

for ABI in "${ABIS[@]}"; do
  echo "==== Building Unicorn for $ABI ===="
  BUILD="$WORK/build-$ABI"
  cmake -S "$WORK/unicorn" -B "$BUILD" -G Ninja \
    -DCMAKE_TOOLCHAIN_FILE="$NDK/build/cmake/android.toolchain.cmake" \
    -DANDROID_ABI="$ABI" \
    -DANDROID_PLATFORM=android-30 \
    -DCMAKE_BUILD_TYPE=Release \
    -DUNICORN_ARCH=x86 \
    -DBUILD_SHARED_LIBS=OFF \
    -DUNICORN_LEGACY_STATIC_ARCHIVE=ON
  # 'unicorn_archive' = the all-in-one bundle (API + common + softmmu).
  cmake --build "$BUILD" --target unicorn_archive -j"$(getconf _NPROCESSORS_ONLN)"
  mkdir -p "$PREBUILT/$ABI"
  cp -v "$BUILD/libunicorn.a" "$PREBUILT/$ABI/"
done

mkdir -p "$PREBUILT/include"
cp -rv "$WORK/unicorn/include/." "$PREBUILT/include/"
rm -rf "$WORK"
echo "==== Done. Libs in $PREBUILT ===="
