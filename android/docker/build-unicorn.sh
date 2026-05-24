#!/usr/bin/env bash
# Cross-compiles Unicorn (x86 guest only) to Android static libs inside Linux,
# where QEMU's configure step works. Outputs to /out/<abi>/ + /out/include.
set -euo pipefail

NDK=/opt/android-ndk-r28c
SRC=/opt/unicorn
ABIS=("arm64-v8a" "x86_64")

for ABI in "${ABIS[@]}"; do
  echo "==== Building Unicorn for $ABI ===="
  BUILD="/tmp/build-$ABI"
  cmake -S "$SRC" -B "$BUILD" -G Ninja \
    -DCMAKE_TOOLCHAIN_FILE="$NDK/build/cmake/android.toolchain.cmake" \
    -DANDROID_ABI="$ABI" \
    -DANDROID_PLATFORM=android-30 \
    -DCMAKE_BUILD_TYPE=Release \
    -DUNICORN_ARCH=x86 \
    -DBUILD_SHARED_LIBS=OFF \
    -DUNICORN_LEGACY_STATIC_ARCHIVE=ON
  # The 'unicorn_archive' target is the v1-style all-in-one bundle (public API +
  # common + softmmu merged into a single libunicorn.a). The plain 'unicorn'
  # target only produces libunicorn-static.a (API objects, no engine).
  cmake --build "$BUILD" --target unicorn_archive -j"$(nproc)"

  mkdir -p "/out/$ABI"
  # Copy ONLY the all-in-one — linking the component archives too would
  # duplicate symbols.
  cp -v "$BUILD/libunicorn.a" "/out/$ABI/"
done

# Headers are ABI-independent.
mkdir -p /out/include
cp -rv "$SRC/include/." /out/include/
echo "==== Done. Artifacts in /out ===="
ls -R /out
