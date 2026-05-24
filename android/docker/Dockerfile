# Builds Unicorn 2.1.4 (x86 guest) as Android static libs for arm64-v8a + x86_64.
# QEMU's configure needs a Unix host, so we do it in Linux and export the .a files.
FROM ubuntu:24.04

RUN apt-get update && apt-get install -y --no-install-recommends \
        cmake ninja-build python3 git build-essential pkg-config binutils \
        ca-certificates wget unzip \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt

# Android NDK r28c (matches the host SDK NDK 28.2.13676358).
RUN wget -q https://dl.google.com/android/repository/android-ndk-r28c-linux.zip \
    && unzip -q android-ndk-r28c-linux.zip \
    && rm android-ndk-r28c-linux.zip

RUN git clone --depth 1 --branch 2.1.4 \
        https://github.com/unicorn-engine/unicorn.git /opt/unicorn

COPY build-unicorn.sh /opt/build-unicorn.sh
RUN sed -i 's/\r$//' /opt/build-unicorn.sh \
    && chmod +x /opt/build-unicorn.sh \
    && /opt/build-unicorn.sh

# `docker run --rm -v <host_prebuilt_dir>:/host <image> cp -a /out/. /host/`
CMD ["bash", "-c", "cp -a /out/. /host/ && echo copied to /host"]
