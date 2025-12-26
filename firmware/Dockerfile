# Reproducible build environment for VaultKey Firmware
FROM debian:bookworm-slim

# Prevent interactive prompts
ENV DEBIAN_FRONTEND=noninteractive

# Install build dependencies
RUN apt-get update && apt-get install -y \
    cmake \
    gcc-arm-none-eabi \
    libnewlib-arm-none-eabi \
    libstdc++-arm-none-eabi-newlib \
    ninja-build \
    python3 \
    git \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Set up Pico SDK
ENV PICO_SDK_PATH=/opt/pico-sdk
RUN git clone --depth 1 --branch 2.1.0 https://github.com/raspberrypi/pico-sdk.git ${PICO_SDK_PATH} \
    && cd ${PICO_SDK_PATH} \
    && git submodule update --init

# Create build directory
WORKDIR /build

# Default command to build
CMD ["bash", "-c", "cmake -G Ninja -DPICO_BOARD=pico2 .. && ninja"]
