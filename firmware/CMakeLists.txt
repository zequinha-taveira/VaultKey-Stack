cmake_minimum_required(VERSION 3.13)

# Default to pico2 (Official RP2350 board definition)
set(PICO_BOARD "pico2" CACHE STRING "Target board")
set(PICO_PLATFORM "rp2350" CACHE STRING "Target platform")

include($ENV{PICO_SDK_PATH}/pico_sdk_init.cmake)

project(vaultkey_firmware C CXX ASM)

pico_sdk_init()

add_executable(vaultkey_firmware
    src/main.c
    src/usb_descriptors.c
    src/vk_protocol.c
    src/vault.c
    src/vk_crypto.c
    src/aes.c
    src/hardening.c
    src/vk_totp.c
    src/vk_keyboard.c
    lib/argon2/argon2.c
    src/vk_fido.c
    lib/cb0r/cb0r.c
    lib/nacl/tweetnacl.c
    lib/sha256/sha256.c
    lib/p256/p256-m.c
    lib/p256/p256_rng.c
)

# Include directories
target_include_directories(vaultkey_firmware PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/include
    ${CMAKE_CURRENT_LIST_DIR}/lib/argon2
    ${CMAKE_CURRENT_LIST_DIR}/lib/cb0r
    ${CMAKE_CURRENT_LIST_DIR}/lib/nacl
    ${CMAKE_CURRENT_LIST_DIR}/lib/sha256
    ${CMAKE_CURRENT_LIST_DIR}/lib/p256
)

# Pull in common dependencies
target_link_libraries(vaultkey_firmware
    pico_stdlib
    pico_flash
    pico_rand
    tinyusb_device
    tinyusb_board
)

# Enable USB CDC and HID
target_compile_definitions(vaultkey_firmware PRIVATE
    PICO_USB=1
)

# Production flags
target_compile_options(vaultkey_firmware PRIVATE
    -Os
    -fstack-protector-strong
    -Wall
    -Wextra
)

# Create map/bin/hex/uf2 files
pico_add_extra_outputs(vaultkey_firmware)

# Diagnostic Blinky Target
add_executable(vaultkey_blinky src/test_blinky.c)
target_link_libraries(vaultkey_blinky pico_stdlib hardware_gpio)
pico_add_extra_outputs(vaultkey_blinky)
