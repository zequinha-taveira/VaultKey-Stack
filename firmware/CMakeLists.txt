cmake_minimum_required(VERSION 3.13)

# Initialize Pico SDK
include(pico_sdk_import.cmake)

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
)

# Include directories
target_include_directories(vaultkey_firmware PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/include
    ${CMAKE_CURRENT_LIST_DIR}/lib/argon2
    ${CMAKE_CURRENT_LIST_DIR}/lib/cb0r
    ${CMAKE_CURRENT_LIST_DIR}/lib/nacl
    ${CMAKE_CURRENT_LIST_DIR}/lib/sha256
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

# Create map/bin/hex/uf2 files
pico_add_extra_outputs(vaultkey_firmware)
