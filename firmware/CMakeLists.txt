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
)

# Include directories
target_include_directories(vaultkey_firmware PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/include
)

# Pull in common dependencies
target_link_libraries(vaultkey_firmware
    pico_stdlib
    pico_flash
    tinyusb_device
    tinyusb_board
)

# Enable USB CDC and HID
target_compile_definitions(vaultkey_firmware PRIVATE
    PICO_USB=1
)

# Create map/bin/hex/uf2 files
pico_add_extra_outputs(vaultkey_firmware)
