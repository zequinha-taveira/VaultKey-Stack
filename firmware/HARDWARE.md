# Hardware Configuration
# VaultKey Firmware for Tenstar RP2350-USB

# Pinout (Tenstar RP2350-USB)
# - GP22: WS2812 RGB LED (Data In)
# - GP21: User Button (External, use pull-up)
# - GP0-GP20, GP23-GP29: Available for expansion

# Flash Configuration
# - Total Flash: 16MB (W25Q128BVPIQ)
# - Vault Storage: Last 64KB (Offset: 0xFFF0000)

# Build for Tenstar RP2350-USB:
# 1. Set PICO_BOARD=tenstar_rp2350_usb (or generic rp2350)
# 2. cmake -DPICO_BOARD=rp2350 ..
# 3. make

# Default Button Wiring:
# Connect a tactile button between GP21 and GND.
# The internal pull-up resistor is enabled in firmware.
