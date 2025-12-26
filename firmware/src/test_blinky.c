/**
 * Minimal Blinky Test for Tenstar RP2350
 * Toggles LED to prove board, architecture, and flash boot process are valid.
 * PIN_LED 22 (WS2812)
 *
 * If this fails, the issue is Architecture (ARM vs RISC-V) or Flash Boot
 * (boot2).
 */
#include "hardware/gpio.h"
#include "pico/stdlib.h"
#include <stdio.h>


#define PIN_LED 22 // Configurable: 22 (Standard) or 16 (Zero)

// Basic WS2812 Bit-bang
void blinky_ws2812(uint8_t r, uint8_t g, uint8_t b) {
  uint32_t val = ((uint32_t)g << 16) | ((uint32_t)r << 8) | (uint32_t)b;
  for (int i = 23; i >= 0; i--) {
    if (val & (1 << i)) {
      gpio_put(PIN_LED, 1);
      for (volatile int j = 0; j < 10; j++)
        ; // T1H
      gpio_put(PIN_LED, 0);
      for (volatile int j = 0; j < 3; j++)
        ; // T1L
    } else {
      gpio_put(PIN_LED, 1);
      for (volatile int j = 0; j < 3; j++)
        ; // T0H
      gpio_put(PIN_LED, 0);
      for (volatile int j = 0; j < 10; j++)
        ; // T0L
    }
  }
  // Latch
  sleep_us(50);
}

int main() {
  stdio_init_all();

  // Setup WS2812 Pin
  gpio_init(PIN_LED);
  gpio_set_dir(PIN_LED, GPIO_OUT);

  // Also toggle standard Pin 25 just in case
  gpio_init(25);
  gpio_set_dir(25, GPIO_OUT);

  while (true) {
    // Red
    blinky_ws2812(50, 0, 0);
    gpio_put(25, 1);
    sleep_ms(500);

    // Green
    blinky_ws2812(0, 50, 0);
    gpio_put(25, 0);
    sleep_ms(500);

    // Blue
    blinky_ws2812(0, 0, 50);
    sleep_ms(500);
  }
}
