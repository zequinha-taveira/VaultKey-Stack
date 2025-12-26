#include "pico/stdlib.h"
#include <string.h>

/**
 * @brief Securely clear memory to prevent secret leakage.
 * Uses volatile to ensure the compiler doesn't optimize it away.
 */
void vk_secure_zero(void* ptr, size_t len) {
    if (ptr == NULL || len == 0) return;
    volatile uint8_t* p = (volatile uint8_t*)ptr;
    while (len--) {
        *p++ = 0;
    }
}

/**
 * @brief Stubs for protocol fuzzing.
 * In a real CI environment, these would be hooked into AFL++ or libFuzzer.
 */
void vk_fuzz_entry(const uint8_t* data, size_t len) {
    // This function will be the entry point for fuzzing the CBOR parser
    // vk_protocol_parse(data, (uint16_t)len, &dummy_packet);
}
