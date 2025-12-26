// p256_rng.c - RNG implementation for p256-m using VaultKey TRNG
#include "p256-m.h"
#include "vk_crypto.h"

int p256_generate_random(uint8_t *output, unsigned output_size) {
    vk_crypto_get_random(output, output_size);
    return 0;
}
