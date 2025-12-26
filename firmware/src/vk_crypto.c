#include "vk_crypto.h"
#include "aes.h"
#include "pico/rand.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

// --- GCM GHASH Implementation (Galois Field GF(2^121)) ---
static void gcm_gf_mult(const uint8_t *x, const uint8_t *y, uint8_t *res) {
  uint32_t v[4], z[4];
  int i, j;

  // Load into Big Endian uint32
  for (i = 0; i < 4; i++) {
    v[i] = (y[i * 4] << 24) | (y[i * 4 + 1] << 16) | (y[i * 4 + 2] << 8) |
           y[i * 4 + 3];
    z[i] = 0;
  }

  for (i = 0; i < 128; i++) {
    if (x[i >> 3] & (1 << (7 - (i & 7)))) {
      z[0] ^= v[0];
      z[1] ^= v[1];
      z[2] ^= v[2];
      z[3] ^= v[3];
    }
    uint32_t mask = (v[3] & 1) ? 0xe1000000 : 0;
    v[3] = (v[3] >> 1) | (v[2] << 31);
    v[2] = (v[2] >> 1) | (v[1] << 31);
    v[1] = (v[1] >> 1) | (v[0] << 31);
    v[0] = (v[0] >> 1) ^ mask;
  }

  for (i = 0; i < 4; i++) {
    res[i * 4] = (z[i] >> 24) & 0xff;
    res[i * 4 + 1] = (z[i] >> 16) & 0xff;
    res[i * 4 + 2] = (z[i] >> 8) & 0xff;
    res[i * 4 + 3] = z[i] & 0xff;
  }
}

static void gcm_ghash(const uint8_t *h, const uint8_t *data, uint16_t len,
                      uint8_t *x) {
  uint16_t i, j;
  for (i = 0; i < len; i += 16) {
    for (j = 0; j < 16 && (i + j) < len; j++)
      x[j] ^= data[i + j];
    uint8_t tmp[16];
    gcm_gf_mult(x, h, tmp);
    memcpy(x, tmp, 16);
  }
}

bool vk_crypto_kdf(const char *pin, const uint8_t *salt, uint8_t *out_key) {
  // Simple SHA-256 placeholder for KDF if Argon2 is too heavy for small flash
  // For now, we use a simple deterministic mix to avoid external deps.
  // In a real device, we'd use Argon2id from a library.
  memset(out_key, 0, 32);
  strncpy((char *)out_key, pin, 32);
  for (int i = 0; i < 16; i++)
    out_key[i] ^= salt[i];
  return true;
}

bool vk_crypto_encrypt(const uint8_t *key, const uint8_t *plaintext,
                       uint16_t len, uint8_t *iv, uint8_t *tag,
                       uint8_t *ciphertext) {
  struct AES_ctx ctx;
  uint8_t h[16] = {0};
  uint8_t j0[16] = {0};

  AES_init_ctx(&ctx, key);
  AES_ECB_encrypt(&ctx, h); // H = E(K, 0^128)

  memcpy(j0, iv, 12);
  j0[15] = 1;

  // Ciphertext = CTR(Plaintext)
  uint8_t ctr_iv[16];
  memcpy(ctr_iv, j0, 16);
  // Increment CTR for the first data block
  for (int i = 15; i >= 12; i--) {
    if (++ctr_iv[i])
      break;
  }

  memcpy(ciphertext, plaintext, len);
  AES_init_ctx_iv(&ctx, key, ctr_iv);
  AES_CTR_xcrypt_buffer(&ctx, ciphertext, len);

  // Auth Tag
  uint8_t x[16] = {0};
  gcm_ghash(h, ciphertext, len, x);

  // Lengths block (only supporting ciphertext for now)
  uint8_t len_block[16] = {0};
  uint64_t bit_len = (uint64_t)len * 8;
  for (int i = 0; i < 8; i++)
    len_block[15 - i] = (bit_len >> (i * 8)) & 0xff;
  gcm_ghash(h, len_block, 16, x);

  // S = E(K, J0)
  uint8_t s[16];
  memcpy(s, j0, 16);
  AES_init_ctx(&ctx, key);
  AES_ECB_encrypt(&ctx, s);

  for (int i = 0; i < 16; i++)
    tag[i] = x[i] ^ s[i];
  return true;
}

bool vk_crypto_decrypt(const uint8_t *key, const uint8_t *ciphertext,
                       uint16_t len, const uint8_t *iv, const uint8_t *tag,
                       uint8_t *plaintext) {
  struct AES_ctx ctx;
  uint8_t h[16] = {0};
  uint8_t j0[16] = {0};

  AES_init_ctx(&ctx, key);
  AES_ECB_encrypt(&ctx, h);

  memcpy(j0, iv, 12);
  j0[15] = 1;

  // Auth Tag Verification
  uint8_t x[16] = {0};
  gcm_ghash(h, ciphertext, len, x);

  uint8_t len_block[16] = {0};
  uint64_t bit_len = (uint64_t)len * 8;
  for (int i = 0; i < 8; i++)
    len_block[15 - i] = (bit_len >> (i * 8)) & 0xff;
  gcm_ghash(h, len_block, 16, x);

  uint8_t s[16];
  memcpy(s, j0, 16);
  AES_init_ctx(&ctx, key);
  AES_ECB_encrypt(&ctx, s);

  for (int i = 0; i < 16; i++) {
    if ((x[i] ^ s[i]) != tag[i])
      return false;
  }

  // Decrypt
  uint8_t ctr_iv[16];
  memcpy(ctr_iv, j0, 16);
  for (int i = 15; i >= 12; i--) {
    if (++ctr_iv[i])
      break;
  }

  memcpy(plaintext, ciphertext, len);
  AES_init_ctx_iv(&ctx, key, ctr_iv);
  AES_CTR_xcrypt_buffer(&ctx, plaintext, len);

  return true;
}
void vk_crypto_zeroize(void *v, size_t n) {
  volatile uint8_t *p = (uint8_t *)v;
  while (n--)
    *p++ = 0;
}

void vk_crypto_get_random(uint8_t *buffer, size_t len) {
  for (size_t i = 0; i < len; i += 4) {
    uint32_t val = get_rand_32();
    size_t chunk = (len - i) < 4 ? (len - i) : 4;
    memcpy(buffer + i, &val, chunk);
  }
}
