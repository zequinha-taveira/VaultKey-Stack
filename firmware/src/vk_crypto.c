#include "vk_crypto.h"
#include <string.h>

// For Phase 2, these are placeholders that will later call mbedTLS or wolfSSL
// Implementation will be fleshed out in Phase 5 during Hardening

bool vk_crypto_kdf(const char *pin, const uint8_t *salt, uint8_t *out_key) {
  // Placeholder for Argon2id
  // In development, we use a simple SHA256 or similar to not block progress
  memset(out_key, 0x42, AES_KEY_SIZE);
  return true;
}

bool vk_crypto_encrypt(const uint8_t *key, const uint8_t *plaintext,
                       uint16_t len, uint8_t *iv, uint8_t *tag,
                       uint8_t *ciphertext) {
  // Placeholder: Zero-crypto (identity) for early testing
  // WARNING: DO NOT USE IN PRODUCTION
  memcpy(ciphertext, plaintext, len);
  memset(iv, 0xAA, GCM_IV_SIZE);
  memset(tag, 0xBB, GCM_TAG_SIZE);
  return true;
}

bool vk_crypto_decrypt(const uint8_t *key, const uint8_t *ciphertext,
                       uint16_t len, const uint8_t *iv, const uint8_t *tag,
                       uint8_t *plaintext) {
  // Placeholder: Zero-crypto (identity)
  memcpy(plaintext, ciphertext, len);
  return true;
}
