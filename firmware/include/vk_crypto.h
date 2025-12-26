#ifndef VK_CRYPTO_H
#define VK_CRYPTO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>


// AES-256-GCM Settings
#define AES_KEY_SIZE 32
#define GCM_IV_SIZE 12
#define GCM_TAG_SIZE 16

// Argon2id Settings (Hardware-friendly defaults)
#define ARGON2_SALT_SIZE 16
#define ARGON2_MEM_COST 2048
#define ARGON2_TIME_COST 3
#define ARGON2_LANES 1

// KDF: Derive a master key from user PIN and salt
bool vk_crypto_kdf(const char *pin, const uint8_t *salt, uint8_t *out_key);

// AES-GCM Encryption
bool vk_crypto_encrypt(const uint8_t *key, const uint8_t *plaintext,
                       uint16_t len, uint8_t *iv, uint8_t *tag,
                       uint8_t *ciphertext);

// AES-GCM Decryption
bool vk_crypto_decrypt(const uint8_t *key, const uint8_t *ciphertext,
                       uint16_t len, const uint8_t *iv, const uint8_t *tag,
                       uint8_t *plaintext);

// Memory Sanitization
void vk_crypto_zeroize(void *v, size_t n);

// Randomness
void vk_crypto_get_random(uint8_t *buffer, size_t len);
bool vk_crypto_trng_check(void);

#endif // VK_CRYPTO_H
