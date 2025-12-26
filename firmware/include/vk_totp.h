#ifndef VK_TOTP_H
#define VK_TOTP_H

#include <stdint.h>

/**
 * @brief Generate a 6-digit TOTP code.
 * @param key Secret seed bytes.
 * @param key_len Length of the secret seed.
 * @param timestamp Current Unix timestamp (UTC).
 * @return 6-digit TOTP code as an integer.
 */
uint32_t vk_totp_generate(const uint8_t *key, uint16_t key_len,
                          uint64_t timestamp);

#endif // VK_TOTP_H
