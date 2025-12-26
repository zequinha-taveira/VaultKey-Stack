#ifndef VK_ARGON2_H
#define VK_ARGON2_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>


/**
 * Perform Argon2id key derivation.
 *
 * @param pwd      Password string
 * @param pwdlen   Length of password
 * @param salt     Salt buffer
 * @param saltlen  Length of salt (usually 16 bytes)
 * @param t_cost   Number of iterations (e.g. 1-3)
 * @param m_cost   Memory cost in KiB (e.g. 16)
 * @param out_key  Buffer to store the resulting 32-byte key
 * @return true on success
 */
bool vk_argon2id(const char *pwd, uint32_t pwdlen, const uint8_t *salt,
                 uint32_t saltlen, uint32_t t_cost, uint32_t m_cost,
                 uint8_t *out_key);

#endif // VK_ARGON2_H
