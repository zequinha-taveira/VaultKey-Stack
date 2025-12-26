#ifndef ARGON2_H
#define ARGON2_H

#include <stddef.h>
#include <stdint.h>


#define ARGON2_BLOCK_SIZE 1024
#define ARGON2_QWORDS_IN_BLOCK (ARGON2_BLOCK_SIZE / 8)

typedef struct {
  uint64_t v[ARGON2_QWORDS_IN_BLOCK];
} argon2_block;

typedef enum { Argon2_d = 0, Argon2_i = 1, Argon2_id = 2 } argon2_type;

int argon2id_hash_raw(const uint32_t t_cost, const uint32_t m_cost,
                      const uint32_t parallelism, const void *pwd,
                      const size_t pwdlen, const void *salt,
                      const size_t saltlen, void *out, const size_t outlen);

#endif
