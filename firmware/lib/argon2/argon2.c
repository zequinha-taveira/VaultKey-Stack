#include "argon2.h"
#include <stdlib.h>
#include <string.h>

/* BLAKE2b Internal */
static const uint64_t blake2b_iv[8] = {
    0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL, 0x3c6ef372fe94f82bULL,
    0xa54ff53a5f1d36f1ULL, 0x510e527fad682d1aULL, 0x9b05688c2b3e6c1fULL,
    0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL};

static inline uint64_t rotr64(uint64_t x, int n) {
  return (x >> n) | (x << (64 - n));
}

static void blake2b_g(uint64_t *v, int a, int b, int c, int d, uint64_t x,
                      uint64_t y) {
  v[a] = v[a] + v[b] + x;
  v[d] = rotr64(v[d] ^ v[a], 32);
  v[c] = v[c] + v[d];
  v[b] = rotr64(v[b] ^ v[c], 24);
  v[a] = v[a] + v[b] + y;
  v[d] = rotr64(v[d] ^ v[a], 16);
  v[c] = v[c] + v[d];
  v[b] = rotr64(v[b] ^ v[c], 63);
}

static void blake2b_round(uint64_t *v, const uint64_t *m, const uint8_t *s) {
  blake2b_g(v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
  blake2b_g(v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
  blake2b_g(v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
  blake2b_g(v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
  blake2b_g(v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
  blake2b_g(v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
  blake2b_g(v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
  blake2b_g(v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
}

static void blake2b_compress(uint64_t *h, const uint8_t *block, uint64_t t0,
                             uint64_t t1, int last) {
  static const uint8_t sigma[12][16] = {
      {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
      {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
      {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
      {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
      {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
      {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
      {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
      {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
      {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
      {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
      {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
      {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3}};
  uint64_t v[16], m[16];
  memcpy(v, h, 64);
  memcpy(v + 8, blake2b_iv, 64);
  v[12] ^= t0;
  v[13] ^= t1;
  if (last)
    v[14] = ~v[14];
  for (int i = 0; i < 16; i++) {
    uint64_t w;
    memcpy(&w, block + i * 8, 8);
    m[i] = w;
  }
  for (int i = 0; i < 12; i++)
    blake2b_round(v, m, sigma[i]);
  for (int i = 0; i < 8; i++)
    h[i] ^= v[i] ^ v[i + 8];
}

static void blake2b(uint8_t *out, size_t outlen, const void *in, size_t inlen) {
  uint64_t h[8];
  memcpy(h, blake2b_iv, 64);
  h[0] ^= 0x01010000 ^ outlen;
  const uint8_t *p = (const uint8_t *)in;
  while (inlen > 128) {
    blake2b_compress(h, p, 128, 0, 0); // Simplified t counter
    inlen -= 128;
    p += 128;
  }
  uint8_t last[128] = {0};
  memcpy(last, p, inlen);
  blake2b_compress(h, last, (uint64_t)inlen, 0, 1);
  memcpy(out, h, outlen);
}

/* Argon2 Block Mixing */
static inline uint64_t fBlaMka(uint64_t x, uint64_t y) {
  const uint64_t m = 0xFFFFFFFFULL;
  const uint64_t xy = (x & m) * (y & m);
  return x + y + 2 * xy;
}

static void G(uint64_t *a, uint64_t *b, uint64_t *c, uint64_t *d) {
  *a = fBlaMka(*a, *b);
  *d = rotr64(*d ^ *a, 32);
  *c = fBlaMka(*c, *d);
  *b = rotr64(*b ^ *c, 24);
  *a = fBlaMka(*a, *b);
  *d = rotr64(*d ^ *a, 16);
  *c = fBlaMka(*c, *d);
  *b = rotr64(*b ^ *c, 63);
}

static void fill_block(const argon2_block *prev, const argon2_block *ref,
                       argon2_block *next, int with_xor) {
  argon2_block blockR;
  for (int i = 0; i < 128; i++)
    blockR.v[i] = prev->v[i] ^ ref->v[i];
  argon2_block block_tmp;
  memcpy(&block_tmp, &blockR, sizeof(argon2_block));

  for (int i = 0; i < 8; i++) {
    uint64_t *v = &blockR.v[16 * i];
    G(&v[0], &v[4], &v[8], &v[12]);
    G(&v[1], &v[5], &v[9], &v[13]);
    G(&v[2], &v[6], &v[10], &v[14]);
    G(&v[3], &v[7], &v[11], &v[15]);
    G(&v[0], &v[5], &v[10], &v[15]);
    G(&v[1], &v[6], &v[11], &v[12]);
    G(&v[2], &v[7], &v[8], &v[13]);
    G(&v[3], &v[4], &v[9], &v[14]);
  }
  for (int i = 0; i < 8; i++) {
    uint64_t *v = blockR.v;
    G(&v[2 * i], &v[2 * i + 1], &v[2 * i + 16], &v[2 * i + 17]);
    G(&v[2 * i + 32], &v[2 * i + 33], &v[2 * i + 48], &v[2 * i + 49]);
    G(&v[2 * i + 64], &v[2 * i + 65], &v[2 * i + 80], &v[2 * i + 81]);
    G(&v[2 * i + 96], &v[2 * i + 97], &v[2 * i + 112], &v[2 * i + 113]);
  }

  for (int i = 0; i < 128; i++) {
    next->v[i] = blockR.v[i] ^ block_tmp.v[i];
    if (with_xor)
      next->v[i] ^= prev->v[i]; // Simplified with_xor for 2nd pass
  }
}

int argon2id_hash_raw(const uint32_t t_cost, const uint32_t m_cost,
                      const uint32_t parallelism, const void *pwd,
                      const size_t pwdlen, const void *salt,
                      const size_t saltlen, void *out, const size_t outlen) {
  if (parallelism != 1)
    return -1;
  if (m_cost < 8)
    return -1;

  argon2_block *memory = malloc(m_cost * sizeof(argon2_block));
  if (!memory)
    return -1;

  // H0 = Blake2b(p, outlen, m_cost, t_cost, v, type, pwdlen, pwd, saltlen,
  // salt, ...)
  uint8_t h0[64];
  uint32_t params[10];
  params[0] = parallelism;
  params[1] = (uint32_t)outlen;
  params[2] = m_cost;
  params[3] = t_cost;
  params[4] = 0x13; // Version
  params[5] = Argon2_id;
  params[6] = (uint32_t)pwdlen;
  // Note: This is an approximation of the complex multi-field H0.
  // In a full implementation, each field is hashed sequentially.
  blake2b(h0, 64, params, sizeof(params));
  blake2b(h0, 64, pwd, pwdlen);
  blake2b(h0, 64, salt, saltlen);

  // Initialize first two blocks
  for (uint32_t i = 0; i < 2; i++) {
    uint8_t block_init[72];
    memcpy(block_init, h0, 64);
    memset(block_init + 64, 0, 4);
    memcpy(block_init + 68, &i, 4);
    // Simplified Blake2b-long for 1KB block
    blake2b((uint8_t *)&memory[i], 1024, block_init, 72);
  }

  // Fill blocks
  for (uint32_t i = 2; i < m_cost; i++) {
    // Argon2id: first half of first pass is Argon2i (independent addressing)
    // second half and subsequent passes are Argon2d (dependent addressing)
    uint32_t ref_idx;
    if (i < m_cost / 2) {
      // Placeholder for Argon2i addressing (pseudo-random from internal state)
      ref_idx = (i - 1) % i;
    } else {
      // Argon2d: data-dependent addressing
      uint64_t val = memory[i - 1].v[0];
      ref_idx = (uint32_t)(val % (i - 1));
    }
    fill_block(&memory[i - 1], &memory[ref_idx], &memory[i], 0);
  }

  // Final Hash
  blake2b(out, outlen, &memory[m_cost - 1], 1024);

  free(memory);
  return 0;
}
