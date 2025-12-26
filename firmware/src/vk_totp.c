#include "vk_totp.h"
#include <string.h>

// SHA1 constants and functions (minimal implementation)
#define SHA1_BLOCK_SIZE 64
#define SHA1_DIGEST_SIZE 20

// Rotate left macro
#define ROL(value, bits) (((value) << (bits)) | ((value) >> (32 - (bits))))

static void sha1_transform(uint32_t state[5], const uint8_t buffer[64]) {
  uint32_t a, b, c, d, e, roll[80];
  int i;

  for (i = 0; i < 16; i++) {
    roll[i] = (buffer[i * 4] << 24) | (buffer[i * 4 + 1] << 16) |
              (buffer[i * 4 + 2] << 8) | (buffer[i * 4 + 3]);
  }
  for (i = 16; i < 80; i++) {
    roll[i] = ROL(roll[i - 3] ^ roll[i - 8] ^ roll[i - 14] ^ roll[i - 16], 1);
  }

  a = state[0];
  b = state[1];
  c = state[2];
  d = state[3];
  e = state[4];

  for (i = 0; i < 80; i++) {
    uint32_t f, k;
    if (i < 20) {
      f = (b & c) | ((~b) & d);
      k = 0x5A827999;
    } else if (i < 40) {
      f = b ^ c ^ d;
      k = 0x6ED9EBA1;
    } else if (i < 60) {
      f = (b & c) | (b & d) | (c & d);
      k = 0x8F1BBCDC;
    } else {
      f = b ^ c ^ d;
      k = 0xCA62C1D6;
    }
    uint32_t temp = ROL(a, 5) + f + e + k + roll[i];
    e = d;
    d = c;
    c = ROL(b, 30);
    b = a;
    a = temp;
  }

  state[0] += a;
  state[1] += b;
  state[2] += c;
  state[3] += d;
  state[4] += e;
}

static void sha1(const uint8_t *data, size_t len, uint8_t digest[20]) {
  uint32_t state[5] = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476,
                       0xC3D2E1F0};
  uint8_t buffer[64];
  size_t i;
  uint64_t total_bits = (uint64_t)len * 8;

  for (i = 0; i + 64 <= len; i += 64) {
    sha1_transform(state, data + i);
  }

  memset(buffer, 0, 64);
  memcpy(buffer, data + i, len - i);
  buffer[len - i] = 0x80;

  if (len - i >= 56) {
    sha1_transform(state, buffer);
    memset(buffer, 0, 64);
  }

  for (int j = 0; j < 8; j++) {
    buffer[63 - j] = (uint8_t)(total_bits >> (j * 8));
  }
  sha1_transform(state, buffer);

  for (int j = 0; j < 5; j++) {
    digest[j * 4] = (uint8_t)(state[j] >> 24);
    digest[j * 4 + 1] = (uint8_t)(state[j] >> 16);
    digest[j * 4 + 2] = (uint8_t)(state[j] >> 8);
    digest[j * 4 + 3] = (uint8_t)state[j];
  }
}

static void hmac_sha1(const uint8_t *key, uint16_t key_len, const uint8_t *msg,
                      uint16_t msg_len, uint8_t mac[20]) {
  uint8_t k_ipad[64], k_opad[64];
  uint8_t tk[20];
  int i;

  if (key_len > 64) {
    sha1(key, key_len, tk);
    key = tk;
    key_len = 20;
  }

  memset(k_ipad, 0x36, 64);
  memset(k_opad, 0x5C, 64);
  for (i = 0; i < key_len; i++) {
    k_ipad[i] ^= key[i];
    k_opad[i] ^= key[i];
  }

  uint8_t inner_msg[64 + msg_len];
  memcpy(inner_msg, k_ipad, 64);
  memcpy(inner_msg + 64, msg, msg_len);
  uint8_t inner_hash[20];
  sha1(inner_msg, 64 + msg_len, inner_hash);

  uint8_t outer_msg[64 + 20];
  memcpy(outer_msg, k_opad, 64);
  memcpy(outer_msg + 64, inner_hash, 20);
  sha1(outer_msg, 64 + 20, mac);
}

uint32_t vk_totp_generate(const uint8_t *key, uint16_t key_len,
                          uint64_t timestamp) {
  uint64_t interval = timestamp / 30;
  uint8_t msg[8];
  for (int i = 0; i < 8; i++) {
    msg[7 - i] = (uint8_t)(interval >> (i * 8));
  }

  uint8_t hash[20];
  hmac_sha1(key, key_len, msg, 8, hash);

  int offset = hash[19] & 0x0F;
  uint32_t bin_code =
      ((hash[offset] & 0x7F) << 24) | ((hash[offset + 1] & 0xFF) << 16) |
      ((hash[offset + 2] & 0xFF) << 8) | (hash[offset + 3] & 0xFF);

  return bin_code % 1000000;
}
