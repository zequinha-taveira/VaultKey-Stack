#include "vk_fido.h"
#include "cb0r.h"
#include "sha256.h"
#include "tusb.h"
#include "tweetnacl.h"
#include "vault.h"
#include "vk_crypto.h"
#include <stdbool.h>
#include <stdint.h>
#include <string.h>


// --- Context and Constants ---

typedef struct {
  uint32_t cid;
  uint8_t cmd;
  uint16_t total_len;
  uint16_t current_len;
  uint8_t next_seq;
  uint8_t buffer[1024];
  bool active;
} u2fhid_context_t;

static u2fhid_context_t fido_ctx = {0};
static uint32_t next_cid = 0x11223344;

#define VK_AAGUID                                                              \
  {0x56, 0x4B, 0x53, 0x54, 0x41, 0x43, 0x4B, 0x01,                             \
   0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09}

static bool vk_fido_wait_for_user_presence(void) {
  // Hardware implementation: check button press.
  // For now, we simulate user is always present.
  return true;
}

#define CTAP_STATUS_OK 0x00
#define CTAP_ERR_INVALID_CBOR 0x22
#define CTAP_ERR_NO_CREDENTIALS 0x2b
#define CTAP_ERR_KEY_STORE_FULL 0x27

#define FIDO_ITF_INDEX 2

// --- CBOR Encoding Helpers ---

static size_t encode_cose_key(uint8_t *out, const uint8_t *pk) {
  size_t off = 0;
  out[off++] = 0xA4; // Map(4)
  out[off++] = 0x01;
  out[off++] = 0x01; // kty: OKP
  out[off++] = 0x03;
  out[off++] = 0x27; // alg: EdDSA (-8)
  out[off++] = 0x20;
  out[off++] = 0x06; // crv: Ed25519 (6)
  out[off++] = 0x21;
  out[off++] = 0x58;
  out[off++] = 0x20;
  memcpy(out + off, pk, 32);
  off += 32; // x-coordinate
  return off;
}

static size_t encode_auth_data(uint8_t *out, const uint8_t *rp_id_hash,
                               uint8_t flags, uint32_t counter,
                               const uint8_t *aaguid, const uint8_t *cred_id,
                               size_t cred_id_len, const uint8_t *pk) {
  size_t off = 0;
  memcpy(out + off, rp_id_hash, 32);
  off += 32;
  out[off++] = flags;
  out[off++] = (uint8_t)(counter >> 24);
  out[off++] = (uint8_t)(counter >> 16);
  out[off++] = (uint8_t)(counter >> 8);
  out[off++] = (uint8_t)counter;
  if (flags & 0x40) { // Attested Data (AT)
    memcpy(out + off, aaguid, 16);
    off += 16;
    out[off++] = (uint8_t)(cred_id_len >> 8);
    out[off++] = (uint8_t)(cred_id_len & 0xFF);
    memcpy(out + off, cred_id, cred_id_len);
    off += cred_id_len;
    off += encode_cose_key(out + off, pk);
  }
  return off;
}

// --- CTAP2 Logic ---

static void handle_get_info(uint32_t cid) {
  uint8_t aaguid[] = VK_AAGUID;
  uint8_t res[256];
  size_t off = 0;
  res[off++] = 0x00; // Status OK
  res[off++] = 0xA5; // Map(5)

  // 01: versions ["FIDO_2_0", "FIDO_2_1"]
  res[off++] = 0x01;
  res[off++] = 0x82;
  res[off++] = 0x68;
  memcpy(&res[off], "FIDO_2_0", 8);
  off += 8;
  res[off++] = 0x68;
  memcpy(&res[off], "FIDO_2_1", 8);
  off += 8;

  // 03: aaguid
  res[off++] = 0x03;
  res[off++] = 0x50;
  memcpy(&res[off], aaguid, 16);
  off += 16;

  // 04: options {rk: true, up: true, uv: false}
  res[off++] = 0x04;
  res[off++] = 0xA3;
  res[off++] = 0x62;
  res[off++] = 'r';
  res[off++] = 'k';
  res[off++] = 0xF5;
  res[off++] = 0x62;
  res[off++] = 'u';
  res[off++] = 'p';
  res[off++] = 0xF5;
  res[off++] = 0x62;
  res[off++] = 'u';
  res[off++] = 'v';
  res[off++] = 0xF4;

  // 06: maxMsgSize 1024
  res[off++] = 0x06;
  res[off++] = 0x19;
  res[off++] = 0x04;
  res[off++] = 0x00;

  // 09: pinProtocols [1]
  res[off++] = 0x09;
  res[off++] = 0x81;
  res[off++] = 0x01;

  vk_fido_send_response(cid, U2FHID_MSG, res, off);
}

static void vk_fido_dispatch_ctap2(uint32_t cid, uint8_t *payload,
                                   uint16_t len) {
  uint8_t ctap_cmd = payload[0];
  uint8_t *data = payload + 1;
  uint16_t data_len = len - 1;

  if (ctap_cmd == CTAP2_CMD_GET_INFO) {
    handle_get_info(cid);
  } else if (ctap_cmd == CTAP2_CMD_MAKE_CREDENTIAL) {
    cb0r_s map, rp_val, rp_id_val;
    if (cb0r_read(data, data_len, &map) &&
        cb0r_find(&map, CB0R_MAP, CTAP2_PARAM_RP, NULL, &rp_val) &&
        cb0r_find(&rp_val, CB0R_UTF8, 0, (uint8_t *)"id", &rp_id_val)) {
      vk_fido_cred_t new_cred = {0};
      size_t id_len = cb0r_vlen(&rp_id_val);
      memcpy(new_cred.rp_id, cb0r_value(&rp_id_val), id_len > 63 ? 63 : id_len);
      crypto_sign_ed25519_tweet_keypair(new_cred.public_key,
                                        new_cred.private_key);
      vk_crypto_get_random(new_cred.credential_id, 32);

      if (vk_fido_wait_for_user_presence() && vault_fido_add(&new_cred)) {
        uint8_t res_buf[512], rp_id_hash[32], auth_data[256];
        SHA256_CTX ctx;
        sha256_init(&ctx);
        sha256_update(&ctx, (uint8_t *)new_cred.rp_id, strlen(new_cred.rp_id));
        sha256_final(&ctx, rp_id_hash);
        uint8_t aaguid[] = VK_AAGUID;
        size_t ad_len =
            encode_auth_data(auth_data, rp_id_hash, 0x41, 0, aaguid,
                             new_cred.credential_id, 32, new_cred.public_key);

        res_buf[0] = 0x00;
        res_buf[1] = 0xA3;
        res_buf[2] = 0x01;
        res_buf[3] = 0x64;
        memcpy(&res_buf[4], "none", 4);
        res_buf[8] = 0x02;
        res_buf[9] = 0x58;
        res_buf[10] = (uint8_t)ad_len;
        memcpy(&res_buf[11], auth_data, ad_len);
        size_t off = 11 + ad_len;
        res_buf[off++] = 0x03;
        res_buf[off++] = 0xA0;
        vk_fido_send_response(cid, U2FHID_MSG, res_buf, off);
      } else
        vk_fido_send_response(cid, U2FHID_MSG,
                              (uint8_t[]){CTAP_ERR_KEY_STORE_FULL}, 1);
    } else
      vk_fido_send_response(cid, U2FHID_MSG, (uint8_t[]){CTAP_ERR_INVALID_CBOR},
                            1);
  } else if (ctap_cmd == CTAP2_CMD_GET_ASSERTION) {
    cb0r_s map, rp_val, hash_val;
    if (cb0r_read(data, data_len, &map) &&
        cb0r_find(&map, CB0R_UTF8, CTAP2_PARAM_RP, NULL, &rp_val) &&
        cb0r_find(&map, CB0R_BYTE, CTAP2_PARAM_CLIENT_DATA_HASH, NULL,
                  &hash_val)) {
      char rp_id[64] = {0};
      size_t id_len = cb0r_vlen(&rp_val);
      memcpy(rp_id, cb0r_value(&rp_val), id_len > 63 ? 63 : id_len);
      vk_fido_cred_t cred;
      if (vault_fido_list_by_rp(rp_id, &cred, 1) > 0) {
        uint8_t rp_id_hash[32], auth_data[37], to_sign[37 + 32], sig[64 + 69];
        SHA256_CTX ctx;
        sha256_init(&ctx);
        sha256_update(&ctx, (uint8_t *)rp_id, strlen(rp_id));
        sha256_final(&ctx, rp_id_hash);
        size_t ad_len = encode_auth_data(auth_data, rp_id_hash, 0x01, 0, NULL,
                                         NULL, 0, NULL);
        memcpy(to_sign, auth_data, ad_len);
        memcpy(to_sign + ad_len, cb0r_value(&hash_val), 32);
        unsigned long long sig_len;
        crypto_sign_ed25519_tweet(sig, &sig_len, to_sign, ad_len + 32,
                                  cred.private_key);

        uint8_t res_buf[256];
        res_buf[0] = 0x00;
        res_buf[1] = 0xA3;
        res_buf[2] = 0x01;
        res_buf[3] = 0xA2;
        res_buf[4] = 0x62;
        res_buf[5] = 'i';
        res_buf[6] = 'd';
        res_buf[7] = 0x58;
        res_buf[8] = 0x20;
        memcpy(&res_buf[9], cred.credential_id, 32);
        res_buf[41] = 0x64;
        res_buf[42] = 't';
        res_buf[43] = 'y';
        res_buf[44] = 'p';
        res_buf[45] = 'e';
        res_buf[46] = 0x6A;
        memcpy(&res_buf[47], "public-key", 10);
        res_buf[57] = 0x02;
        res_buf[58] = 0x58;
        res_buf[59] = (uint8_t)ad_len;
        memcpy(&res_buf[60], auth_data, ad_len);
        size_t off = 60 + ad_len;
        res_buf[off++] = 0x03;
        res_buf[off++] = 0x58;
        res_buf[off++] = 64;
        memcpy(&res_buf[off], sig, 64);
        off += 64;
        vk_fido_send_response(cid, U2FHID_MSG, res_buf, off);
      } else
        vk_fido_send_response(cid, U2FHID_MSG,
                              (uint8_t[]){CTAP_ERR_NO_CREDENTIALS}, 1);
    } else
      vk_fido_send_response(cid, U2FHID_MSG, (uint8_t[]){CTAP_ERR_INVALID_CBOR},
                            1);
  } else
    vk_fido_send_response(cid, U2FHID_ERROR, (uint8_t[]){0x01}, 1);
}

// --- Transport Layer ---

void vk_fido_handle_report(uint8_t const *report) {
  uint32_t cid;
  memcpy(&cid, report, 4);
  if (report[4] & 0x80) { // Init packet
    uint8_t cmd = report[4] & 0x7F;
    uint16_t len = (report[5] << 8) | report[6];
    if (cid == 0xFFFFFFFF && cmd == (U2FHID_INIT & 0x7F)) {
      u2fhid_init_resp_t resp;
      memcpy(resp.nonce, &report[7], 8);
      resp.cid = next_cid++;
      resp.versionInterface = 2;
      resp.versionMajor = 2;
      resp.versionMinor = 0;
      resp.versionBuild = 0;
      resp.capFlags = 0x01;
      vk_fido_send_response(0xFFFFFFFF, U2FHID_INIT, (uint8_t *)&resp,
                            sizeof(resp));
      return;
    }
    if (cmd == (U2FHID_PING & 0x7F)) {
      vk_fido_send_response(cid, U2FHID_PING, &report[7], len > 57 ? 57 : len);
    } else if (cmd == (U2FHID_MSG & 0x7F)) {
      fido_ctx.cid = cid;
      fido_ctx.cmd = U2FHID_MSG;
      fido_ctx.total_len = len;
      fido_ctx.current_len = 0;
      fido_ctx.next_seq = 0;
      fido_ctx.active = true;
      size_t to_copy = len > 57 ? 57 : len;
      memcpy(fido_ctx.buffer, &report[7], to_copy);
      fido_ctx.current_len = (uint16_t)to_copy;
      if (fido_ctx.current_len >= fido_ctx.total_len) {
        vk_fido_dispatch_ctap2(cid, fido_ctx.buffer, fido_ctx.total_len);
        fido_ctx.active = false;
      }
    }
  } else { // Continuation packet
    uint8_t seq = report[4];
    if (fido_ctx.active && cid == fido_ctx.cid && seq == fido_ctx.next_seq) {
      size_t remaining = fido_ctx.total_len - fido_ctx.current_len;
      size_t to_copy = remaining > 59 ? 59 : remaining;
      memcpy(fido_ctx.buffer + fido_ctx.current_len, &report[5], to_copy);
      fido_ctx.current_len += (uint16_t)to_copy;
      fido_ctx.next_seq++;
      if (fido_ctx.current_len >= fido_ctx.total_len) {
        vk_fido_dispatch_ctap2(cid, fido_ctx.buffer, fido_ctx.total_len);
        fido_ctx.active = false;
      }
    }
  }
}

void vk_fido_send_response(uint32_t cid, uint8_t cmd, uint8_t const *data,
                           uint16_t len) {
  uint8_t report[64] = {0};
  memcpy(report, &cid, 4);
  report[4] = cmd | 0x80;
  report[5] = (uint8_t)(len >> 8);
  report[6] = (uint8_t)(len & 0xFF);
  size_t sent = len > 57 ? 57 : len;
  if (data)
    memcpy(&report[7], data, sent);
  tud_hid_n_report(FIDO_ITF_INDEX, 0, report, 64);
  uint8_t seq = 0;
  while (sent < len) {
    memset(report, 0, 64);
    memcpy(report, &cid, 4);
    report[4] = seq++;
    size_t to_send = (len - sent) > 59 ? 59 : (len - sent);
    memcpy(&report[5], data + sent, to_send);
    sent += to_send;
    while (!tud_hid_n_ready(FIDO_ITF_INDEX)) {
      tud_task();
    }
    tud_hid_n_report(FIDO_ITF_INDEX, 0, report, 64);
  }
}
