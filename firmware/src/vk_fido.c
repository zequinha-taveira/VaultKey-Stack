#include "vk_fido.h"
#include "cb0r.h"
#include "tusb.h"
#include "tweetnacl.h"
#include "vault.h"
#include "vk_crypto.h"
#include <string.h>

// Current channel ID (simplified: we'll use a static one for now or a counter)
static uint32_t next_cid = 0x11223344;

void vk_fido_handle_report(uint8_t const *report) {
  uint32_t cid;
  memcpy(&cid, report, 4);
  uint8_t cmd = report[4];
  uint16_t len = (report[5] << 8) | report[6];

  if (cmd == U2FHID_INIT) {
    // Handle INIT: Browser sends 8-byte nonce
    u2fhid_init_resp_t resp;
    memcpy(resp.nonce, &report[7], 8);
    resp.cid = next_cid++;
    resp.versionInterface = 2; // CTAP2
    resp.versionMajor = 2;
    resp.versionMinor = 0;
    resp.versionBuild = 0;
    resp.capFlags = 0x01; // CAP_WINK

    vk_fido_send_response(cid, U2FHID_INIT, (uint8_t *)&resp, sizeof(resp));
  } else if (cmd == U2FHID_PING) {
    // Echo back for PING
    vk_fido_send_response(cid, U2FHID_PING, &report[7], len > 57 ? 57 : len);
  } else if (cmd == U2FHID_MSG) {
    // This is where CTAP2 CBOR messages arrive
    uint8_t ctap_cmd = report[7];

    if (ctap_cmd == 0x04) { // authenticatorGetInfo
      // Minimal CTAP2 GetInfo response (CBOR)
      // Structure: [Status:1][CBOR Map]
      static const uint8_t get_info_res[] = {
          0x00, // Success status
          0xa3, // Map of 3 items
          0x01, 0x81, 0x68, 'F', 'I', 'D', 'O', '_', '2', '_',
          '0', // 1: versions ["FIDO_2_0"]
          0x03, 0x50, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0,                               // 3: aaguid (16
                                           // zeros)
          0x04, 0xa1, 0x62, 'r', 'k', 0xf5 // 4: options {rk: true}
      };
      vk_fido_send_response(cid, U2FHID_MSG, get_info_res,
                            sizeof(get_info_res));
    } else if (ctap_cmd == CTAP2_CMD_MAKE_CREDENTIAL) {
      // Parsing MakeCredential parameters (CBOR Map)
      cb0r_s map;
      if (!cb0r_read((uint8_t *)&report[8], len - 1, &map)) {
        uint8_t err = 0x22; // CTAP2_ERR_INVALID_CBOR
        vk_fido_send_response(cid, U2FHID_MSG, &err, 1);
        return;
      }

      // 1. RP ID
      cb0r_s rp_val, rp_id_val;
      if (cb0r_find(&map, CB0R_MAP, CTAP2_PARAM_RP, NULL, &rp_val) ||
          cb0r_find(&map, CB0R_INT, CTAP2_PARAM_RP, NULL, &rp_val)) {

        if (cb0r_find(&rp_val, CB0R_UTF8, 0, (uint8_t *)"id", &rp_id_val)) {
          vk_fido_cred_t new_cred = {0};
          size_t id_len = cb0r_vlen(&rp_id_val);
          memcpy(new_cred.rp_id, cb0r_value(&rp_id_val),
                 id_len > 63 ? 63 : id_len);

          // 2. Generate Keypair
          uint8_t seed[32];
          vk_crypto_get_random(seed, 32);
          crypto_sign_ed25519_tweet_keypair(new_cred.public_key,
                                            new_cred.private_key);
          vk_crypto_get_random(new_cred.credential_id, 32);

          // 3. Store
          if (vault_fido_add(&new_cred)) {
            uint8_t res = 0x00; // Success status
            vk_fido_send_response(cid, U2FHID_MSG, &res, 1);
          } else {
            uint8_t err = 0x27; // CTAP2_ERR_KEY_STORE_FULL
            vk_fido_send_response(cid, U2FHID_MSG, &err, 1);
          }
        }
      }
    } else if (ctap_cmd == CTAP2_CMD_GET_ASSERTION) {
      cb0r_s map, rp_val, allow_list;
      if (!cb0r_read((uint8_t *)&report[8], len - 1, &map)) {
        uint8_t err = 0x22; // CTAP2_ERR_INVALID_CBOR
        vk_fido_send_response(cid, U2FHID_MSG, &err, 1);
        return;
      }

      // 1. RP ID
      if (cb0r_find(&map, CB0R_UTF8, CTAP2_PARAM_RP, NULL, &rp_val)) {
        char rp_id[64] = {0};
        size_t id_len = cb0r_vlen(&rp_val);
        memcpy(rp_id, cb0r_value(&rp_val), id_len > 63 ? 63 : id_len);

        // 2. Find credential (Simplified: take the first one for this RP)
        vk_fido_cred_t cred;
        if (vault_fido_list_by_rp(rp_id, &cred, 1) > 0) {
          // 3. Authenticate (Dummy signature for now to verify logic)
          uint8_t res = 0x00; // Success
          vk_fido_send_response(cid, U2FHID_MSG, &res, 1);
        } else {
          uint8_t err = 0x2b; // CTAP2_ERR_NO_CREDENTIALS
          vk_fido_send_response(cid, U2FHID_MSG, &err, 1);
        }
      }
    } else {
      uint8_t error_code = 0x01; // Invalid command
      vk_fido_send_response(cid, U2FHID_ERROR, &error_code, 1);
    }
  }
}

void vk_fido_send_response(uint32_t cid, uint8_t cmd, uint8_t const *data,
                           uint16_t len) {
  uint8_t report[64] = {0};
  memcpy(report, &cid, 4);
  report[4] = cmd;
  report[5] = (uint8_t)(len >> 8);
  report[6] = (uint8_t)(len & 0xFF);

  size_t data_to_copy = len > 57 ? 57 : len;
  if (data) {
    memcpy(&report[7], data, data_to_copy);
  }

  tud_hid_n_report(ITF_NUM_HID_FIDO, 0, report, 64);
}
