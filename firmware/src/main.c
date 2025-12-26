#include "pico/stdlib.h"
#include "tusb.h"
#include "vault.h"
#include "vk_protocol.h"
#include "vk_totp.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

// CDC Callback: Invoked when CDC interface received data from host
void tud_cdc_rx_cb(uint8_t itf) {
  (void)itf;
  uint8_t buf[128];
  uint32_t count = tud_cdc_read(buf, sizeof(buf));

  vk_packet_t packet;
  if (vk_protocol_parse(buf, (uint16_t)count, &packet)) {
    if (packet.type == VK_MSG_PING) {
      uint8_t res_buf[64];
      uint16_t res_len = vk_protocol_create_packet(VK_MSG_PONG, packet.id,
                                                   (const uint8_t *)"PONG", 4,
                                                   res_buf, sizeof(res_buf));
      if (res_len > 0) {
        tud_cdc_write(res_buf, res_len);
        tud_cdc_write_flush();
      }
    } else if (packet.type == VK_MSG_AUTH_REQ) {
      if (packet.payload_len == 32) {
        if (vault_is_locked()) {
          uint8_t res_buf[64];
          uint16_t res_len = vk_protocol_create_packet(
              VK_MSG_ERROR, packet.id, (const uint8_t *)"LOCKED", 6, res_buf,
              sizeof(res_buf));
          tud_cdc_write(res_buf, res_len);
          tud_cdc_write_flush();
        } else {
          bool success = false;
          if (!vault_is_setup()) {
            // First run: Initialize canary with this key
            success = vault_setup_canary(packet.payload);
            if (success) {
              vault_set_session_key(packet.payload);
            }
          } else {
            // Standard login: Verify against canary
            success = vault_verify_pin(packet.payload);
            if (success) {
              vault_set_session_key(packet.payload);
              vault_report_auth_result(true);
            } else {
              vault_report_auth_result(false);
            }
          }

          uint8_t res_buf[64];
          uint16_t res_len = vk_protocol_create_packet(
              VK_MSG_AUTH_RES, packet.id,
              (const uint8_t *)(success ? "OK" : "FAIL"), success ? 2 : 4,
              res_buf, sizeof(res_buf));
          tud_cdc_write(res_buf, res_len);
          tud_cdc_write_flush();
        }
      }
    } else if (packet.type == VK_MSG_VAULT_DEL_REQ) {
      // Payload: [NameLen:1][Name:N]
      if (packet.payload_len > 1) {
        uint8_t name_len = packet.payload[0];
        char name[ENTRY_NAME_MAX];
        uint8_t safe_name_len =
            name_len < (ENTRY_NAME_MAX - 1) ? name_len : (ENTRY_NAME_MAX - 1);
        memcpy(name, &packet.payload[1], safe_name_len);
        name[safe_name_len] = '\0';

        bool success = vault_delete(name);

        uint8_t res_buf[64];
        uint16_t res_len = vk_protocol_create_packet(
            VK_MSG_VAULT_DEL_RES, packet.id,
            (const uint8_t *)(success ? "OK" : "FAIL"), success ? 2 : 4,
            res_buf, sizeof(res_buf));
        tud_cdc_write(res_buf, res_len);
        tud_cdc_write_flush();
      }
    } else if (packet.type == VK_MSG_GET_SECURITY_REQ) {
      uint8_t status[5];
      uint32_t fails = vault_get_fail_count();
      memcpy(status, &fails, 4);
      status[4] = vault_is_locked() ? 1 : 0;

      uint8_t res_buf[64];
      uint16_t res_len =
          vk_protocol_create_packet(VK_MSG_GET_SECURITY_RES, packet.id, status,
                                    5, res_buf, sizeof(res_buf));
      tud_cdc_write(res_buf, res_len);
      tud_cdc_write_flush();
    } else if (packet.type == VK_MSG_TOTP_REQ) {
      if (packet.payload_len >= 8) {
        uint64_t timestamp = 0;
        memcpy(&timestamp, packet.payload, 8);

        // Mock seed for TOTP demo
        const uint8_t mock_seed[] = "JBSWY3DPEHPK3PXP"; // Base32: 'HELLO'
        uint32_t code =
            vk_totp_generate(mock_seed, sizeof(mock_seed) - 1, timestamp);

        char code_str[8];
        snprintf(code_str, sizeof(code_str), "%06u", code);

        uint8_t res_buf[64];
        uint16_t res_len = vk_protocol_create_packet(
            VK_MSG_TOTP_RES, packet.id, (const uint8_t *)code_str, 6, res_buf,
            sizeof(res_buf));
        if (res_len > 0) {
          tud_cdc_write(res_buf, res_len);
          tud_cdc_write_flush();
        }
      }
    } else if (packet.type == VK_MSG_VAULT_GET_REQ) {
      // Payload: [NameLen:1][Name:N]
      if (packet.payload_len > 1) {
        uint8_t name_len = packet.payload[0];
        char name[ENTRY_NAME_MAX];
        uint8_t safe_name_len =
            name_len < (ENTRY_NAME_MAX - 1) ? name_len : (ENTRY_NAME_MAX - 1);
        memcpy(name, &packet.payload[1], safe_name_len);
        name[safe_name_len] = '\0';

        uint8_t secret[ENTRY_SECRET_MAX];
        uint16_t secret_len = 0;
        bool success = vault_get_decrypted(name, secret, &secret_len);

        uint8_t res_buf[128];
        uint16_t res_len =
            vk_protocol_create_packet(VK_MSG_VAULT_GET_RES, packet.id, secret,
                                      secret_len, res_buf, sizeof(res_buf));

        // Sanitize memory
        vk_crypto_zeroize(secret, sizeof(secret));

        tud_cdc_write(res_buf, res_len);
        tud_cdc_write_flush();
      }
    } else if (packet.type == VK_MSG_VAULT_LIST_REQ) {
      char names[MAX_ENTRIES][ENTRY_NAME_MAX];
      int count = vault_list(names, MAX_ENTRIES);

      uint8_t list_payload[512]; // Buffer for packed names
      uint16_t offset = 0;
      for (int i = 0; i < count; i++) {
        uint8_t name_len = (uint8_t)strlen(names[i]);
        if (offset + 1 + name_len > sizeof(list_payload))
          break;
        list_payload[offset++] = name_len;
        memcpy(&list_payload[offset], names[i], name_len);
        offset += name_len;
      }

      uint8_t res_buf[1024]; // Larger response buffer
      uint16_t res_len = vk_protocol_create_packet(
          VK_MSG_VAULT_LIST_RES, packet.id, list_payload, offset, res_buf,
          sizeof(res_buf));
      tud_cdc_write(res_buf, res_len);
      tud_cdc_write_flush();
    } else if (packet.type == VK_MSG_VAULT_ADD_REQ) {
      // Payload: [NameLen:1][Name:N][SecretLen:1][Secret:S]
      if (packet.payload_len > 2) {
        uint8_t name_len = packet.payload[0];
        char name[ENTRY_NAME_MAX];
        uint8_t safe_name_len =
            name_len < (ENTRY_NAME_MAX - 1) ? name_len : (ENTRY_NAME_MAX - 1);
        memcpy(name, &packet.payload[1], safe_name_len);
        name[safe_name_len] = '\0';

        uint16_t secret_offset = 1 + name_len;
        if (secret_offset < packet.payload_len) {
          uint8_t secret_len = packet.payload[secret_offset];
          uint8_t *secret = &packet.payload[secret_offset + 1];

          bool success = vault_set(name, secret, secret_len);

          uint8_t res_buf[64];
          uint16_t res_len = vk_protocol_create_packet(
              VK_MSG_VAULT_ADD_RES, packet.id,
              (const uint8_t *)(success ? "OK" : "FAIL"), success ? 2 : 4,
              res_buf, sizeof(res_buf));
          tud_cdc_write(res_buf, res_len);
          tud_cdc_write_flush();
        }
      }
    }
  }
}
else if (packet.type == VK_MSG_FIDO_LIST_REQ) {
  vk_fido_cred_t creds[MAX_FIDO_CREDS];
  int count = vault_fido_list_all(creds, MAX_FIDO_CREDS);

  uint8_t list_payload[1024];
  uint16_t offset = 0;
  for (int i = 0; i < count; i++) {
    uint8_t rp_len = (uint8_t)strlen(creds[i].rp_id);
    list_payload[offset++] = rp_len;
    memcpy(&list_payload[offset], creds[i].rp_id, rp_len);
    offset += rp_len;
    list_payload[offset++] = 32; // cred_id len
    memcpy(&list_payload[offset], creds[i].credential_id, 32);
    offset += 32;
  }

  uint8_t res_buf[1024 + 64];
  uint16_t res_len =
      vk_protocol_create_packet(VK_MSG_FIDO_LIST_RES, packet.id, list_payload,
                                offset, res_buf, sizeof(res_buf));
  tud_cdc_write(res_buf, res_len);
  tud_cdc_write_flush();
}
else if (packet.type == VK_MSG_FIDO_DEL_REQ) {
  if (packet.payload_len == 32) {
    bool success = vault_fido_delete(packet.payload);
    uint8_t res_buf[64];
    uint16_t res_len =
        vk_protocol_create_packet(VK_MSG_FIDO_DEL_RES, packet.id,
                                  (const uint8_t *)(success ? "OK" : "FAIL"),
                                  success ? 2 : 4, res_buf, sizeof(res_buf));
    tud_cdc_write(res_buf, res_len);
    tud_cdc_write_flush();
  }
}
}
}

#include "vk_fido.h"

// HID Callback: Invoked when received GET_REPORT control request
uint16_t tud_hid_get_report_cb(uint8_t itf, uint8_t report_id,
                               hid_report_type_t report_type, uint8_t *buffer,
                               uint16_t reqlen) {
  (void)itf;
  (void)report_id;
  (void)report_type;
  (void)buffer;
  (void)reqlen;
  return 0;
}

// HID Callback: Invoked when received SET_REPORT control request or output
// report
void tud_hid_set_report_cb(uint8_t itf, uint8_t report_id,
                           hid_report_type_t report_type, uint8_t const *buffer,
                           uint16_t bufsize) {
  (void)report_id;
  (void)report_type;

  if (itf == 2) { // ITF_NUM_HID_FIDO
    vk_fido_handle_report(buffer);
    return;
  }

  // Original Protocol handler (ITF 0)
  if (itf == 0) {
    vk_packet_t packet;
    if (vk_protocol_parse(buffer, (uint16_t)bufsize, &packet)) {
      // Logic from CDC handler could be shared here
    }
  }
}

#include "vk_crypto.h"

int main() {
  stdio_init_all();

  // Security Health Check: Ensure TRNG is working
  if (!vk_crypto_trng_check()) {
    // Critical failure: Hardware random generator not responding or stuck.
    // In a real device, we would blink an LED or show an error.
    while (1) {
      tight_loop_contents();
    }
  }

  tusb_init();
  vk_protocol_init();

  while (1) {
    tud_task(); // tinyusb device task
  }

  return 0;
}
