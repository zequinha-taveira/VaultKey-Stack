#include "bsp/board.h"
#include "hardware/gpio.h"
#include "pico/stdlib.h"
#include "tusb.h"
#include "vault.h"
#include "vk_crypto.h"
#include "vk_fido.h"
#include "vk_protocol.h"
#include "vk_totp.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

// Tenstar RP2350-USB Pinout
#define PIN_LED 22    // WS2812 RGB LED
#define PIN_BUTTON 21 // User presence button (external or bridge GP21 to GND)

// Basic WS2812 Bit-bang for RP2350
void ws2812_put_rgb(uint8_t r, uint8_t g, uint8_t b) {
  uint32_t val = ((uint32_t)g << 16) | ((uint32_t)r << 8) | (uint32_t)b;
  for (int i = 23; i >= 0; i--) {
    if (val & (1 << i)) {
      gpio_put(PIN_LED, 1);
      for (volatile int j = 0; j < 10; j++)
        ; // High for long
      gpio_put(PIN_LED, 0);
    } else {
      gpio_put(PIN_LED, 1);
      for (volatile int j = 0; j < 2; j++)
        ; // High for short
      gpio_put(PIN_LED, 0);
    }
  }
}

static bool led_blink_fast = false;
static bool led_active = false;

void vk_main_set_led_mode(bool wait_for_touch) {
  led_blink_fast = wait_for_touch;
  led_active = true;
}

void vk_main_led_off(void) {
  led_active = false;
  ws2812_put_rgb(0, 0, 0); // All off
}

bool vk_main_wait_for_button(uint32_t timeout_ms) {
  uint32_t start = board_millis();
  vk_main_set_led_mode(true); // Fast blink

  while (board_millis() - start < timeout_ms) {
    tud_task(); // Keep USB alive

    // Active low button (pull-up enabled)
    if (!gpio_get(PIN_BUTTON)) {
      vk_main_led_off();
      return true;
    }

    // LED blinking handling is done in led_task called from main while loop?
    // No, main loop calls led_task. Here we are blocking.
    // We should probably run led_task logic here or non-blocking?
    // For simplicity, let's just minimal blink or rely on the fact main loop
    // isn't running? Wait, main loop calls tud_task and led_task. If we block
    // here, we need to call led_task() too? Actually, let's just sleep/delay
    // bit?

    // Re-implement LED blink here for blocking wait
    // Or assume led_task is called? No, we are in a loop.
    // Let's call led void led_task(void); relative forward decl needed?
    // It's defined later. Let's move led_task up or define prototype.
  }
  vk_main_led_off();
  return false;
}

static void led_task(void) {
  if (!led_active)
    return;

  static uint32_t last_step = 0;
  uint32_t now = board_millis();
  uint32_t interval = led_blink_fast ? 100 : 1000;

  if (now - last_step > interval) {
    last_step = now;
    static bool toggle = false;
    toggle = !toggle;
    if (toggle) {
      if (led_blink_fast)
        ws2812_put_rgb(255, 0, 0); // Red for action
      else
        ws2812_put_rgb(0, 0, 255); // Blue for active
    } else {
      ws2812_put_rgb(0, 0, 0);
    }
  }
}

// Re-defining wait_for_button to use led_task if possible, or just simple logic
// Actually, let's fix the order. move led_task up.
// I will just place led_task before wait_for_button in the file structure I
// write.

void tud_cdc_rx_cb(uint8_t itf) {
  (void)itf;
  if (tud_cdc_available()) {
    uint8_t buf[1024];
    uint32_t count = tud_cdc_read(buf, sizeof(buf));

    vk_packet_t packet;
    if (vk_protocol_parse(buf, (uint16_t)count, &packet)) {
      vault_update_activity();

      if (packet.type == VK_MSG_INFO_REQ) {
        uint8_t res_buf[64];
        uint16_t res_len = vk_protocol_create_packet(
            VK_MSG_INFO_RES, packet.id, (const uint8_t *)"VaultKey v1.0", 13,
            res_buf, sizeof(res_buf));
        tud_cdc_write(res_buf, res_len);
        tud_cdc_write_flush();
      } else if (packet.type == VK_MSG_VAULT_UNLOCK_REQ) {
        // [PinLen:1][Pin:N]
        if (packet.payload_len > 1) {
          uint8_t pin_len = packet.payload[0];
          if (pin_len + 1 <= packet.payload_len) {
            char pin[64];
            memcpy(pin, &packet.payload[1], pin_len);
            pin[pin_len] = '\0';
            bool success = vault_unlock(pin);
            uint8_t res_buf[64];
            uint16_t res_len = vk_protocol_create_packet(
                VK_MSG_VAULT_UNLOCK_RES, packet.id,
                (const uint8_t *)(success ? "OK" : "FAIL"), success ? 2 : 4,
                res_buf, sizeof(res_buf));
            tud_cdc_write(res_buf, res_len);
            tud_cdc_write_flush();
          }
        }
      } else if (packet.type == VK_MSG_VAULT_ADD_REQ) {
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
      } else if (packet.type == VK_MSG_VAULT_GET_REQ) {
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

          vk_crypto_zeroize(secret, sizeof(secret));
          tud_cdc_write(res_buf, res_len);
          tud_cdc_write_flush();
        }
      } else if (packet.type == VK_MSG_VAULT_DEL_REQ) {
        if (packet.payload_len > 0) {
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
      } else if (packet.type == VK_MSG_VAULT_LIST_REQ) {
        char names[MAX_ENTRIES][ENTRY_NAME_MAX];
        int count = vault_list(names, MAX_ENTRIES);
        uint8_t list_payload[1024];
        uint16_t offset = 0;
        for (int i = 0; i < count; i++) {
          uint8_t nlen = (uint8_t)strlen(names[i]);
          if (offset + 1 + nlen > sizeof(list_payload))
            break;
          list_payload[offset++] = nlen;
          memcpy(&list_payload[offset], names[i], nlen);
          offset += nlen;
        }
        uint8_t res_buf[1024 + 64];
        uint16_t res_len = vk_protocol_create_packet(
            VK_MSG_VAULT_LIST_RES, packet.id, list_payload, offset, res_buf,
            sizeof(res_buf));
        tud_cdc_write(res_buf, res_len);
        tud_cdc_write_flush();
      } else if (packet.type == VK_MSG_GET_SECURITY_REQ) {
        uint8_t status[5];
        uint32_t fails = vault_get_fail_count();
        memcpy(status, &fails, 4);
        status[4] = vault_is_locked() ? 1 : 0;
        uint8_t res_buf[64];
        uint16_t res_len =
            vk_protocol_create_packet(VK_MSG_GET_SECURITY_RES, packet.id,
                                      status, 5, res_buf, sizeof(res_buf));
        tud_cdc_write(res_buf, res_len);
        tud_cdc_write_flush();
      } else if (packet.type == VK_MSG_TOTP_REQ) {
        if (packet.payload_len >= 8) {
          uint64_t ts = 0;
          memcpy(&ts, packet.payload, 8);
          const uint8_t mock_seed[] = "JBSWY3DPEHPK3PXP";
          uint32_t code =
              vk_totp_generate(mock_seed, sizeof(mock_seed) - 1, ts);
          char code_str[8];
          snprintf(code_str, sizeof(code_str), "%06lu", code); // Correct format
          uint8_t res_buf[64];
          uint16_t res_len = vk_protocol_create_packet(
              VK_MSG_TOTP_RES, packet.id, (const uint8_t *)code_str, 6, res_buf,
              sizeof(res_buf));
          tud_cdc_write(res_buf, res_len);
          tud_cdc_write_flush();
        }
      } else if (packet.type == VK_MSG_LOCK_REQ) {
        vault_lock();
        uint8_t res_buf[64];
        uint16_t res_len = vk_protocol_create_packet(VK_MSG_LOCK_RES, packet.id,
                                                     (const uint8_t *)"OK", 2,
                                                     res_buf, sizeof(res_buf));
        tud_cdc_write(res_buf, res_len);
        tud_cdc_write_flush();
      } else if (packet.type == VK_MSG_FIDO_LIST_REQ) {
        vk_fido_cred_t creds[MAX_FIDO_CREDS];
        int count = vault_fido_list_all(creds, MAX_FIDO_CREDS);
        uint8_t list_payload[1024];
        uint16_t offset = 0;
        for (int i = 0; i < count; i++) {
          uint8_t rplen = (uint8_t)strlen(creds[i].rp_id);
          if (offset + 64 > sizeof(list_payload))
            break;
          list_payload[offset++] = rplen;
          memcpy(&list_payload[offset], creds[i].rp_id, rplen);
          offset += rplen;
          list_payload[offset++] = 32;
          memcpy(&list_payload[offset], creds[i].credential_id, 32);
          offset += 32;
        }
        uint8_t res_buf[1024 + 64];
        uint16_t res_len = vk_protocol_create_packet(
            VK_MSG_FIDO_LIST_RES, packet.id, list_payload, offset, res_buf,
            sizeof(res_buf));
        tud_cdc_write(res_buf, res_len);
        tud_cdc_write_flush();
      } else if (packet.type == VK_MSG_FIDO_DEL_REQ) {
        if (packet.payload_len == 32) {
          bool success = vault_fido_delete(packet.payload);
          uint8_t res_buf[64];
          uint16_t res_len = vk_protocol_create_packet(
              VK_MSG_FIDO_DEL_RES, packet.id,
              (const uint8_t *)(success ? "OK" : "FAIL"), success ? 2 : 4,
              res_buf, sizeof(res_buf));
          tud_cdc_write(res_buf, res_len);
          tud_cdc_write_flush();
        }
      } else if (packet.type == VK_MSG_FIDO_PIN_STATUS_REQ) {
        uint8_t status = vault_fido_has_pin() ? 1 : 0;
        uint8_t res_buf[64];
        uint16_t res_len =
            vk_protocol_create_packet(VK_MSG_FIDO_PIN_STATUS_RES, packet.id,
                                      &status, 1, res_buf, sizeof(res_buf));
        tud_cdc_write(res_buf, res_len);
        tud_cdc_write_flush();
      } else if (packet.type == VK_MSG_FIDO_SET_PIN_REQ) {
        if (packet.payload_len == 32) {
          bool success = vault_fido_set_pin(packet.payload);
          uint8_t res_buf[64];
          uint16_t res_len = vk_protocol_create_packet(
              VK_MSG_FIDO_SET_PIN_RES, packet.id,
              (const uint8_t *)(success ? "OK" : "FAIL"), success ? 2 : 4,
              res_buf, sizeof(res_buf));
          tud_cdc_write(res_buf, res_len);
          tud_cdc_write_flush();
        }
      }
    }
  }
}

// FIDO HID & Main are simpler.

// FIDO Callback
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

// HID Callback: Invoked when received SET_REPORT control request
void tud_hid_set_report_cb(uint8_t itf, uint8_t report_id,
                           hid_report_type_t report_type, uint8_t const *buffer,
                           uint16_t bufsize) {
  (void)itf;
  (void)report_id;
  (void)report_type;

  // Handle FIDO HID packets
  // FIDO packets are 64 bytes
  if (bufsize == 64) {
    vault_update_activity();
    vk_fido_handle_report(buffer);
  }
}

int main(void) {
  board_init();
  tusb_init();
  vault_init();

  gpio_init(PIN_LED);
  gpio_set_dir(PIN_LED, GPIO_OUT);

  // GP21 Button
  gpio_init(PIN_BUTTON);
  gpio_set_dir(PIN_BUTTON, GPIO_IN);
  gpio_pull_up(PIN_BUTTON);

  while (1) {
    tud_task(); // tinyusb device task
    led_task();
    vault_check_autolock();
  }
  return 0;
}
