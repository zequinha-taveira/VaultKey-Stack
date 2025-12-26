#include "pico/stdlib.h"
#include "tusb.h"
#include "vk_protocol.h"
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
    }
    // Handle other message types here
  }
}

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
  (void)itf;
  (void)report_id;
  (void)report_type;
  (void)buffer;
  (void)bufsize;

  // Protocol can also be handled over HID for better cross-platform
  // compatibility without drivers
  vk_packet_t packet;
  if (vk_protocol_parse(buffer, (uint16_t)bufsize, &packet)) {
    // Process packet...
  }
}

int main() {
  stdio_init_all();
  tusb_init();
  vk_protocol_init();

  while (1) {
    tud_task(); // tinyusb device task
  }

  return 0;
}
