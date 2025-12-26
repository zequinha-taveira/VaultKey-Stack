#include "vk_protocol.h"
#include <string.h>

// Minimal CBOR helper functions could go here
// For Phase 2, we implement a skeletal parser that recognizes the basic
// structure

void vk_protocol_init(void) {
  // Initialize any state (e.g., auth status)
}

bool vk_protocol_parse(const uint8_t *data, uint16_t len,
                       vk_packet_t *out_packet) {
  if (len < 3)
    return false;

  // VERY minimal "CBOR-like" parser for initial development
  // In a real implementation, this would use a proper CBOR library (e.g. QCBOR)

  // For now, let's assume a simplified framing:
  // [Version:1][Type:1][ID:4][PayloadLen:2][Payload:...]

  out_packet->version = data[0];
  out_packet->type = (vk_msg_type_t)data[1];

  // TODO: Implement actual CBOR decoding logic here
  // This is a placeholder for Phase 2 implementation.

  return true;
}

uint16_t vk_protocol_create_packet(vk_msg_type_t type, uint32_t id,
                                   const uint8_t *payload, uint16_t payload_len,
                                   uint8_t *out_buf, uint16_t max_len) {
  // Placeholder for CBOR encoding
  if (max_len < (payload_len + 8))
    return 0;

  out_buf[0] = VK_PROTO_VERSION;
  out_buf[1] = (uint8_t)type;
  // ... encode ID and length ...
  memcpy(&out_buf[8], payload, payload_len);

  return payload_len + 8;
}
