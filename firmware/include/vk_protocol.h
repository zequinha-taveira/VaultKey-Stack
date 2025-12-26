#ifndef VK_PROTOCOL_H
#define VK_PROTOCOL_H

#include <stdbool.h>
#include <stdint.h>

// Protocol Constants
#define VK_PROTO_VERSION 1

typedef enum {
  VK_MSG_PING = 0,
  VK_MSG_PONG = 1,
  VK_MSG_AUTH_CHALLENGE = 2,
  VK_MSG_AUTH_RESPONSE = 3,
  VK_MSG_VAULT_LIST_REQ = 4,
  VK_MSG_VAULT_LIST_RES = 5,
  VK_MSG_VAULT_GET_REQ = 6,
  VK_MSG_VAULT_GET_RES = 7,
  VK_MSG_VAULT_SET_REQ = 8,
  VK_MSG_VAULT_SET_RES = 9,
  VK_MSG_VAULT_DELETE_REQ = 10,
  VK_MSG_VAULT_DELETE_RES = 11,
  VK_MSG_TOTP_REQ = 12,
  VK_MSG_TOTP_RES = 13,
  VK_MSG_ERROR = 255
} vk_msg_type_t;

typedef struct {
  uint8_t version;
  vk_msg_type_t type;
  uint32_t id;
  const uint8_t *payload;
  uint16_t payload_len;
} vk_packet_t;

// Initialize protocol handler
void vk_protocol_init(void);

// Parse incoming CBOR data into a packet
bool vk_protocol_parse(const uint8_t *data, uint16_t len,
                       vk_packet_t *out_packet);

// Create a CBOR response
uint16_t vk_protocol_create_packet(vk_msg_type_t type, uint32_t id,
                                   const uint8_t *payload, uint16_t payload_len,
                                   uint8_t *out_buf, uint16_t max_len);

#endif // VK_PROTOCOL_H
