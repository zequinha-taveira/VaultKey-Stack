#ifndef VK_PROTOCOL_H
#define VK_PROTOCOL_H

#include <stdbool.h>
#include <stdint.h>

// Protocol Constants
#define VK_PROTO_VERSION 1

typedef enum {
  VK_MSG_PING = 0,
  VK_MSG_PONG = 1,
  VK_MSG_AUTH_REQ = 4,
  VK_MSG_AUTH_RES = 5,
  VK_MSG_GET_SECURITY_REQ = 16,
  VK_MSG_GET_SECURITY_RES = 17,
  VK_MSG_VAULT_LIST_REQ = 20,
  VK_MSG_VAULT_LIST_RES = 21,
  VK_MSG_VAULT_GET_REQ = 22,
  VK_MSG_VAULT_GET_RES = 23,
  VK_MSG_VAULT_ADD_REQ = 24,
  VK_MSG_VAULT_ADD_RES = 25,
  VK_MSG_VAULT_DEL_REQ = 26,
  VK_MSG_VAULT_DEL_RES = 27,
  VK_MSG_TOTP_REQ = 30,
  VK_MSG_TOTP_RES = 31,
  VK_MSG_KEYB_TYPE_REQ = 14,
  VK_MSG_KEYB_TYPE_RES = 15,
  VK_MSG_FIDO_LIST_REQ = 40,
  VK_MSG_FIDO_LIST_RES = 41,
  VK_MSG_FIDO_DEL_REQ = 42,
  VK_MSG_FIDO_DEL_RES = 43,
  VK_MSG_FIDO_PIN_STATUS_REQ = 44,
  VK_MSG_FIDO_PIN_STATUS_RES = 45,
  VK_MSG_FIDO_SET_PIN_REQ = 46,
  VK_MSG_FIDO_SET_PIN_RES = 47,
  VK_MSG_LOCK_REQ = 50,
  VK_MSG_LOCK_RES = 51,
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
