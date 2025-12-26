#ifndef VK_FIDO_H
#define VK_FIDO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// U2FHID Commands
#define U2FHID_PING 0x81
#define U2FHID_MSG 0x83
#define U2FHID_LOCK 0x84
#define U2FHID_INIT 0x86
#define U2FHID_WINK 0x08
#define U2FHID_ERROR 0xBF

// CTAP2 Commands
#define CTAP2_CMD_MAKE_CREDENTIAL 0x01
#define CTAP2_CMD_GET_ASSERTION 0x02
#define CTAP2_CMD_GET_INFO 0x04

// CTAP2 Parameters
#define CTAP2_PARAM_CLIENT_DATA_HASH 0x01
#define CTAP2_PARAM_RP 0x02
#define CTAP2_PARAM_USER 0x03
#define CTAP2_PARAM_PUB_KEY_PARAMS 0x04
#define CTAP2_PARAM_OPTIONS 0x07

// U2FHID Initialization response structure
typedef struct {
  uint8_t nonce[8];
  uint32_t cid;
  uint8_t versionInterface;
  uint8_t versionMajor;
  uint8_t versionMinor;
  uint8_t versionBuild;
  uint8_t capFlags;
} u2fhid_init_resp_t;

/**
 * Handle an incoming FIDO HID report.
 *
 * @param report 64-byte HID report buffer
 */
void vk_fido_handle_report(uint8_t const *report);

/**
 * Send a FIDO HID response.
 */
void vk_fido_send_response(uint32_t cid, uint8_t cmd, uint8_t const *data,
                           uint16_t len);

#endif // VK_FIDO_H
