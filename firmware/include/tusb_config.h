#ifndef _TUSB_CONFIG_H_
#define _TUSB_CONFIG_H_

#ifdef __cplusplus
extern "C" {
#endif

// RHPort number used for device can be 0 or 1
#ifndef BOARD_TUD_RHPORT
#define BOARD_TUD_RHPORT 0
#endif

// RHPort Max Speed
#ifndef BOARD_TUD_MAX_SPEED
#define BOARD_TUD_MAX_SPEED OPT_MODE_FULL_SPEED
#endif

// Device stack enabled
#define CFG_TUD_ENABLED 1

// Endpoint mapping
#define CFG_TUD_ENDPOINT0_SIZE 64

// CDC enabled
#define CFG_TUD_CDC 1
#define CFG_TUD_CDC_RX_BUFSIZE 512
#define CFG_TUD_CDC_TX_BUFSIZE 512

// HID enabled
#define CFG_TUD_HID 2
#define CFG_TUD_HID_BUFSIZE 64

#ifdef __cplusplus
}
#endif

#endif /* _TUSB_CONFIG_H_ */
