#include "tusb.h"

#define USBD_VID 0x234b
#define USBD_PID 0x0000

//--------------------------------------------------------------------+
// HID Report Descriptors
//--------------------------------------------------------------------+

// HID Generic Report (for Protocol)
uint8_t const desc_hid_generic_report[] = {
    TUD_HID_REPORT_DESC_GENERIC_INOUT(CFG_TUD_HID_BUFSIZE)};

// HID Keyboard Report
uint8_t const desc_hid_keyboard_report[] = {TUD_HID_REPORT_DESC_KEYBOARD()};

// HID FIDO Report (U2FHID)
// Usage Page 0xF1D0, Usage 0x01
uint8_t const desc_hid_fido_report[] = {
    0x06, 0xd0, 0xf1, // Usage Page (FIDO Alliance)
    0x09, 0x01,       // Usage (U2F HID Authenticator Device)
    0xa1, 0x01,       // Collection (Application)
    0x09, 0x20,       // Usage (Data In)
    0x15, 0x00,       // Logical Minimum (0)
    0x26, 0xff, 0x00, // Logical Maximum (255)
    0x75, 0x08,       // Report Size (8)
    0x95, 0x40,       // Report Count (64)
    0x81, 0x02,       // Input (Data, Absolute, Variable)
    0x09, 0x21,       // Usage (Data Out)
    0x15, 0x00,       // Logical Minimum (0)
    0x26, 0xff, 0x00, // Logical Maximum (255)
    0x75, 0x08,       // Report Size (8)
    0x95, 0x40,       // Report Count (64)
    0x91, 0x02,       // Output (Data, Absolute, Variable)
    0xc0              // End Collection
};

// Array of HID report descriptors
uint8_t const *const hid_report_descriptors[] = {
    desc_hid_generic_report, desc_hid_keyboard_report, desc_hid_fido_report};

uint8_t const *tud_hid_descriptor_report_cb(uint8_t itf) {
  return hid_report_descriptors[itf];
}

//--------------------------------------------------------------------+
// Device Descriptor
//--------------------------------------------------------------------+
tusb_desc_device_t const desc_device = {.bLength = sizeof(tusb_desc_device_t),
                                        .bDescriptorType = TUSB_DESC_DEVICE,
                                        .bcdUSB = 0x0210, // USB 2.1 for BOS
                                        .bDeviceClass = TUSB_CLASS_MISC,
                                        .bDeviceSubClass = MISC_SUBCLASS_COMMON,
                                        .bDeviceProtocol = MISC_PROTOCOL_IAD,
                                        .bMaxPacketSize0 =
                                            CFG_TUD_ENDPOINT0_SIZE,
                                        .idVendor = USBD_VID,
                                        .idProduct = USBD_PID,
                                        .bcdDevice = 0x0100,
                                        .iManufacturer = 0x01,
                                        .iProduct = 0x02,
                                        .iSerialNumber = 0x03,
                                        .bNumConfigurations = 0x01};

uint8_t const *tud_descriptor_device_cb(void) {
  return (uint8_t const *)&desc_device;
}

//--------------------------------------------------------------------+
// Configuration Descriptor
//--------------------------------------------------------------------+
enum {
  ITF_NUM_CDC = 0,
  ITF_NUM_CDC_DATA,
  ITF_NUM_HID_GENERIC,
  ITF_NUM_HID_KEYBOARD,
  ITF_NUM_HID_FIDO,
  ITF_NUM_TOTAL
};

#define CONFIG_ID_TOTAL_LEN                                                    \
  (TUD_CONFIG_DESC_LEN + TUD_CDC_DESC_LEN + (3 * TUD_HID_DESC_LEN))

#define EPNUM_CDC_NOTIF 0x81
#define EPNUM_CDC_OUT 0x02
#define EPNUM_CDC_IN 0x82
#define EPNUM_HID_GEN 0x83
#define EPNUM_HID_KEYB 0x84
#define EPNUM_HID_FIDO 0x85

uint8_t const desc_configuration[] = {
    TUD_CONFIG_DESCRIPTOR(1, ITF_NUM_TOTAL, 0, CONFIG_ID_TOTAL_LEN,
                          TUSB_DESC_CONFIG_ATT_REMOTE_WAKEUP, 100),

    // CDC
    TUD_CDC_DESCRIPTOR(ITF_NUM_CDC, 4, EPNUM_CDC_NOTIF, 8, EPNUM_CDC_OUT,
                       EPNUM_CDC_IN, 64),

    // HID Generic
    TUD_HID_DESCRIPTOR(ITF_NUM_HID_GENERIC, 5, HID_ITF_PROTOCOL_NONE,
                       sizeof(desc_hid_generic_report), EPNUM_HID_GEN,
                       CFG_TUD_HID_BUFSIZE, 10),

    // HID Keyboard
    TUD_HID_DESCRIPTOR(ITF_NUM_HID_KEYBOARD, 6, HID_ITF_PROTOCOL_KEYBOARD,
                       sizeof(desc_hid_keyboard_report), EPNUM_HID_KEYB, 8, 10),

    // HID FIDO
    TUD_HID_DESCRIPTOR(ITF_NUM_HID_FIDO, 7, HID_ITF_PROTOCOL_NONE,
                       sizeof(desc_hid_fido_report), EPNUM_HID_FIDO,
                       CFG_TUD_HID_BUFSIZE, 10)};

uint8_t const *tud_descriptor_configuration_cb(uint8_t index) {
  return desc_configuration;
}

//--------------------------------------------------------------------+
// String Descriptors
//--------------------------------------------------------------------+
char const *string_desc_arr[] = {
    (const char[]){0x09, 0x04}, // 0: English
    "VaultKey Stack",           // 1: Manufacturer
    "VaultKey",                 // 2: Product
    "VK-0001",                  // 3: Serial
    "VaultKey CDC",             // 4: CDC Interface
    "VaultKey Protocol",        // 5: HID Generic
    "VaultKey Keyboard",        // 6: HID Keyboard
    "VaultKey FIDO",            // 7: HID FIDO
};

static uint16_t _desc_str[32];

uint16_t const *tud_descriptor_string_cb(uint8_t index, uint16_t langid) {
  (void)langid;
  uint8_t chr_count;

  if (index == 0) {
    memcpy(&_desc_str[1], string_desc_arr[0], 2);
    chr_count = 1;
  } else {
    if (index >= sizeof(string_desc_arr) / sizeof(string_desc_arr[0]))
      return NULL;
    const char *str = string_desc_arr[index];
    chr_count = (uint8_t)strlen(str);
    if (chr_count > 31)
      chr_count = 31;
    for (uint8_t i = 0; i < chr_count; i++)
      _desc_str[1 + i] = str[i];
  }

  _desc_str[0] = (uint16_t)((TUSB_DESC_STRING << 8) | (2 * chr_count + 2));
  return (uint16_t const *)_desc_str;
}

//--------------------------------------------------------------------+
// Microsoft OS 2.0 Descriptors
//--------------------------------------------------------------------+

#define MS_OS_20_DESC_LEN 0x50

// BOS Descriptor is required for MS OS 2.0 support
#define BOS_TOTAL_LEN (TUD_BOS_DESC_LEN + TUD_BOS_MICROSOFT_OS_DESC_LEN)

#define MS_OS_20_PLATFORM_CAPABILITY_ID                                        \
  0xD8DD60DF, 0x4589, 0x4CC7, 0x9C, 0xD2, 0x65, 0x9D, 0x9E, 0x64, 0x8A, 0x9F

uint8_t const desc_bos[] = {
    // BOS Header
    TUD_BOS_DESCRIPTOR(BOS_TOTAL_LEN, 1),

    // Microsoft OS 2.0 Platform Capability Descriptor
    TUD_BOS_MS_OS_20_DESCRIPTOR(MS_OS_20_DESC_LEN, 1) // 0x01 is the vendor code
};

uint8_t const *tud_descriptor_bos_cb(void) { return desc_bos; }

uint8_t const desc_ms_os_20[] = {
    // Set Header: length, type, windows version, total length
    U16_TO_U8S_LE(0x000A), U16_TO_U8S_LE(MS_OS_20_SET_HEADER_DESCRIPTOR),
    U32_TO_U8S_LE(0x06030000), U16_TO_U8S_LE(MS_OS_20_DESC_LEN),

    // Configuration Subset Header: length, type, configuration index, reserved,
    // total length of this subset
    U16_TO_U8S_LE(0x0008), U16_TO_U8S_LE(MS_OS_20_SUBSET_HEADER_CONFIGURATION),
    0, 0, U16_TO_U8S_LE(MS_OS_20_DESC_LEN - 0x0A),

    // Function Subset Header: length, type, first interface, reserved, subset
    // length
    U16_TO_U8S_LE(0x0008), U16_TO_U8S_LE(MS_OS_20_SUBSET_HEADER_FUNCTION), 0, 0,
    U16_TO_U8S_LE(MS_OS_20_DESC_LEN - 0x0A - 0x08),

    // Registry Property: FriendlyName = "VaultKey"
    U16_TO_U8S_LE(0x0036), U16_TO_U8S_LE(MS_OS_20_FEATURE_REG_PROPERTY),
    U16_TO_U8S_LE(0x0001),
    U16_TO_U8S_LE(
        0x001A), // PropertyDataType (1=REG_SZ), PropertyNameLength (26)
    'F', 0x00, 'r', 0x00, 'i', 0x00, 'e', 0x00, 'n', 0x00, 'd',
    0x00, // "FriendlyName"
    'l', 0x00, 'y', 0x00, 'N', 0x00, 'a', 0x00, 'm', 0x00, 'e', 0x00, 0x00,
    0x00,
    U16_TO_U8S_LE(0x0012), // PropertyDataLength (18) = 16 chars + 2 null
    'V', 0x00, 'a', 0x00, 'u', 0x00, 'l', 0x00, 't', 0x00, 'K', 0x00, 'e', 0x00,
    'y', 0x00, 0x00, 0x00};

TU_VERIFY_STATIC(sizeof(desc_ms_os_20) == MS_OS_20_DESC_LEN, "Incorrect Size");

uint8_t const *tud_descriptor_ms_os_20_cb(void) { return desc_ms_os_20; }
