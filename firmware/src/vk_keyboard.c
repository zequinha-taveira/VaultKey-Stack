#include "vk_keyboard.h"
#include "pico/stdlib.h"
#include "tusb.h"
#include <string.h>


// Simple ASCII to HID keycode mapping (US Layout)
static const uint8_t ascii_to_hid[] = {
    [' '] = HID_KEY_SPACE,
    ['!'] = HID_KEY_1,          // Needs Shift
    ['"'] = HID_KEY_APOSTROPHE, // Needs Shift
    ['#'] = HID_KEY_3,          // Needs Shift
    ['$'] = HID_KEY_4,          // Needs Shift
    ['%'] = HID_KEY_5,          // Needs Shift
    ['&'] = HID_KEY_7,          // Needs Shift
    ['\''] = HID_KEY_APOSTROPHE,
    ['('] = HID_KEY_9,     // Needs Shift
    [')'] = HID_KEY_0,     // Needs Shift
    ['*'] = HID_KEY_8,     // Needs Shift
    ['+'] = HID_KEY_EQUAL, // Needs Shift
    [','] = HID_KEY_COMMA,       ['-'] = HID_KEY_MINUS, ['.'] = HID_KEY_PERIOD,
    ['/'] = HID_KEY_SLASH,       ['0'] = HID_KEY_0,     ['1'] = HID_KEY_1,
    ['2'] = HID_KEY_2,           ['3'] = HID_KEY_3,     ['4'] = HID_KEY_4,
    ['5'] = HID_KEY_5,           ['6'] = HID_KEY_6,     ['7'] = HID_KEY_7,
    ['8'] = HID_KEY_8,           ['9'] = HID_KEY_9,
    [':'] = HID_KEY_SEMICOLON, // Needs Shift
    [';'] = HID_KEY_SEMICOLON,
    ['<'] = HID_KEY_COMMA, // Needs Shift
    ['='] = HID_KEY_EQUAL,
    ['>'] = HID_KEY_PERIOD, // Needs Shift
    ['?'] = HID_KEY_SLASH,  // Needs Shift
    ['@'] = HID_KEY_2,      // Needs Shift
    ['A'] = HID_KEY_A,           ['B'] = HID_KEY_B,     ['C'] = HID_KEY_C,
    ['D'] = HID_KEY_D,           ['E'] = HID_KEY_E,     ['F'] = HID_KEY_F,
    ['G'] = HID_KEY_G,           ['H'] = HID_KEY_H,     ['I'] = HID_KEY_I,
    ['J'] = HID_KEY_J,           ['K'] = HID_KEY_K,     ['L'] = HID_KEY_L,
    ['M'] = HID_KEY_M,           ['N'] = HID_KEY_N,     ['O'] = HID_KEY_O,
    ['P'] = HID_KEY_P,           ['Q'] = HID_KEY_Q,     ['R'] = HID_KEY_R,
    ['S'] = HID_KEY_S,           ['T'] = HID_KEY_T,     ['U'] = HID_KEY_U,
    ['V'] = HID_KEY_V,           ['W'] = HID_KEY_W,     ['X'] = HID_KEY_X,
    ['Y'] = HID_KEY_Y,           ['Z'] = HID_KEY_Z,     ['a'] = HID_KEY_A,
    ['b'] = HID_KEY_B,           ['c'] = HID_KEY_C,     ['d'] = HID_KEY_D,
    ['e'] = HID_KEY_E,           ['f'] = HID_KEY_F,     ['g'] = HID_KEY_G,
    ['h'] = HID_KEY_H,           ['i'] = HID_KEY_I,     ['j'] = HID_KEY_J,
    ['k'] = HID_KEY_K,           ['l'] = HID_KEY_L,     ['m'] = HID_KEY_M,
    ['n'] = HID_KEY_N,           ['o'] = HID_KEY_O,     ['p'] = HID_KEY_P,
    ['q'] = HID_KEY_Q,           ['r'] = HID_KEY_R,     ['s'] = HID_KEY_S,
    ['t'] = HID_KEY_T,           ['u'] = HID_KEY_U,     ['v'] = HID_KEY_V,
    ['w'] = HID_KEY_W,           ['x'] = HID_KEY_X,     ['y'] = HID_KEY_Y,
    ['z'] = HID_KEY_Z,
};

static bool needs_shift(char c) {
  if (c >= 'A' && c <= 'Z')
    return true;
  if (strchr("!@#$%^&*()_+{}|:\"<>?", c))
    return true;
  return false;
}

void vk_keyboard_type(const char *text) {
  // Note: This is an implementation of "ITF_NUM_HID_KEYBOARD" (Interface 1 for
  // HID stack) In our usb_descriptors.c, Keyboard is the second HID interface
  // (index 1)
  const uint8_t itf = 1;

  for (size_t i = 0; text[i] != '\0'; i++) {
    char c = text[i];
    uint8_t keycode = ascii_to_hid[(uint8_t)c];
    uint8_t modifier = needs_shift(c) ? KEYBOARD_MODIFIER_LEFTSHIFT : 0;

    // Press key
    tud_hid_n_keyboard_report(itf, 0, modifier,
                              (uint8_t[]){keycode, 0, 0, 0, 0, 0});
    board_delay(10);

    // Release key
    tud_hid_n_report_complete_cb(itf, (uint8_t[]){0},
                                 1); // Mock completion for local loop
    tud_hid_n_keyboard_report(itf, 0, 0, NULL);
    board_delay(10);
  }
}
