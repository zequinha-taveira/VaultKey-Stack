#ifndef VK_KEYBOARD_H
#define VK_KEYBOARD_H

#include <stdint.h>

/**
 * @brief Type a string of text via USB HID Keyboard emulation.
 * @param text NULL-terminated string to type.
 */
void vk_keyboard_type(const char *text);

#endif // VK_KEYBOARD_H
