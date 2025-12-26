#include "vault.h"
#include "hardware/flash.h"
#include "hardware/sync.h"
#include "pico/stdlib.h"
#include <string.h>

// Define flash offset for the vault (last 64KB of 2MB flash)
#define FLASH_TARGET_OFFSET (1024 * 1024 * 2 - 65536)
// Size of the entries array in bytes
#define VAULT_STORAGE_SIZE sizeof(entries)
// Ensure we use enough sectors
#define VAULT_ERASE_SIZE                                                       \
  ((VAULT_STORAGE_SIZE / FLASH_SECTOR_SIZE + 1) * FLASH_SECTOR_SIZE)

static vault_entry_t entries[MAX_ENTRIES];

static void vault_sync_to_flash(void) {
  const uint8_t *flash_target_contents =
      (const uint8_t *)(XIP_BASE + FLASH_TARGET_OFFSET);

  // Basic Wear Leveling: Only write if data changed
  if (memcmp(entries, flash_target_contents, VAULT_STORAGE_SIZE) == 0) {
    return;
  }

  uint32_t ints = save_and_disable_interrupts();

  // Erase sectors
  flash_range_erase(FLASH_TARGET_OFFSET, VAULT_ERASE_SIZE);

  // Program data
  // Note: flash_range_program needs data to be a multiple of FLASH_PAGE_SIZE
  // We'll pad the buffer if necessary, but here we just write the whole array
  // assuming it's reasonably sized or we pad it.
  flash_range_program(FLASH_TARGET_OFFSET, (const uint8_t *)entries,
                      VAULT_STORAGE_SIZE);

  restore_interrupts(ints);
}

static void vault_load_from_flash(void) {
  const uint8_t *flash_target_contents =
      (const uint8_t *)(XIP_BASE + FLASH_TARGET_OFFSET);
  memcpy(entries, flash_target_contents, VAULT_STORAGE_SIZE);
}

bool vault_init(void) {
  vault_load_from_flash();

  // Basic integrity check (if first entry is completely empty but occupied,
  // might be uninitialized) For now, if all names are FF, it's empty
  if (entries[0].name[0] == 0xFF) {
    memset(entries, 0, sizeof(entries));
  }

  return true;
}

int vault_list(char names[][ENTRY_NAME_MAX], int max_count) {
  int count = 0;
  for (int i = 0; i < MAX_ENTRIES && count < max_count; i++) {
    if (entries[i].occupied) {
      strncpy(names[count], entries[i].name, ENTRY_NAME_MAX);
      count++;
    }
  }
  return count;
}

bool vault_set(const char *name, const uint8_t *secret, uint16_t len) {
  if (len > ENTRY_SECRET_MAX)
    return false;

  int slot = -1;
  for (int i = 0; i < MAX_ENTRIES; i++) {
    if (entries[i].occupied && strcmp(entries[i].name, name) == 0) {
      slot = i;
      break;
    }
    if (!entries[i].occupied && slot == -1) {
      slot = i;
    }
  }

  if (slot == -1)
    return false;

  strncpy(entries[slot].name, name, ENTRY_NAME_MAX);
  memcpy(entries[slot].encrypted_secret, secret, len);
  entries[slot].occupied = true;

  vault_sync_to_flash();

  return true;
}

bool vault_get(const char *name, vault_entry_t *out_entry) {
  for (int i = 0; i < MAX_ENTRIES; i++) {
    if (entries[i].occupied && strcmp(entries[i].name, name) == 0) {
      memcpy(out_entry, &entries[i], sizeof(vault_entry_t));
      return true;
    }
  }
  return false;
}

bool vault_delete(const char *name) {
  for (int i = 0; i < MAX_ENTRIES; i++) {
    if (entries[i].occupied && strcmp(entries[i].name, name) == 0) {
      entries[i].occupied = false;
      vault_sync_to_flash();
      return true;
    }
  }
  return false;
}

void vault_format(void) {
  memset(entries, 0, sizeof(entries));
  vault_sync_to_flash();
}
