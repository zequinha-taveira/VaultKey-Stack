#include "vault.h"
#include "hardware/flash.h"
#include "hardware/sync.h"
#include "pico/stdlib.h"
#include <string.h>

// Define flash offset for the vault (last 64KB of 2MB flash)
#define FLASH_TARGET_OFFSET (1024 * 1024 * 2 - 65536)
typedef struct {
  security_state_t security;
  vault_entry_t entries[MAX_ENTRIES];
} vault_storage_t;

static vault_storage_t vault_data;

#define VAULT_STORAGE_SIZE sizeof(vault_data)
#define VAULT_ERASE_SIZE                                                       \
  ((VAULT_STORAGE_SIZE / FLASH_SECTOR_SIZE + 1) * FLASH_SECTOR_SIZE)

static void vault_sync_to_flash(void) {
  const uint8_t *flash_target_contents =
      (const uint8_t *)(XIP_BASE + FLASH_TARGET_OFFSET);

  if (memcmp(&vault_data, flash_target_contents, VAULT_STORAGE_SIZE) == 0) {
    return;
  }

  uint32_t ints = save_and_disable_interrupts();
  flash_range_erase(FLASH_TARGET_OFFSET, VAULT_ERASE_SIZE);
  flash_range_program(FLASH_TARGET_OFFSET, (const uint8_t *)&vault_data,
                      VAULT_STORAGE_SIZE);
  restore_interrupts(ints);
}

static void vault_load_from_flash(void) {
  const uint8_t *flash_target_contents =
      (const uint8_t *)(XIP_BASE + FLASH_TARGET_OFFSET);
  memcpy(&vault_data, flash_target_contents, VAULT_STORAGE_SIZE);
}

bool vault_init(void) {
  vault_load_from_flash();

  if (vault_data.security.magic != SECURITY_STATE_MAGIC) {
    memset(&vault_data, 0, sizeof(vault_data));
    vault_data.security.magic = SECURITY_STATE_MAGIC;
    vault_sync_to_flash();
  }

  return true;
}

bool vault_is_locked(void) { return vault_data.security.is_locked; }

uint32_t vault_get_fail_count(void) { return vault_data.security.fail_count; }

void vault_report_auth_result(bool success) {
  if (success) {
    vault_data.security.fail_count = 0;
    vault_data.security.is_locked = false;
  } else {
    vault_data.security.fail_count++;
    if (vault_data.security.fail_count >= 5) {
      vault_data.security.is_locked = true;
    }
  }
  vault_sync_to_flash();
}

int vault_list(char names[][ENTRY_NAME_MAX], int max_count) {
  int count = 0;
  for (int i = 0; i < MAX_ENTRIES && count < max_count; i++) {
    if (vault_data.entries[i].occupied) {
      strncpy(names[count], vault_data.entries[i].name, ENTRY_NAME_MAX);
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
    if (vault_data.entries[i].occupied &&
        strcmp(vault_data.entries[i].name, name) == 0) {
      slot = i;
      break;
    }
    if (!vault_data.entries[i].occupied && slot == -1) {
      slot = i;
    }
  }

  if (slot == -1)
    return false;

  strncpy(vault_data.entries[slot].name, name, ENTRY_NAME_MAX);

  // Real Encryption
  uint8_t master_key[32]; // Derived earlier or stored in session
  memset(master_key, 0x42,
         32); // Mock for now until Phase 11 auth is fully wired

  uint8_t iv[12];
  // Simple deterministic IV for demo, should be random in production
  memset(iv, slot, 12);
  memcpy(vault_data.entries[slot].nonce, iv, 12);

  if (!vk_crypto_encrypt(master_key, secret, len, iv,
                         vault_data.entries[slot].tag,
                         vault_data.entries[slot].encrypted_secret)) {
    return false;
  }

  vault_data.entries[slot].occupied = true;
  vault_sync_to_flash();
  return true;
}

bool vault_get(const char *name, vault_entry_t *out_entry) {
  for (int i = 0; i < MAX_ENTRIES; i++) {
    if (vault_data.entries[i].occupied &&
        strcmp(vault_data.entries[i].name, name) == 0) {
      memcpy(out_entry, &vault_data.entries[i], sizeof(vault_entry_t));
      return true;
    }
  }
  return false;
}

bool vault_delete(const char *name) {
  for (int i = 0; i < MAX_ENTRIES; i++) {
    if (vault_data.entries[i].occupied &&
        strcmp(vault_data.entries[i].name, name) == 0) {
      vault_data.entries[i].occupied = false;
      vault_sync_to_flash();
      return true;
    }
  }
  return false;
}

void vault_format(void) {
  memset(&vault_data, 0, sizeof(vault_data));
  vault_data.security.magic = SECURITY_STATE_MAGIC;
  vault_sync_to_flash();
}
