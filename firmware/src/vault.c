#include "vault.h"
#include <string.h>

// For initial development, we use an in-memory array
// In Phase 5+, this will use the Pico Flash API
static vault_entry_t entries[MAX_ENTRIES];

bool vault_init(void) {
  memset(entries, 0, sizeof(entries));
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

  // Find existing or empty slot
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

  // TODO: Implement actual flash persistence and encryption logic here

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
      return true;
    }
  }
  return false;
}

void vault_format(void) { memset(entries, 0, sizeof(entries)); }
