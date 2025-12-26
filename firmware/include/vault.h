#ifndef VAULT_H
#define VAULT_H

#include <stdbool.h>
#include <stdint.h>

#define MAX_ENTRIES 100
#define ENTRY_NAME_MAX 32
#define ENTRY_SECRET_MAX 64

typedef struct {
  char name[ENTRY_NAME_MAX];
  uint8_t encrypted_secret[ENTRY_SECRET_MAX];
  uint8_t nonce[12];
  uint8_t tag[16];
  bool occupied;
  uint8_t _padding[3]; // Align to 128 bytes
} vault_entry_t;

typedef struct {
  uint32_t fail_count;
  bool is_locked;
  uint32_t magic;
  uint8_t _padding[120]; // Align to 128 bytes
} security_state_t;

#define SECURITY_STATE_MAGIC 0x564B5353 // "VKSS"

// Security API
bool vault_is_locked(void);
uint32_t vault_get_fail_count(void);
void vault_report_auth_result(bool success);

// Initialize vault (mount flash, verify integrity)
bool vault_init(void);

// List entry names
int vault_list(char names[][ENTRY_NAME_MAX], int max_count);

// Set entry
bool vault_set(const char *name, const uint8_t *secret, uint16_t len);

// Get entry (returns encrypted data)
bool vault_get(const char *name, vault_entry_t *out_entry);

// Delete entry
bool vault_delete(const char *name);

// Format vault (danger!)
void vault_format(void);

#endif // VAULT_H
