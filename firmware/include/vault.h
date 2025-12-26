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
  uint16_t secret_len;
  bool occupied;
  uint8_t _padding[1]; // Align to 128 bytes
} vault_entry_t;

#define FIDO_CREDID_MAX 32
#define FIDO_RPID_MAX 64
#define FIDO_USER_MAX 64

typedef struct {
  uint8_t credential_id[FIDO_CREDID_MAX];
  uint8_t private_key[32]; // Ed25519
  uint8_t public_key[32];
  char rp_id[FIDO_RPID_MAX];
  char user_name[FIDO_USER_MAX];
  bool occupied;
  uint8_t _padding[31]; // Align to 256 bytes (64+32+32+64+32+1+31 = 256)
} vk_fido_cred_t;

typedef struct {
  uint32_t fail_count;
  bool is_locked;
  uint32_t magic;
  uint8_t canary[16];        // Encrypted "VERIFY" block
  uint8_t canary_tag[16];    // Auth tag for canary
  uint8_t fido_pin_hash[32]; // SHA-256 of LEFT(SHA-256(PIN), 16)
  bool fido_pin_set;
  uint8_t _padding[55]; // Align to 128 bytes
} security_state_t;

#define SECURITY_STATE_MAGIC 0x564B5353 // "VKSS"

// Session API
void vault_set_session_key(const uint8_t *key);
bool vault_has_session_key(void);
const uint8_t *vault_get_session_key(void);
bool vault_verify_pin(const uint8_t *key);
bool vault_setup_canary(const uint8_t *key);

// Security API
bool vault_is_setup(void);
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

// Get entry (returns decrypted secret)
bool vault_get_decrypted(const char *name, uint8_t *out_secret,
                         uint16_t *out_len);

// Delete entry
bool vault_delete(const char *name);

// Format vault (danger!)
void vault_format(void);

// FIDO2 API
bool vault_fido_add(const vk_fido_cred_t *cred);
bool vault_fido_get_by_id(const uint8_t *cred_id, vk_fido_cred_t *out_cred);
int vault_fido_list_by_rp(const char *rp_id, vk_fido_cred_t *out_creds,
                          int max_count);
int vault_fido_list_all(vk_fido_cred_t *out_creds, int max_count);
bool vault_fido_delete(const uint8_t *cred_id);

// FIDO2 PIN API
bool vault_fido_set_pin(const uint8_t pin_hash[32]);
bool vault_fido_verify_pin(const uint8_t pin_hash[32]);
bool vault_fido_has_pin(void);

#endif // VAULT_H
