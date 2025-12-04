#ifndef CMK_H
#define CMK_H

#include <SecretBuffer.h>

extern EVP_PKEY ** cmk_EVP_PKEY_p_from_magic(SV *sv, bool autocreate);
extern EVP_PKEY *  cmk_key_get_pubkey(SV *objref);
extern EVP_PKEY *  cmk_key_get_privkey(SV *objref);
extern EVP_PKEY *  cmk_key_keygen(SV *objref, const char *type_and_params);
extern EVP_PKEY *  cmk_key_keygen_params(SV *objref, const char *type, const char **params, int param_count);
extern void cmk_key_slot_create(HV *slot, EVP_PKEY *public_key, const U8 *cipher_key, size_t cipher_key_len);
extern void cmk_key_slot_unlock(HV *slot, EVP_PKEY *private_key, secret_buffer *cipher_key_out);

#if 0
/* Create the 'private_encrypted' field of the Key object from the 'private' field
 * using AES with an aes_key derived from the supplied password.  The field 'pbkdf2_iter'
 * is consulted to determine whether to use pbkdf2, and pbk_salt field is generated if so.
 * The 'private' field is unmodified.
 * Dies on failure.
 */
extern void cmk_key_encrypt_private(cmk_key *key, const char *pass, size_t pass_len);

/* Create the 'private' field of the Key object from the 'private_encrypted' field
 * using AES with an aes_key reconstructed from the supplied password.
 * Dies on failure.
 */
extern void cmk_key_decrypt_private(cmk_key *key, const char *pass, size_t pass_len);

/* This struct represents a simple wrapper around the parameters for an encryption context.
 * When created, it contains a secret AES key which is used to encrypt a secret.  You can then
 * create cmk_key_slot records that hold an encrypted version of that AES key before wiping the
 * AES key.  After that, you need an unlocked cmk_key_slot to restore the original AES key and
 * re-create the encryption context to decrypt the secret.
 */
typedef struct {
   cmk_aes_key   aes_key;
   cmk_aes_nonce nonce;
   cmk_gcm_tag   gcm_tag;
   bool unlocked: 1,
        gcm_tag_initialized: 1;
} cmk_vault;

/* This struct holds an encrypted AES key of a vault, encrypted by a cmk_key plus an ephemeral
 * public key passed through a KDF to compute an AES key that encrypts the vault AES key.
 * These fields are "public" (non-secret).
 */
typedef struct {
   cmk_x25519_pubkey pubkey;
   cmk_kdf_salt      kdf_salt;
   cmk_aes_key       aes_key_encrypted;
   cmk_aes_nonce     nonce;
   cmk_gcm_tag       gcm_tag;
} cmk_key_slot;

extern cmk_vault* cmk_vault_from_magic(SV *ref, int flags);

/* Create a new "unlocked" vault.  Generates a random AES key, and nonce.
 * gcm_tag is not initialized until an encryption occurs.
 */
extern void cmk_vault_create(cmk_vault *vault);

/* Import the value of a cmk_vault into an uninitialized struct, reading from a hashref */
extern void cmk_vault_import(cmk_vault *vault, HV *in);

/* Export the public values of a cmk_vault into a hashref */
extern void cmk_vault_export(cmk_vault *vault, HV *out);

/* Currently just wipes secrets, but could free allocated things in the future. */
extern void cmk_vault_destroy(cmk_vault *vault);

/* Unlock an encryption by decrypting the secret AES key from the given lock and its key
 * (which must also be unlocked).  nonce and gcm_tag fields must already be initialized.
 */
extern void cmk_vault_unlock(cmk_vault *vault, const cmk_key_slot *slot, const cmk_key *key);

/* This deletes the aes_key from the struct. */
extern void cmk_vault_lock(cmk_vault *vault);

/* Using an "unlocked" vault (where aes_key is populated) encrypt from the input buffer into
 * the output buffer, and update the gcm_tag of the secret.  This uses AES-GCM so the length of
 * the input will equal the length of the output.  Caller must ensure output is allocated to at
 * least 'len' bytes.  The output buffer *may* be the same pointer as the input buffer, for
 * in-place operation, but otherwise the buffers may not overlap.
 */
extern void cmk_vault_encrypt_buffer(cmk_vault *vault, const secret_buffer *in, secret_buffer *out);

/* Using an "unlocked" vault (where aes_key is populated) decrypt from the input buffer into
 * the output buffer.  This uses AES-GCM so the length of the input will equal the length of
 * the output.  Caller must ensure output is allocated to at least 'len' bytes.  The output
 * buffer *may* be the same pointer as the input buffer, for in-place operation, but otherwise
 * the buffers may not overlap.
 */
extern void cmk_vault_decrypt_buffer(cmk_vault *vault, const secret_buffer *in, secret_buffer *out);

extern cmk_key_slot* cmk_key_slot_from_magic(SV *ref, int flags);

/* Create a cmk_key_slot from an unlocked vault and a public key */
extern void cmk_key_slot_create(cmk_key_slot *slot, cmk_vault *vault, cmk_key *key);

/* Import the value of a cmk_key_slot into an uninitialized struct, reading from a hashref */
extern void cmk_key_slot_import(cmk_key_slot *slot, HV *in);

/* Export the values of a cmk_key_slot into a hashref.  (all fields are public) */
extern void cmk_key_slot_export(cmk_key_slot *slot, HV *out);

/* Free resources og a key slot.
 * Currently this is a no-op since the struct doesn't contain any secrets.
 */
extern void cmk_key_slot_destroy(cmk_key_slot *slot);
#endif

#endif /* define CMK_H */
