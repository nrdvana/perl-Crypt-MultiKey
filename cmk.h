#ifndef CMK_H
#define CMK_H

#include <SecretBuffer.h>

#define CMK_PUBKEY_LEN 32
#define CMK_PRIVKEY_LEN 32
#define CMK_AES_NONCE_LEN 12
#define CMK_GCM_TAG_LEN 16
#define CMK_AES_KEYLEN 32
#define CMK_SALT_LEN 16

typedef unsigned char cmk_x25519_pubkey[CMK_PUBKEY_LEN];
typedef unsigned char cmk_x25519_privkey[CMK_PRIVKEY_LEN];
typedef unsigned char cmk_kdf_salt[CMK_SALT_LEN];
typedef unsigned char cmk_aes_key[CMK_AES_KEYLEN];
typedef unsigned char cmk_aes_nonce[CMK_AES_NONCE_LEN];
typedef unsigned char cmk_gcm_tag[CMK_GCM_TAG_LEN];

/* The keys used by this module are a public/private pair, with the private key
 * encrypted by a password using AES-256.  The "password" that unlocks the private
 * half of this key can either be the raw AES key (if pbkdf2_iterations == 0)
 * or needs run through pbkdf2 to generate the AES key.
 * If pbkdf2_iterations are 0, then the salt is not used.
 *
 * If 'unlocked' is false, the privkey buffer has not been initialized, and you
 * need to call cmk_key_unlock.  Before freeing the key, be sure to call
 * cmk_key_lock to wipe the 'privkey' field.  The key is initially unlocked
 * after a call to cmk_key_x25519_create.
 */
typedef struct {
   int32_t            format;
   cmk_x25519_pubkey  pubkey;
   cmk_x25519_privkey privkey;
   cmk_x25519_privkey privkey_encrypted;
   cmk_kdf_salt       kdf_salt;
   int                pbkdf2_iterations;
   bool               unlocked;
} cmk_key_x25519;

typedef union {
   int32_t            format;
   cmk_key_x25519     x25519;
} cmk_key;

#define CMK_KEYFORMAT_X25519 1

#define CMK_MAGIC_AUTOCREATE 1
#define CMK_MAGIC_OR_DIE     2
#define CMK_MAGIC_UNDEF_OK   4
extern cmk_key* cmk_key_from_magic(SV *ref, int flags);

/* Generate a public/private key pair and encrypt the private key with AES-256.
 * Process the password with pbkdf2 if the iterations count is not zero.
 * If pbkdf2_iter == 0, pw is the AES key itself and must be the correct length.
 */
extern void cmk_key_create(cmk_key *key, int type, secret_buffer *pw, int pbkdf2_iter);

/* Initialize key struct from previous values */
extern void cmk_key_import(cmk_key *key, HV *in);

/* Encode public fields to JSON-compatible structure in a hashref */
extern void cmk_key_export(cmk_key *key, HV *out);

/* Wipe any secrets from the key.
 * Also future-proofing in case struct later contains allocated portions.
 */
extern void cmk_key_destroy(cmk_key *key);

/* Using a password matching the one that created the key (which may be a direct AES key)
 * populate key->privkey and mark the key as unlocked.
 */
extern void cmk_key_unlock(cmk_key *key, secret_buffer *pw);

/* Wipe any secrets from the key, returning it to a locked state.
 */
extern void cmk_key_lock(cmk_key *key);

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
} cmk_lockbox;

/* This struct holds an encrypted AES key of a lockbox, encrypted by a cmk_key plus an ephemeral
 * public key passed through a KDF to compute an AES key that encrypts the lockbox AES key.
 * These fields are "public" (non-secret).
 */
typedef struct {
   cmk_x25519_pubkey pubkey;
   cmk_kdf_salt      kdf_salt;
   cmk_aes_key       aes_key_encrypted;
   cmk_aes_nonce     nonce;
   cmk_gcm_tag       gcm_tag;
} cmk_key_slot;

extern cmk_lockbox* cmk_lockbox_from_magic(SV *ref, int flags);

/* Create a new "unlocked" lockbox.  Generates a random AES key, and nonce.
 * gcm_tag is not initialized until an encryption occurs.
 */
extern void cmk_lockbox_create(cmk_lockbox *lockbox);

/* Import the value of a cmk_lockbox into an uninitialized struct, reading from a hashref */
extern void cmk_lockbox_import(cmk_lockbox *lockbox, HV *in);

/* Export the public values of a cmk_lockbox into a hashref */
extern void cmk_lockbox_export(cmk_lockbox *lockbox, HV *out);

/* Currently just wipes secrets, but could free allocated things in the future. */
extern void cmk_lockbox_destroy(cmk_lockbox *lockbox);

/* Unlock an encryption by decrypting the secret AES key from the given lock and its key
 * (which must also be unlocked).  nonce and gcm_tag fields must already be initialized.
 */
extern void cmk_lockbox_unlock(cmk_lockbox *lockbox, const cmk_key_slot *slot, const cmk_key *key);

/* This deletes the aes_key from the struct. */
extern void cmk_lockbox_lock(cmk_lockbox *lockbox);

/* Using an "unlocked" lockbox (where aes_key is populated) encrypt from the input buffer into
 * the output buffer, and update the gcm_tag of the secret.  This uses AES-GCM so the length of
 * the input will equal the length of the output.  Caller must ensure output is allocated to at
 * least 'len' bytes.  The output buffer *may* be the same pointer as the input buffer, for
 * in-place operation, but otherwise the buffers may not overlap.
 */
extern void cmk_lockbox_encrypt_buffer(cmk_lockbox *lockbox, const secret_buffer *in, secret_buffer *out);

/* Using an "unlocked" lockbox (where aes_key is populated) decrypt from the input buffer into
 * the output buffer.  This uses AES-GCM so the length of the input will equal the length of
 * the output.  Caller must ensure output is allocated to at least 'len' bytes.  The output
 * buffer *may* be the same pointer as the input buffer, for in-place operation, but otherwise
 * the buffers may not overlap.
 */
extern void cmk_lockbox_decrypt_buffer(cmk_lockbox *lockbox, const secret_buffer *in, secret_buffer *out);

extern cmk_key_slot* cmk_key_slot_from_magic(SV *ref, int flags);

/* Create a cmk_key_slot from an unlocked lockbox and a public key */
extern void cmk_key_slot_create(cmk_key_slot *slot, cmk_lockbox *lockbox, cmk_key *key);

/* Import the value of a cmk_key_slot into an uninitialized struct, reading from a hashref */
extern void cmk_key_slot_import(cmk_key_slot *slot, HV *in);

/* Export the values of a cmk_key_slot into a hashref.  (all fields are public) */
extern void cmk_key_slot_export(cmk_key_slot *slot, HV *out);

/* Free resources og a key slot.
 * Currently this is a no-op since the struct doesn't contain any secrets.
 */
extern void cmk_key_slot_destroy(cmk_key_slot *slot);

#endif /* define CMK_H */
