#ifndef CMK_H
#define CMK_H

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
 * half of this key can either be the AES key itself (if pbkdf2_iterations == 0)
 * or needs run through pbkdf2 to generate the AES key.
 * If pbkdf2_iterations are 0, then the salt is not used.
 *
 * If 'unlocked' is false, the privkey buffer has not been initialized, and you
 * need to call cmk_key_unlock.  Before freeing the key, be sure to call
 * cmk_key_lock to wipe the 'privkey' field.  The key is initially unlocked
 * after a call to cmk_key_x25519_create.
 */
typedef struct {
   cmk_x25519_pubkey  pubkey;
   cmk_x25519_privkey privkey;
   cmk_x25519_privkey privkey_encrypted;
   cmk_kdf_salt       kdf_salt;
   int                pbkdf2_iterations;
   bool               unlocked;
} cmk_key_x25519;

/* Only one key type for now, later this might be a type-selected union. */
typedef cmk_key_x25519 cmk_key;

/* Generate an X25519 key pair and encrypt the private key with AES-256.
 * Process the password with pbkdf2 if the iterations count is not zero.
 * If pbkdf2_iter == 0, pw must be the correct length for AES.
 */
extern void cmk_key_x25519_create(cmk_key_x25519 *key, const char *pw, size_t pw_len, int pbkdf2_iter);

/* Initialize x25519 key with previous values */
extern void cmk_key_x25519_init(cmk_key_x25519 *key, const cmk_x25519_pubkey pubkey,
   const cmk_x25519_privkey privkey_enc, const cmk_kdf_salt kdf_salt, int kdf_iters);

/* Using a password matching the one that created the key (which may be a direct AES key)
 * populate key->privkey and mark the key as unlocked.
 */
extern void cmk_key_unlock(cmk_key *key, const char *pw, size_t pw_len);

/* Wipe any secrets from the key.
 */
extern void cmk_key_lock(cmk_key *key);

/* Wipe any secrets from the key.
 * Also future-proofing in case struct later contains allocated portions.
 */
extern void cmk_key_destroy(cmk_key *key);

/* This struct describes a "locked" AES key, encrypted by a cmk_key_x25519 plus an ephemeral
 * public key passed through a KDF to compute an AES key that encrypts the actual AES key.
 * These fields are "public" (non-secret).  When combined with an unlocked cmk_key_x25519,
 * they can produce the original AES key of a cmk_secret.
 */
typedef struct {
   cmk_x25519_pubkey pubkey;
   cmk_kdf_salt      kdf_salt;
   cmk_aes_key       aes_key_encrypted;
   cmk_aes_nonce     nonce;
   cmk_gcm_tag       gcm_tag;
} cmk_locked_aes_key;

typedef struct {
   cmk_aes_key   aes_key;
   cmk_aes_nonce nonce;
   cmk_gcm_tag   gcm_tag;
   bool unlocked: 1,
        gcm_tag_initialized: 1;
} cmk_secret;

/* Create a new 'unlocked" secret.  Generates a random AES key, and nonce.
 * gcm_tag is not initialized until an encryption occurs.
 */
void cmk_secret_create(cmk_secret *secret);

/* Initialize a secret with previous values.  It will initially be locked if aes_key is NULL.
 * nonce and gcm_tag cannot be null.
 */
void cmk_secret_init(cmk_secret *secret, const cmk_aes_key aes_key, const cmk_aes_nonce nonce, const cmk_gcm_tag gcm_tag);

/* Unlock a secret by decrypting the secret AES key from the given lock and its key
 * (which must also be unlocked).  nonce and gcm_tag fields must already be initialized.
 */
void cmk_secret_unlock(cmk_secret *secret, const cmk_locked_aes_key *lock, const cmk_key_x25519 *key);

/* Initialize a cmk_locked_aes_key struct by creating a new ephemeral public/private keypair,
 * computing an AES key from a shared secret derived via X25519 using the key’s public key and
 * a newly generated ephemeral private key and a KDF, then encrypt the AES key of a cmk_secret
 * and store it in the lock.
 */
void cmk_locked_aes_key_create(cmk_locked_aes_key *lock, const cmk_secret *secret, const cmk_key_x25519 *key);

/* Using an "unlocked" secret (where aes_key is populated) encrypt from the input buffer into
 * the output buffer, and update the gcm_tag of the secret.  This uses AES-GCM so the length of
 * the input will equal the length of the output.  Caller must ensure output is allocated to at
 * least 'len' bytes.  The output buffer *may* be the same pointer as the input buffer, for
 * in-place operation, but otherwise the buffers may not overlap.
 */
void cmk_secret_encrypt_buffer(cmk_secret *secret, const unsigned char *in, size_t len, unsigned char *out);

/* Using an "unlocked" secret (where aes_key is populated) decrypt from the input buffer into
 * the output buffer.  This uses AES-GCM so the length of the input will equal the length of
 * the output.  Caller must ensure output is allocated to at least 'len' bytes.  The output
 * buffer *may* be the same pointer as the input buffer, for in-place operation, but otherwise
 * the buffers may not overlap.
 */
void cmk_secret_decrypt_buffer(cmk_secret *secret, const unsigned char *in, size_t len, unsigned char *out);

/* Currently just wipes secrets, but could free allocated things in the future. */
void cmk_secret_destroy(cmk_secret *secret);

#endif /* define CMK_H */
