#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <openssl/kdf.h>
#include <string.h>
#include <stdbool.h>

#define PUBKEY_LEN 32
#define PRIVKEY_LEN 32
#define NONCE_LEN 12
#define TAG_LEN 16
#define AES_KEYLEN 32
#define SALT_LEN 16

/* The keys used by this module are a public/private pair, with the private key
 * encrypted by a password using AES-256.  The "password" that unlocks the private
 * half of this key can either be the AES key itself (if pbkdf2_iterations == 0)
 * or needs run through pbkdf2 to generate the AES key.
 * If pbkdf2_iterations are 0, then the salt is not used.
 * If 'unlocked' is false, the privkey buffer has not been initialized, and you
 * need to call cmk_unlock_key.  Before freeing the key, be sure to call
 * cmk_lock_key to wipe the 'privkey' field.  The key is initially unlocked
 * after a call to cmk_create_key_x25519.
 */
typedef struct {
   unsigned char pubkey[PUBKEY_LEN];
   unsigned char privkey[PRIVKEY_LEN];
   unsigned char encrypted_privkey[PRIVKEY_LEN];
   int pbkdf2_iterations;
   bool unlocked;
   unsigned char salt[SALT_LEN];
} cmk_key_x25519;

/* The cmk_encrypt function fills out this struct with a random nonce and public half
 * of an ephemeral key, then allocates a buffer for the ciphertext it generates.
 * The caller must free this buffer.
 */
typedef struct {
   unsigned char ephemeral_pubkey[PUBKEY_LEN];
   unsigned char nonce[NONCE_LEN];
   unsigned char tag[TAG_LEN];
   unsigned char hkdf_salt[16];
   unsigned char *ciphertext;
   size_t ciphertext_len;

   unsigned char aes_key[32];  /* derived from ephemeral_priv + pubkey via HKDF */
   bool unlocked;              /* true if aes_key is valid */
} cmk_secret;

/* Initialize OpenSSL (not needed for LibreSSL) */
int cmk_init() {
#ifdef HAVE_OPENSSL
   OpenSSL_add_all_algorithms();
   ERR_load_crypto_strings();
#endif
   return 1;
}

/* Generate an X25519 key pair and encrypt the private key with AES-256.
 * Process the password with pbkdf2 if the iterations count is not zero.
 * If iterations == 0, pw must be the correct length for AES.
 */
void cmk_create_key_x25519(cmk_key_x25519 *key, char *pw, size_t pw_len, int pbkdf2_iter);

/* Using a password matching the one that created the key (which may be a direct AES key)
 * populate key->privkey and mark the key as unlocked.
 */
void cmk_unlock_key(cmk_key_x25519 *key, const char *pw, size_t pw_len);

/* Wipe any secrets from the key
 */
void cmk_lock_key(cmk_key_x25519 *key);

/* Generate an ephemeral keypair, and then encrypt the input data with AES-GCM using the secret
 * from the combined private ephemeral key and provided public key, storing all details needed
 * for decryption into the cmk_secret.
 */
void cmk_encrypt(cmk_key_x25519 *key, char *input, size_t in_len, cmk_secret *out);

/* Compute the AES key from the supplied private key (must be unlocked) and public key of the
 * ciphertext, then decrypt the ciphertext into the supplied buffer. The caller must allocate
 * at least as many bytes as the length of the ciphertext.
 */
int cmk_decrypt(cmk_key_x25519 *key, cmk_secret *in, char *out, size_t out_len);


void cmk_create_key_x25519(cmk_key_x25519 *key, char *pw, size_t pw_len, int pbkdf2_iter) {
   int err = 0;
   EVP_PKEY_CTX *pctx = NULL;
   EVP_PKEY *pkey = NULL;
   unsigned char aes_key[sizeof(key->privkey)];
   EVP_CIPHER_CTX *ctx = NULL;
   int outlen;

   if (!key || !pw) croak("Null key or password");

   if (pbkdf2_iter > 0) {
      if (RAND_bytes(key->salt, sizeof(key->salt)) != 1)
         err = "Failed to generate salt", goto cleanup;
      if (PKCS5_PBKDF2_HMAC(pw, pw_len, key->salt, sizeof(key->salt),
                            pbkdf2_iter, EVP_sha256(), sizeof(aes_key), aes_key) != 1)
         err = "PBKDF2 failed", goto cleanup;
   } else {
      if (pw_len != sizeof(aes_key))
         croak("Password must be %zu bytes when pbkdf2_iter is 0", sizeof(aes_key));
      memcpy(aes_key, pw, sizeof(aes_key));
      memset(key->salt, 0, sizeof(key->salt));
   }

   pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
   if (!pctx || EVP_PKEY_keygen_init(pctx) <= 0 || EVP_PKEY_keygen(pctx, &pkey) <= 0)
      err = "Key generation failed", goto cleanup;

   size_t len = sizeof(key->privkey);
   if (EVP_PKEY_get_raw_private_key(pkey, key->privkey, &len) != 1 || len != sizeof(key->privkey))
      err = "Failed to extract private key", goto cleanup;

   len = sizeof(key->pubkey);
   if (EVP_PKEY_get_raw_public_key(pkey, key->pubkey, &len) != 1 || len != sizeof(key->pubkey))
      err = "Failed to extract public key", goto cleanup;

   ctx = EVP_CIPHER_CTX_new();
   if (!ctx || EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, aes_key, NULL) != 1)
      err = "EncryptInit failed", goto cleanup;

   if (EVP_CIPHER_CTX_set_padding(ctx, 0) != 1)
      err = "Disable padding failed", goto cleanup;

   if (EVP_EncryptUpdate(ctx, key->encrypted_privkey, &outlen, key->privkey, sizeof(key->privkey)) != 1 || outlen != sizeof(key->encrypted_privkey))
      err = "EncryptUpdate failed", goto cleanup;

   if (EVP_EncryptFinal_ex(ctx, key->encrypted_privkey + outlen, &outlen) != 1)
      err = "EncryptFinal failed", goto cleanup;

   key->pbkdf2_iterations = pbkdf2_iter;
   key->unlocked = true;

cleanup:
   OPENSSL_cleanse(aes_key, sizeof(aes_key));
   if (ctx) EVP_CIPHER_CTX_free(ctx);
   if (pkey) EVP_PKEY_free(pkey);
   if (pctx) EVP_PKEY_CTX_free(pctx);

   if (err) {
      unsigned long ssl_err = ERR_get_error();
      char ssl_err_str[256] = {0};
      if (ssl_err) {
         ERR_error_string_n(ssl_err, ssl_err_str, sizeof(ssl_err_str));
         croak("%s: %s", err, ssl_err_str);
      } else {
         croak("%s", err);
      }
   }
}

void cmk_unlock_key(cmk_key_x25519 *key, const char *pw, size_t pw_len) {
   int err = 0, outlen = 0;
   unsigned char aes_key[sizeof(key->privkey)];
   unsigned char test_pub[sizeof(key->pubkey)];
   size_t len = sizeof(test_pub);
   EVP_PKEY *pkey = NULL;
   EVP_CIPHER_CTX *ctx = NULL;

   if (!key || !pw) croak("Null key or password");

   if (key->pbkdf2_iterations > 0) {
      if (PKCS5_PBKDF2_HMAC(pw, pw_len, key->salt, sizeof(key->salt),
                            key->pbkdf2_iterations, EVP_sha256(), sizeof(aes_key), aes_key) != 1)
         err = "PBKDF2 failed", goto cleanup;
   } else {
      if (pw_len != sizeof(aes_key))
         croak("Password must be %zu bytes when pbkdf2_iter is 0", sizeof(aes_key));
      memcpy(aes_key, pw, sizeof(aes_key));
   }

   ctx = EVP_CIPHER_CTX_new();
   if (!ctx || EVP_DecryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, aes_key, NULL) != 1)
      err = "DecryptInit failed", goto cleanup;

   if (EVP_CIPHER_CTX_set_padding(ctx, 0) != 1)
      err = "Disable padding failed", goto cleanup;

   if (EVP_DecryptUpdate(ctx, key->privkey, &outlen, key->encrypted_privkey, sizeof(key->encrypted_privkey)) != 1 || outlen != sizeof(key->privkey))
      err = "DecryptUpdate failed", goto cleanup;

   if (EVP_DecryptFinal_ex(ctx, key->privkey + outlen, &outlen) != 1)
      err = "DecryptFinal failed", goto cleanup;

   pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, key->privkey, sizeof(key->privkey));
   if (!pkey || EVP_PKEY_get_raw_public_key(pkey, test_pub, &len) != 1 || len != sizeof(key->pubkey))
      err = "Public key validation failed", goto cleanup;

   if (memcmp(test_pub, key->pubkey, sizeof(key->pubkey)) != 0)
      err = "Decrypted private key does not match public key", goto cleanup;

   key->unlocked = true;

cleanup:
   OPENSSL_cleanse(aes_key, sizeof(aes_key));
   if (ctx) EVP_CIPHER_CTX_free(ctx);
   if (pkey) EVP_PKEY_free(pkey);

   if (err) {
      OPENSSL_cleanse(key->privkey, sizeof(key->privkey));
      key->unlocked = false;

      unsigned long ssl_err = ERR_get_error();
      char ssl_err_str[256] = {0};
      if (ssl_err) {
         ERR_error_string_n(ssl_err, ssl_err_str, sizeof(ssl_err_str));
         croak("%s: %s", err, ssl_err_str);
      } else {
         croak("%s", err);
      }
   }
}

void cmk_lock_key(cmk_key_x25519 *key) {
   if (!key) return;
   OPENSSL_cleanse(key->privkey, sizeof(key->privkey));
   key->unlocked = false;
}

void cmk_secret_init(cmk_secret *secret, cmk_key_x25519 *key) {
   int err = 0;
   EVP_PKEY_CTX *ctx_kex = NULL;
   EVP_PKEY *ephemeral = NULL, *peer = NULL;
   unsigned char ephemeral_priv[PRIVKEY_LEN];
   unsigned char shared_secret[EVP_MAX_KEY_LENGTH];
   size_t shared_len = sizeof(shared_secret);

   if (!secret || !key)
      croak("Null secret or key");

   if (!key->unlocked)
      croak("Key must be unlocked before initializing secret");

   memset(secret, 0, sizeof(*secret));

   /* Generate ephemeral keypair */
   {
      EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
      if (!pctx || EVP_PKEY_keygen_init(pctx) <= 0 || EVP_PKEY_keygen(pctx, &ephemeral) <= 0)
         err = "Ephemeral key generation failed", goto cleanup;
      EVP_PKEY_CTX_free(pctx);
   }

   size_t len_pub = sizeof(secret->ephemeral_pubkey);
   if (EVP_PKEY_get_raw_public_key(ephemeral, secret->ephemeral_pubkey, &len_pub) != 1 || len_pub != sizeof(secret->ephemeral_pubkey))
      err = "Extracting ephemeral pubkey failed", goto cleanup;

   size_t len_priv = sizeof(ephemeral_priv);
   if (EVP_PKEY_get_raw_private_key(ephemeral, ephemeral_priv, &len_priv) != 1 || len_priv != sizeof(ephemeral_priv))
      err = "Extracting ephemeral private key failed", goto cleanup;

   /* Compute shared secret */
   peer = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, key->pubkey, sizeof(key->pubkey));
   if (!peer)
      err = "Failed to load peer pubkey", goto cleanup;

   ctx_kex = EVP_PKEY_CTX_new(ephemeral, NULL);
   if (!ctx_kex || EVP_PKEY_derive_init(ctx_kex) <= 0 || EVP_PKEY_derive_set_peer(ctx_kex, peer) <= 0)
      err = "Derive init failed", goto cleanup;

   if (EVP_PKEY_derive(ctx_kex, shared_secret, &shared_len) != 1)
      err = "Shared secret derivation failed", goto cleanup;

   if (RAND_bytes(secret->nonce, sizeof(secret->nonce)) != 1)
      err = "Nonce generation failed", goto cleanup;

   if (RAND_bytes(secret->hkdf_salt, sizeof(secret->hkdf_salt)) != 1)
      err = "HKDF salt generation failed", goto cleanup;

   {
      EVP_PKEY_CTX *kdf = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
      if (!kdf ||
          EVP_PKEY_derive_init(kdf) <= 0 ||
          EVP_PKEY_CTX_set_hkdf_md(kdf, EVP_sha256()) <= 0 ||
          EVP_PKEY_CTX_set1_hkdf_salt(kdf, secret->hkdf_salt, sizeof(secret->hkdf_salt)) <= 0 ||
          EVP_PKEY_CTX_set1_hkdf_key(kdf, shared_secret, shared_len) <= 0 ||
          EVP_PKEY_CTX_add1_hkdf_info(kdf, "cmk-encrypt", strlen("cmk-encrypt")) <= 0 ||
          EVP_PKEY_derive(kdf, secret->aes_key, &(size_t){ sizeof(secret->aes_key) }) != 1)
         err = "HKDF failed", goto cleanup;
      EVP_PKEY_CTX_free(kdf);
   }

   secret->unlocked = true;

cleanup:
   OPENSSL_cleanse(ephemeral_priv, sizeof(ephemeral_priv));
   OPENSSL_cleanse(shared_secret, sizeof(shared_secret));
   if (ctx_kex) EVP_PKEY_CTX_free(ctx_kex);
   if (ephemeral) EVP_PKEY_free(ephemeral);
   if (peer) EVP_PKEY_free(peer);

   if (err) {
      OPENSSL_cleanse(secret->aes_key, sizeof(secret->aes_key));
      secret->unlocked = false;
      unsigned long ssl_err = ERR_get_error();
      char ssl_err_str[256] = {0};
      if (ssl_err) {
         ERR_error_string_n(ssl_err, ssl_err_str, sizeof(ssl_err_str));
         croak("%s: %s", err, ssl_err_str);
      } else {
         croak("%s", err);
      }
   }
}

void cmk_unlock_secret(cmk_secret *secret, cmk_key_x25519 *key) {
   int err = 0;
   EVP_PKEY *self = NULL, *ephemeral = NULL;
   EVP_PKEY_CTX *ctx = NULL;
   unsigned char shared_secret[EVP_MAX_KEY_LENGTH];
   size_t shared_len = sizeof(shared_secret);

   if (!secret || !key)
      croak("Null secret or key");

   if (!key->unlocked)
      croak("Key must be unlocked to derive shared secret");

   ephemeral = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL,
                                           secret->ephemeral_pubkey, sizeof(secret->ephemeral_pubkey));
   if (!ephemeral)
      err = "Failed to reconstruct ephemeral public key", goto cleanup;

   self = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL,
                                       key->privkey, sizeof(key->privkey));
   if (!self)
      err = "Failed to load private key", goto cleanup;

   ctx = EVP_PKEY_CTX_new(self, NULL);
   if (!ctx || EVP_PKEY_derive_init(ctx) <= 0 || EVP_PKEY_derive_set_peer(ctx, ephemeral) <= 0)
      err = "Key derivation init failed", goto cleanup;

   if (EVP_PKEY_derive(ctx, shared_secret, &shared_len) != 1)
      err = "Key derivation failed", goto cleanup;

   {
      EVP_PKEY_CTX *kdf = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
      if (!kdf ||
          EVP_PKEY_derive_init(kdf) <= 0 ||
          EVP_PKEY_CTX_set_hkdf_md(kdf, EVP_sha256()) <= 0 ||
          EVP_PKEY_CTX_set1_hkdf_salt(kdf, secret->hkdf_salt, sizeof(secret->hkdf_salt)) <= 0 ||
          EVP_PKEY_CTX_set1_hkdf_key(kdf, shared_secret, shared_len) <= 0 ||
          EVP_PKEY_CTX_add1_hkdf_info(kdf, "cmk-encrypt", strlen("cmk-encrypt")) <= 0 ||
          EVP_PKEY_derive(kdf, secret->aes_key, &(size_t){ sizeof(secret->aes_key) }) != 1)
         err = "HKDF failed", goto cleanup;
      EVP_PKEY_CTX_free(kdf);
   }

   secret->unlocked = true;

cleanup:
   OPENSSL_cleanse(shared_secret, sizeof(shared_secret));
   if (ctx) EVP_PKEY_CTX_free(ctx);
   if (ephemeral) EVP_PKEY_free(ephemeral);
   if (self) EVP_PKEY_free(self);

   if (err) {
      OPENSSL_cleanse(secret->aes_key, sizeof(secret->aes_key));
      secret->unlocked = false;

      unsigned long ssl_err = ERR_get_error();
      char ssl_err_str[256] = {0};
      if (ssl_err) {
         ERR_error_string_n(ssl_err, ssl_err_str, sizeof(ssl_err_str));
         croak("%s: %s", err, ssl_err_str);
      } else {
         croak("%s", err);
      }
   }
}

void cmk_lock_secret(cmk_secret *secret) {
   if (!secret) return;
   OPENSSL_cleanse(secret->aes_key, sizeof(secret->aes_key));
   secret->unlocked = false;
}

void cmk_secret_encrypt(cmk_secret *secret,
                        const char *input, size_t in_len,
                        unsigned char *out, size_t *out_len) {
   int err = 0, len = 0, final_len = 0;
   EVP_CIPHER_CTX *ctx = NULL;

   if (!secret || !input || !out || !out_len)
      croak("Null argument to encrypt");

   if (!secret->unlocked)
      croak("Secret must be unlocked before encryption");

   ctx = EVP_CIPHER_CTX_new();
   if (!ctx)
      err = "Failed to create AES context", goto cleanup;

   if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
      err = "EncryptInit_ex failed", goto cleanup;

   if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(secret->nonce), NULL) != 1)
      err = "Set IV length failed", goto cleanup;

   if (EVP_EncryptInit_ex(ctx, NULL, NULL, secret->aes_key, secret->nonce) != 1)
      err = "EncryptInit with key/IV failed", goto cleanup;

   if (EVP_EncryptUpdate(ctx, out, &len, (unsigned char *)input, in_len) != 1)
      err = "EncryptUpdate failed", goto cleanup;
   *out_len = len;

   if (EVP_EncryptFinal_ex(ctx, out + len, &final_len) != 1)
      err = "EncryptFinal failed", goto cleanup;
   *out_len += final_len;

   if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, sizeof(secret->tag), secret->tag) != 1)
      err = "Get GCM tag failed", goto cleanup;

cleanup:
   if (ctx) EVP_CIPHER_CTX_free(ctx);
   if (err) {
      unsigned long ssl_err = ERR_get_error();
      char ssl_err_str[256] = {0};
      if (ssl_err) {
         ERR_error_string_n(ssl_err, ssl_err_str, sizeof(ssl_err_str));
         croak("%s: %s", err, ssl_err_str);
      } else {
         croak("%s", err);
      }
   }
}

int cmk_decrypt(cmk_secret *secret,
                const unsigned char *ciphertext, size_t ciphertext_len,
                char *out, size_t out_len) {
   int err = 0, len = 0, final_len = 0;
   EVP_CIPHER_CTX *ctx = NULL;

   if (!secret || !ciphertext || !out)
      croak("Null argument to decrypt");

   if (!secret->unlocked)
      croak("Secret must be unlocked before decryption");

   if (ciphertext_len > out_len)
      croak("Output buffer is too small for ciphertext length");

   ctx = EVP_CIPHER_CTX_new();
   if (!ctx)
      err = "Failed to create AES context", goto cleanup;

   if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
      err = "DecryptInit_ex failed", goto cleanup;

   if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(secret->nonce), NULL) != 1)
      err = "Set IV length failed", goto cleanup;

   if (EVP_DecryptInit_ex(ctx, NULL, NULL, secret->aes_key, secret->nonce) != 1)
      err = "DecryptInit with key/IV failed", goto cleanup;

   if (EVP_DecryptUpdate(ctx, (unsigned char *)out, &len, ciphertext, ciphertext_len) != 1)
      err = "DecryptUpdate failed", goto cleanup;

   if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, sizeof(secret->tag), (void *)secret->tag) != 1)
      err = "Set GCM tag failed", goto cleanup;

   if (EVP_DecryptFinal_ex(ctx, (unsigned char *)out + len, &final_len) != 1)
      err = "DecryptFinal (authentication failed)", goto cleanup;

   return len + final_len;

cleanup:
   if (ctx) EVP_CIPHER_CTX_free(ctx);
   if (err) {
      unsigned long ssl_err = ERR_get_error();
      char ssl_err_str[256] = {0};
      if (ssl_err) {
         ERR_error_string_n(ssl_err, ssl_err_str, sizeof(ssl_err_str));
         croak("%s: %s", err, ssl_err_str);
      } else {
         croak("%s", err);
      }
   }

   return -1; // unreachable if croak is fatal, but included for completeness
}
