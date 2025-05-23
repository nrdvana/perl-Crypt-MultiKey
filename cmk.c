#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"
#include "ppport.h"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <openssl/kdf.h>
#include <string.h>
#include <stdlib.h>

#ifdef HAVE_STDBOOL
  #include <stdbool.h>
#elif !defined(bool)
  #define bool int
  #define true 1
  #define false 0
#endif

#include "cmk.h"
#include "SecretBuffer.h"

void cmk_key_x25519_create(cmk_key_x25519 *key, const char *pw, size_t pw_len, int pbkdf2_iter) {
   const char *err = NULL;
   int outlen = 0;
   EVP_PKEY_CTX *pctx = NULL;
   EVP_PKEY *pkey = NULL;
   EVP_CIPHER_CTX *ctx = NULL;
   unsigned char aes_key[CMK_AES_KEYLEN];

   if (!key || !pw)
      croak("Null argument to cmk_key_x25519_create");

   memset(key, 0, sizeof(*key));

   /* Derive AES key from password */
   if (pbkdf2_iter > 0) {
      if (RAND_bytes(key->kdf_salt, sizeof(key->kdf_salt)) != 1)
         err = "Salt generation failed", goto cleanup;

      if (PKCS5_PBKDF2_HMAC(pw, pw_len, key->kdf_salt, sizeof(key->kdf_salt),
                            pbkdf2_iter, EVP_sha256(),
                            sizeof(aes_key), aes_key) != 1)
         err = "PBKDF2 failed", goto cleanup;
   } else {
      if (pw_len != sizeof(aes_key))
         croak("Password must be exactly %zu bytes if not using PBKDF2", sizeof(aes_key));
      memcpy(aes_key, pw, sizeof(aes_key));
      memset(key->kdf_salt, 0, sizeof(key->kdf_salt));
   }

   /* Generate X25519 keypair */
   pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
   if (!pctx || EVP_PKEY_keygen_init(pctx) <= 0 || EVP_PKEY_keygen(pctx, &pkey) <= 0)
      err = "X25519 key generation failed", goto cleanup;

   size_t len = sizeof(key->privkey);
   if (EVP_PKEY_get_raw_private_key(pkey, key->privkey, &len) != 1 || len != sizeof(key->privkey))
      err = "Extracting private key failed", goto cleanup;

   len = sizeof(key->pubkey);
   if (EVP_PKEY_get_raw_public_key(pkey, key->pubkey, &len) != 1 || len != sizeof(key->pubkey))
      err = "Extracting public key failed", goto cleanup;

   /* Encrypt private key with AES-256-ECB (no padding) */
   ctx = EVP_CIPHER_CTX_new();
   if (!ctx || EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, aes_key, NULL) != 1)
      err = "EncryptInit failed", goto cleanup;

   if (EVP_CIPHER_CTX_set_padding(ctx, 0) != 1)
      err = "Disabling AES padding failed", goto cleanup;

   if (EVP_EncryptUpdate(ctx, key->privkey_encrypted, &outlen,
                         key->privkey, sizeof(key->privkey)) != 1 || outlen != sizeof(key->privkey_encrypted))
      err = "EncryptUpdate failed", goto cleanup;

   if (EVP_EncryptFinal_ex(ctx, key->privkey_encrypted + outlen, &outlen) != 1)
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

void cmk_key_x25519_init(cmk_key_x25519 *key,
                         const cmk_x25519_pubkey pubkey,
                         const cmk_x25519_privkey privkey_enc,
                         const cmk_kdf_salt kdf_salt,
                         int kdf_iters
) {
   if (!key || !pubkey || !privkey_enc || !kdf_salt)
      croak("Null argument to cmk_key_x25519_init");

   memcpy(key->pubkey, pubkey, sizeof(key->pubkey));
   memcpy(key->privkey_encrypted, privkey_enc, sizeof(key->privkey_encrypted));
   memcpy(key->kdf_salt, kdf_salt, sizeof(key->kdf_salt));
   key->pbkdf2_iterations = kdf_iters;
   key->unlocked = false;

   /* privkey is not initialized yet, must call cmk_key_unlock later */
   memset(key->privkey, 0, sizeof(key->privkey));
}

void cmk_key_unlock(cmk_key *key, const char *pw, size_t pw_len) {
   const char *err = NULL;
   int outlen = 0;
   unsigned char aes_key[CMK_AES_KEYLEN];
   EVP_CIPHER_CTX *ctx = NULL;
   EVP_PKEY *pkey = NULL;
   unsigned char derived_pub[CMK_PUBKEY_LEN];
   size_t len = sizeof(derived_pub);

   if (!key || !pw)
      croak("Null argument to cmk_key_unlock");

   if (key->unlocked)
      return;  /* Already unlocked */

   /* Derive AES key */
   if (key->pbkdf2_iterations > 0) {
      if (PKCS5_PBKDF2_HMAC(pw, pw_len,
                            key->kdf_salt, sizeof(key->kdf_salt),
                            key->pbkdf2_iterations, EVP_sha256(),
                            sizeof(aes_key), aes_key) != 1)
         err = "PBKDF2 failed", goto cleanup;
   } else {
      if (pw_len != sizeof(aes_key))
         croak("Password must be exactly %zu bytes when PBKDF2 is not used", sizeof(aes_key));
      memcpy(aes_key, pw, sizeof(aes_key));
   }

   ctx = EVP_CIPHER_CTX_new();
   if (!ctx || EVP_DecryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, aes_key, NULL) != 1)
      err = "DecryptInit failed", goto cleanup;

   if (EVP_CIPHER_CTX_set_padding(ctx, 0) != 1)
      err = "Disable padding failed", goto cleanup;

   if (EVP_DecryptUpdate(ctx, key->privkey, &outlen,
                         key->privkey_encrypted, sizeof(key->privkey_encrypted)) != 1 ||
       outlen != sizeof(key->privkey))
      err = "DecryptUpdate failed", goto cleanup;

   if (EVP_DecryptFinal_ex(ctx, key->privkey + outlen, &outlen) != 1)
      err = "DecryptFinal failed", goto cleanup;

   /* Validate that decrypted private key matches the stored public key */
   pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, key->privkey, sizeof(key->privkey));
   if (!pkey ||
       EVP_PKEY_get_raw_public_key(pkey, derived_pub, &len) != 1 ||
       len != sizeof(key->pubkey))
      err = "Public key re-derivation failed", goto cleanup;

   if (memcmp(derived_pub, key->pubkey, sizeof(key->pubkey)) != 0)
      err = "Private key decryption failed: public key mismatch", goto cleanup;

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

void cmk_key_lock(cmk_key *key) {
   if (!key)
      return;

   OPENSSL_cleanse(key->privkey, sizeof(key->privkey));
   key->unlocked = false;
}

void cmk_key_destroy(cmk_key *key) {
   if (!key)
      return;

   /* Future-proofing: if we ever dynamically allocate fields, clean them here */
   OPENSSL_cleanse(key, sizeof(*key));
}

void cmk_secret_create(cmk_secret *secret) {
   if (!secret)
      croak("Null argument to cmk_secret_create");

   memset(secret, 0, sizeof(*secret));

   if (RAND_bytes(secret->aes_key, sizeof(secret->aes_key)) != 1)
      croak("Failed to generate AES key");

   if (RAND_bytes(secret->nonce, sizeof(secret->nonce)) != 1)
      croak("Failed to generate nonce");

   secret->unlocked = true;
   secret->gcm_tag_initialized = false;
}

void cmk_secret_init(cmk_secret *secret,
                     const cmk_aes_key aes_key,
                     const cmk_aes_nonce nonce,
                     const cmk_gcm_tag gcm_tag
) {
   if (!secret || !nonce || !gcm_tag)
      croak("Null argument to cmk_secret_init");

   memset(secret, 0, sizeof(*secret));

   if (aes_key) {
      memcpy(secret->aes_key, aes_key, sizeof(secret->aes_key));
      secret->unlocked = true;
   } else {
      memset(secret->aes_key, 0, sizeof(secret->aes_key));
      secret->unlocked = false;
   }

   memcpy(secret->nonce, nonce, sizeof(secret->nonce));
   memcpy(secret->gcm_tag, gcm_tag, sizeof(secret->gcm_tag));
   secret->gcm_tag_initialized = true;
}

void cmk_secret_encrypt_buffer(cmk_secret *secret,
                                const unsigned char *in, size_t len,
                                unsigned char *ou
) {
   const char *err = NULL;
   int outlen = 0, finallen = 0;
   EVP_CIPHER_CTX *ctx = NULL;

   if (!secret || !in || !out)
      croak("Null argument to cmk_secret_encrypt_buffer");

   if (!secret->unlocked)
      croak("Secret must be unlocked before encryption");

   ctx = EVP_CIPHER_CTX_new();
   if (!ctx)
      err = "Failed to create AES context", goto cleanup;

   if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
      err = "EncryptInit_ex failed", goto cleanup;

   if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                           sizeof(secret->nonce), NULL) != 1)
      err = "Set IV length failed", goto cleanup;

   if (EVP_EncryptInit_ex(ctx, NULL, NULL,
                          secret->aes_key, secret->nonce) != 1)
      err = "EncryptInit with key/IV failed", goto cleanup;

   if (EVP_EncryptUpdate(ctx, out, &outlen, in, len) != 1 || (size_t)outlen != len)
      err = "EncryptUpdate failed", goto cleanup;

   if (EVP_EncryptFinal_ex(ctx, out + outlen, &finallen) != 1)
      err = "EncryptFinal failed", goto cleanup;

   if (finallen != 0)
      err = "Unexpected final block output from AES-GCM", goto cleanup;

   if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG,
                           sizeof(secret->gcm_tag), secret->gcm_tag) != 1)
      err = "Failed to get GCM tag", goto cleanup;

   secret->gcm_tag_initialized = true;

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

void cmk_secret_decrypt_buffer(cmk_secret *secret,
                                const unsigned char *in, size_t len,
                                unsigned char *out
) {
   const char *err = NULL;
   int outlen = 0, finallen = 0;
   EVP_CIPHER_CTX *ctx = NULL;

   if (!secret || !in || !out)
      croak("Null argument to cmk_secret_decrypt_buffer");

   if (!secret->unlocked)
      croak("Secret must be unlocked before decryption");

   if (!secret->gcm_tag_initialized)
      croak("GCM tag is not initialized in secret");

   ctx = EVP_CIPHER_CTX_new();
   if (!ctx)
      err = "Failed to create AES context", goto cleanup;

   if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
      err = "DecryptInit_ex failed", goto cleanup;

   if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                           sizeof(secret->nonce), NULL) != 1)
      err = "Set IV length failed", goto cleanup;

   if (EVP_DecryptInit_ex(ctx, NULL, NULL,
                          secret->aes_key, secret->nonce) != 1)
      err = "DecryptInit with key/IV failed", goto cleanup;

   if (EVP_DecryptUpdate(ctx, out, &outlen, in, len) != 1 || (size_t)outlen != len)
      err = "DecryptUpdate failed", goto cleanup;

   if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,
                           sizeof(secret->gcm_tag), (void *)secret->gcm_tag) != 1)
      err = "Set GCM tag failed", goto cleanup;

   if (EVP_DecryptFinal_ex(ctx, out + outlen, &finallen) != 1)
      err = "DecryptFinal failed (authentication failure?)", goto cleanup;

   if (finallen != 0)
      err = "Unexpected final block output from AES-GCM";

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

void cmk_locked_aes_key_create(cmk_locked_aes_key *lock,
                                const cmk_secret *secret,
                                const cmk_key_x25519 *key
) {
   const char *err = NULL;
   EVP_PKEY_CTX *ctx = NULL;
   EVP_PKEY *ephemeral = NULL, *peer = NULL;
   unsigned char ephemeral_priv[CMK_PRIVKEY_LEN];
   unsigned char shared_secret[EVP_MAX_KEY_LENGTH];
   size_t shared_len = sizeof(shared_secret);
   unsigned char aes_wrap_key[CMK_AES_KEYLEN];
   EVP_CIPHER_CTX *aes_ctx = NULL;
   int outlen = 0;

   if (!lock || !secret || !key)
      croak("Null argument to cmk_locked_aes_key_create");

   if (!key->unlocked)
      croak("Key must be unlocked before wrapping");

   if (!secret->unlocked)
      croak("Secret must be unlocked before wrapping");

   memset(lock, 0, sizeof(*lock));

   /* Step 1: Generate ephemeral keypair */
   {
      EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
      if (!pctx || EVP_PKEY_keygen_init(pctx) <= 0 || EVP_PKEY_keygen(pctx, &ephemeral) <= 0)
         err = "Ephemeral key generation failed";
      if (pctx) EVP_PKEY_CTX_free(pctx);
      if (err) goto cleanup;
   }

   size_t len_pub = sizeof(lock->pubkey);
   if (EVP_PKEY_get_raw_public_key(ephemeral, lock->pubkey, &len_pub) != 1 || len_pub != sizeof(lock->pubkey))
      err = "Extracting ephemeral public key failed", goto cleanup;

   size_t len_priv = sizeof(ephemeral_priv);
   if (EVP_PKEY_get_raw_private_key(ephemeral, ephemeral_priv, &len_priv) != 1 || len_priv != sizeof(ephemeral_priv))
      err = "Extracting ephemeral private key failed", goto cleanup;

   /* Step 2: Derive shared secret from ephemeral private + recipient pubkey */
   peer = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, key->pubkey, sizeof(key->pubkey));
   if (!peer)
      err = "Creating peer public key failed", goto cleanup;

   ctx = EVP_PKEY_CTX_new(ephemeral, NULL);
   if (!ctx || EVP_PKEY_derive_init(ctx) <= 0 || EVP_PKEY_derive_set_peer(ctx, peer) <= 0)
      err = "Derive init failed", goto cleanup;

   if (EVP_PKEY_derive(ctx, shared_secret, &shared_len) != 1)
      err = "Deriving shared secret failed", goto cleanup;

   /* Step 3: Derive AES wrapping key via HKDF */
   if (RAND_bytes(lock->kdf_salt, sizeof(lock->kdf_salt)) != 1)
      err = "Salt generation failed", goto cleanup;

   {
      EVP_PKEY_CTX *kdf = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
      if (!kdf ||
          EVP_PKEY_derive_init(kdf) <= 0 ||
          EVP_PKEY_CTX_set_hkdf_md(kdf, EVP_sha256()) <= 0 ||
          EVP_PKEY_CTX_set1_hkdf_salt(kdf, lock->kdf_salt, sizeof(lock->kdf_salt)) <= 0 ||
          EVP_PKEY_CTX_set1_hkdf_key(kdf, shared_secret, shared_len) <= 0 ||
          EVP_PKEY_CTX_add1_hkdf_info(kdf, "cmk-wrap", strlen("cmk-wrap")) <= 0 ||
          EVP_PKEY_derive(kdf, aes_wrap_key, &(size_t){ sizeof(aes_wrap_key) }) != 1)
         err = "HKDF failed";
      if (kdf) EVP_PKEY_CTX_free(kdf);
      if (err) goto cleanup
   }

   /* Step 4: Encrypt the AES key from secret using AES-GCM */
   if (RAND_bytes(lock->nonce, sizeof(lock->nonce)) != 1)
      err = "Failed to generate GCM nonce", goto cleanup;

   aes_ctx = EVP_CIPHER_CTX_new();
   if (!aes_ctx ||
       EVP_EncryptInit_ex(aes_ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
       EVP_CIPHER_CTX_ctrl(aes_ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(lock->nonce), NULL) != 1 ||
       EVP_EncryptInit_ex(aes_ctx, NULL, NULL, aes_wrap_key, lock->nonce) != 1 ||
       EVP_EncryptUpdate(aes_ctx, lock->aes_key_encrypted, &outlen,
                         secret->aes_key, sizeof(secret->aes_key)) != 1 ||
       outlen != sizeof(lock->aes_key_encrypted) ||
       EVP_EncryptFinal_ex(aes_ctx, NULL, &outlen) != 1 ||
       EVP_CIPHER_CTX_ctrl(aes_ctx, EVP_CTRL_GCM_GET_TAG, sizeof(lock->gcm_tag), lock->gcm_tag) != 1)
      err = "AES-GCM encryption of AES key failed";

cleanup:
   OPENSSL_cleanse(ephemeral_priv, sizeof(ephemeral_priv));
   OPENSSL_cleanse(shared_secret, sizeof(shared_secret));
   OPENSSL_cleanse(aes_wrap_key, sizeof(aes_wrap_key));
   if (ctx) EVP_PKEY_CTX_free(ctx);
   if (peer) EVP_PKEY_free(peer);
   if (ephemeral) EVP_PKEY_free(ephemeral);
   if (aes_ctx) EVP_CIPHER_CTX_free(aes_ctx);

   if (err) {
      memset(lock, 0, sizeof(*lock));
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

void cmk_secret_unlock(cmk_secret *secret,
                       const cmk_locked_aes_key *lock,
                       const cmk_key_x25519 *key
) {
   const char *err = NULL;
   EVP_PKEY *self = NULL, *peer = NULL;
   EVP_PKEY_CTX *kex_ctx = NULL;
   unsigned char shared_secret[EVP_MAX_KEY_LENGTH];
   size_t shared_len = sizeof(shared_secret);
   unsigned char aes_wrap_key[CMK_AES_KEYLEN];
   EVP_CIPHER_CTX *aes_ctx = NULL;
   int outlen = 0;

   if (!secret || !lock || !key)
      croak("Null argument to cmk_secret_unlock");

   if (!key->unlocked)
      croak("Key must be unlocked to derive AES key");

   if (!lock->gcm_tag || !lock->nonce)
      croak("Locked AES key missing nonce or tag");

   memset(secret, 0, sizeof(*secret));

   /* Step 1: Derive shared secret (self privkey + peer pubkey) */
   self = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, key->privkey, sizeof(key->privkey));
   if (!self)
      err = "Failed to create local private key", goto cleanup;

   peer = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, lock->pubkey, sizeof(lock->pubkey));
   if (!peer)
      err = "Failed to load peer ephemeral public key", goto cleanup;

   kex_ctx = EVP_PKEY_CTX_new(self, NULL);
   if (!kex_ctx || EVP_PKEY_derive_init(kex_ctx) <= 0 || EVP_PKEY_derive_set_peer(kex_ctx, peer) <= 0)
      err = "Key agreement setup failed", goto cleanup;

   if (EVP_PKEY_derive(kex_ctx, shared_secret, &shared_len) != 1)
      err = "Failed to derive shared secret", goto cleanup;

   /* Step 2: Derive AES key from shared secret */
   {
      EVP_PKEY_CTX *kdf = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
      if (!kdf ||
          EVP_PKEY_derive_init(kdf) <= 0 ||
          EVP_PKEY_CTX_set_hkdf_md(kdf, EVP_sha256()) <= 0 ||
          EVP_PKEY_CTX_set1_hkdf_salt(kdf, lock->kdf_salt, sizeof(lock->kdf_salt)) <= 0 ||
          EVP_PKEY_CTX_set1_hkdf_key(kdf, shared_secret, shared_len) <= 0 ||
          EVP_PKEY_CTX_add1_hkdf_info(kdf, "cmk-wrap", strlen("cmk-wrap")) <= 0 ||
          EVP_PKEY_derive(kdf, aes_wrap_key, &(size_t){ sizeof(aes_wrap_key) }) != 1)
         err = "HKDF failed";
      if (kdf) EVP_PKEY_CTX_free(kdf);
      if (err) goto cleanup;
   }

   /* Step 3: AES-GCM decrypt the AES key */
   aes_ctx = EVP_CIPHER_CTX_new();
   if (!aes_ctx ||
       EVP_DecryptInit_ex(aes_ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
       EVP_CIPHER_CTX_ctrl(aes_ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(lock->nonce), NULL) != 1 ||
       EVP_DecryptInit_ex(aes_ctx, NULL, NULL, aes_wrap_key, lock->nonce) != 1 ||
       EVP_DecryptUpdate(aes_ctx, secret->aes_key, &outlen,
                         lock->aes_key_encrypted, sizeof(lock->aes_key_encrypted)) != 1 ||
       outlen != sizeof(secret->aes_key) ||
       EVP_CIPHER_CTX_ctrl(aes_ctx, EVP_CTRL_GCM_SET_TAG, sizeof(lock->gcm_tag), (void *)lock->gcm_tag) != 1 ||
       EVP_DecryptFinal_ex(aes_ctx, NULL, &outlen) != 1)
      err = "Failed to decrypt AES key", goto cleanup;

   memcpy(secret->nonce, lock->nonce, sizeof(secret->nonce));
   memcpy(secret->gcm_tag, lock->gcm_tag, sizeof(secret->gcm_tag));
   secret->unlocked = true;
   secret->gcm_tag_initialized = true;

cleanup:
   OPENSSL_cleanse(shared_secret, sizeof(shared_secret));
   OPENSSL_cleanse(aes_wrap_key, sizeof(aes_wrap_key));
   if (aes_ctx) EVP_CIPHER_CTX_free(aes_ctx);
   if (kex_ctx) EVP_PKEY_CTX_free(kex_ctx);
   if (peer) EVP_PKEY_free(peer);
   if (self) EVP_PKEY_free(self);

   if (err) {
      OPENSSL_cleanse(secret->aes_key, sizeof(secret->aes_key));
      secret->unlocked = false;
      secret->gcm_tag_initialized = false;

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
