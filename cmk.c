#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"
#include "ppport.h"

#include "CryptMultiKey_config.h"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <openssl/kdf.h>
#include <string.h>
#include <stdlib.h>

#ifndef HAVE_BOOL
   #define bool int
   #define true 1
   #define false 0
#endif

#include "cmk.h"

void cmk_key_create(cmk_key *key, int type, secret_buffer *pw, int pbkdf2_iter) {
   const char *err = NULL;
   int outlen = 0;
   EVP_PKEY_CTX *pctx = NULL;
   EVP_PKEY *pkey = NULL;
   EVP_CIPHER_CTX *ctx = NULL;
   unsigned char aes_key[CMK_AES_KEYLEN];

   if (!key || !pw)
      croak("Null argument to cmk_key_create");

   if (type != CMK_KEYFORMAT_X25519)
      croak("Unsupported key type");

   memset(key, 0, sizeof(*key));
   key->x25519.format = type;

   /* Derive AES key from password */
   if (pbkdf2_iter > 0) {
      if (RAND_bytes(key->x25519.kdf_salt, sizeof(key->x25519.kdf_salt)) != 1)
         err = "Salt generation failed", goto cleanup;

      if (PKCS5_PBKDF2_HMAC(pw->data, pw->len,
                            key->x25519.kdf_salt, sizeof(key->x25519.kdf_salt),
                            pbkdf2_iter, EVP_sha256(),
                            sizeof(aes_key), aes_key) != 1)
         err = "PBKDF2 failed", goto cleanup;
   } else {
      if (pw->len != sizeof(aes_key))
         croak("Password must be exactly %zu bytes if not using PBKDF2", sizeof(aes_key));
      memcpy(aes_key, pw->data, sizeof(aes_key));
      memset(key->x25519.kdf_salt, 0, sizeof(key->x25519.kdf_salt));
   }

   /* Generate X25519 keypair */
   pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
   if (!pctx || EVP_PKEY_keygen_init(pctx) <= 0 || EVP_PKEY_keygen(pctx, &pkey) <= 0)
      err = "X25519 key generation failed", goto cleanup;

   size_t len = sizeof(key->x25519.privkey);
   if (EVP_PKEY_get_raw_private_key(pkey, key->x25519.privkey, &len) != 1 || len != sizeof(key->x25519.privkey))
      err = "Extracting private key failed", goto cleanup;

   len = sizeof(key->x25519.pubkey);
   if (EVP_PKEY_get_raw_public_key(pkey, key->x25519.pubkey, &len) != 1 || len != sizeof(key->x25519.pubkey))
      err = "Extracting public key failed", goto cleanup;

   /* Encrypt private key with AES-256-ECB (no padding) */
   ctx = EVP_CIPHER_CTX_new();
   if (!ctx || EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, aes_key, NULL) != 1)
      err = "EncryptInit failed", goto cleanup;

   if (EVP_CIPHER_CTX_set_padding(ctx, 0) != 1)
      err = "Disabling AES padding failed", goto cleanup;

   if (EVP_EncryptUpdate(ctx, key->x25519.privkey_encrypted, &outlen,
                         key->x25519.privkey, sizeof(key->x25519.privkey)) != 1 || outlen != sizeof(key->x25519.privkey_encrypted))
      err = "EncryptUpdate failed", goto cleanup;

   if (EVP_EncryptFinal_ex(ctx, key->x25519.privkey_encrypted + outlen, &outlen) != 1)
      err = "EncryptFinal failed", goto cleanup;

   key->x25519.pbkdf2_iterations = pbkdf2_iter;
   key->x25519.unlocked = true;

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

void cmk_key_import(cmk_key *key, HV *in) {
   SV **sv;

   if (!key || !in)
      croak("Null argument to cmk_key_import");

   memset(key, 0, sizeof(*key));
   key->x25519.format = CMK_KEYFORMAT_X25519;

   sv = hv_fetchs(in, "pubkey", 0);
   if (sv && SvOK(*sv)) {
      STRLEN len;
      const char *data = SvPVbyte(*sv, len);
      if (len != sizeof(key->x25519.pubkey))
         croak("Invalid pubkey length");
      memcpy(key->x25519.pubkey, data, len);
   }

   sv = hv_fetchs(in, "privkey_encrypted", 0);
   if (sv && SvOK(*sv)) {
      STRLEN len;
      const char *data = SvPVbyte(*sv, len);
      if (len != sizeof(key->x25519.privkey_encrypted))
         croak("Invalid encrypted key length");
      memcpy(key->x25519.privkey_encrypted, data, len);
   }

   sv = hv_fetchs(in, "kdf_salt", 0);
   if (sv && SvOK(*sv)) {
      STRLEN len;
      const char *data = SvPVbyte(*sv, len);
      if (len != sizeof(key->x25519.kdf_salt))
         croak("Invalid kdf_salt length");
      memcpy(key->x25519.kdf_salt, data, len);
   }

   sv = hv_fetchs(in, "pbkdf2_iterations", 0);
   key->x25519.pbkdf2_iterations = sv && SvOK(*sv) ? (int)SvIV(*sv) : 0;
   key->x25519.unlocked = false;

   memset(key->x25519.privkey, 0, sizeof(key->x25519.privkey));
}

void cmk_key_unlock(cmk_key *key, secret_buffer *pw) {
   const char *err = NULL;
   int outlen = 0;
   unsigned char aes_key[CMK_AES_KEYLEN];
   EVP_CIPHER_CTX *ctx = NULL;
   EVP_PKEY *pkey = NULL;
   unsigned char derived_pub[CMK_PUBKEY_LEN];
   size_t len = sizeof(derived_pub);

   if (!key || !pw)
      croak("Null argument to cmk_key_unlock");

   if (key->x25519.unlocked)
      return;  /* Already unlocked */

   /* Derive AES key */
   if (key->x25519.pbkdf2_iterations > 0) {
      if (PKCS5_PBKDF2_HMAC(pw->data, pw->len,
                            key->x25519.kdf_salt, sizeof(key->x25519.kdf_salt),
                            key->x25519.pbkdf2_iterations, EVP_sha256(),
                            sizeof(aes_key), aes_key) != 1)
         err = "PBKDF2 failed", goto cleanup;
   } else {
      if (pw->len != sizeof(aes_key))
         croak("Password must be exactly %zu bytes when PBKDF2 is not used", sizeof(aes_key));
      memcpy(aes_key, pw->data, sizeof(aes_key));
   }

   ctx = EVP_CIPHER_CTX_new();
   if (!ctx || EVP_DecryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, aes_key, NULL) != 1)
      err = "DecryptInit failed", goto cleanup;

   if (EVP_CIPHER_CTX_set_padding(ctx, 0) != 1)
      err = "Disable padding failed", goto cleanup;

   if (EVP_DecryptUpdate(ctx, key->x25519.privkey, &outlen,
                         key->x25519.privkey_encrypted, sizeof(key->x25519.privkey_encrypted)) != 1 ||
       outlen != sizeof(key->x25519.privkey))
      err = "DecryptUpdate failed", goto cleanup;

   if (EVP_DecryptFinal_ex(ctx, key->x25519.privkey + outlen, &outlen) != 1)
      err = "DecryptFinal failed", goto cleanup;

   /* Validate that decrypted private key matches the stored public key */
   pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, key->x25519.privkey, sizeof(key->x25519.privkey));
   if (!pkey ||
       EVP_PKEY_get_raw_public_key(pkey, derived_pub, &len) != 1 ||
       len != sizeof(key->x25519.pubkey))
      err = "Public key re-derivation failed", goto cleanup;

   if (memcmp(derived_pub, key->x25519.pubkey, sizeof(key->x25519.pubkey)) != 0)
      err = "Private key decryption failed: public key mismatch", goto cleanup;

   key->x25519.unlocked = true;

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

   OPENSSL_cleanse(key->x25519.privkey, sizeof(key->x25519.privkey));
   key->x25519.unlocked = false;
}

void cmk_key_destroy(cmk_key *key) {
   if (!key)
      return;

   /* Future-proofing: if we ever dynamically allocate fields, clean them here */
   OPENSSL_cleanse(key, sizeof(*key));
}

void cmk_lockbox_create(cmk_lockbox *lockbox) {
   if (!lockbox)
      croak("Null argument to cmk_lockbox_create");

   memset(lockbox, 0, sizeof(*lockbox));

   if (RAND_bytes(lockbox->aes_key, sizeof(lockbox->aes_key)) != 1)
      croak("Failed to generate AES key");

   if (RAND_bytes(lockbox->nonce, sizeof(lockbox->nonce)) != 1)
      croak("Failed to generate nonce");

   lockbox->unlocked = true;
   lockbox->gcm_tag_initialized = false;
}

void cmk_lockbox_import(cmk_lockbox *lockbox, HV *in) {
   SV **sv;

   if (!lockbox || !in)
      croak("Null argument to cmk_lockbox_import");

   memset(lockbox, 0, sizeof(*lockbox));

   sv = hv_fetchs(in, "aes_key", 0);
   if (sv && SvOK(*sv)) {
      STRLEN len;
      const char *data = SvPVbyte(*sv, len);
      if (len == sizeof(lockbox->aes_key)) {
         memcpy(lockbox->aes_key, data, len);
         lockbox->unlocked = true;
      }
   }

   sv = hv_fetchs(in, "nonce", 0);
   if (sv && SvOK(*sv)) {
      STRLEN len;
      const char *data = SvPVbyte(*sv, len);
      if (len == sizeof(lockbox->nonce))
         memcpy(lockbox->nonce, data, len);
   }

   sv = hv_fetchs(in, "gcm_tag", 0);
   if (sv && SvOK(*sv)) {
      STRLEN len;
      const char *data = SvPVbyte(*sv, len);
      if (len == sizeof(lockbox->gcm_tag)) {
         memcpy(lockbox->gcm_tag, data, len);
         lockbox->gcm_tag_initialized = true;
      }
   }
}

void cmk_lockbox_export(cmk_lockbox *lockbox, HV *out) {
   if (!lockbox || !out)
      croak("Null argument to cmk_lockbox_export");

   hv_stores(out, "nonce", newSVpvn((char*)lockbox->nonce, sizeof(lockbox->nonce)));
   hv_stores(out, "gcm_tag", newSVpvn((char*)lockbox->gcm_tag, sizeof(lockbox->gcm_tag)));
   if (lockbox->unlocked)
      hv_stores(out, "aes_key", newSVpvn((char*)lockbox->aes_key, sizeof(lockbox->aes_key)));
}

void cmk_lockbox_lock(cmk_lockbox *lockbox) {
   if (!lockbox)
      return;
   OPENSSL_cleanse(lockbox->aes_key, sizeof(lockbox->aes_key));
   lockbox->unlocked = false;
}

void cmk_lockbox_destroy(cmk_lockbox *lockbox) {
   if (!lockbox)
      return;
   OPENSSL_cleanse(lockbox, sizeof(*lockbox));
}

void cmk_lockbox_encrypt_buffer(cmk_lockbox *lockbox,
                                const secret_buffer *in,
                                secret_buffer *out
) {
   const char *err = NULL;
   int outlen = 0, finallen = 0;
   EVP_CIPHER_CTX *ctx = NULL;

   if (!lockbox || !in || !out)
      croak("Null argument to cmk_lockbox_encrypt_buffer");

   if (!lockbox->unlocked)
      croak("Secret must be unlocked before encryption");

   ctx = EVP_CIPHER_CTX_new();
   if (!ctx)
      err = "Failed to create AES context", goto cleanup;

   if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
      err = "EncryptInit_ex failed", goto cleanup;

   if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                           sizeof(lockbox->nonce), NULL) != 1)
      err = "Set IV length failed", goto cleanup;

   if (EVP_EncryptInit_ex(ctx, NULL, NULL,
                          lockbox->aes_key, lockbox->nonce) != 1)
      err = "EncryptInit with key/IV failed", goto cleanup;

   secret_buffer_alloc_at_least(out, in->len);
   if (EVP_EncryptUpdate(ctx, (unsigned char*)out->data, &outlen,
                         (unsigned char*)in->data, in->len) != 1 ||
       (size_t)outlen != in->len)
      err = "EncryptUpdate failed", goto cleanup;

   if (EVP_EncryptFinal_ex(ctx, (unsigned char*)out->data + outlen, &finallen) != 1)
      err = "EncryptFinal failed", goto cleanup;

   if (finallen != 0)
      err = "Unexpected final block output from AES-GCM", goto cleanup;

   if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG,
                           sizeof(lockbox->gcm_tag), lockbox->gcm_tag) != 1)
      err = "Failed to get GCM tag", goto cleanup;

   lockbox->gcm_tag_initialized = true;
   secret_buffer_set_len(out, in->len);

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

void cmk_lockbox_decrypt_buffer(cmk_lockbox *lockbox,
                                const secret_buffer *in,
                                secret_buffer *out
) {
   const char *err = NULL;
   int outlen = 0, finallen = 0;
   EVP_CIPHER_CTX *ctx = NULL;

   if (!lockbox || !in || !out)
      croak("Null argument to cmk_lockbox_decrypt_buffer");

   if (!lockbox->unlocked)
      croak("Secret must be unlocked before decryption");

   if (!lockbox->gcm_tag_initialized)
      croak("GCM tag is not initialized in secret");

   ctx = EVP_CIPHER_CTX_new();
   if (!ctx)
      err = "Failed to create AES context", goto cleanup;

   if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
      err = "DecryptInit_ex failed", goto cleanup;

   if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                           sizeof(lockbox->nonce), NULL) != 1)
      err = "Set IV length failed", goto cleanup;

   if (EVP_DecryptInit_ex(ctx, NULL, NULL,
                          lockbox->aes_key, lockbox->nonce) != 1)
      err = "DecryptInit with key/IV failed", goto cleanup;

   secret_buffer_alloc_at_least(out, in->len);
   if (EVP_DecryptUpdate(ctx, (unsigned char*)out->data, &outlen,
                         (unsigned char*)in->data, in->len) != 1 ||
       (size_t)outlen != in->len)
      err = "DecryptUpdate failed", goto cleanup;

   if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,
                           sizeof(lockbox->gcm_tag), (void *)lockbox->gcm_tag) != 1)
      err = "Set GCM tag failed", goto cleanup;

   if (EVP_DecryptFinal_ex(ctx, (unsigned char*)out->data + outlen, &finallen) != 1)
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
   } else
      secret_buffer_set_len(out, in->len);
}

void cmk_key_slot_create(cmk_key_slot *slot,
                         cmk_lockbox *lockbox,
                         cmk_key *key
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

   if (!slot || !lockbox || !key)
      croak("Null argument to cmk_key_slot_create");

   if (!key->x25519.unlocked)
      croak("Key must be unlocked before wrapping");

   if (!lockbox->unlocked)
      croak("Secret must be unlocked before wrapping");

   memset(slot, 0, sizeof(*slot));

   /* Step 1: Generate ephemeral keypair */
   {
      EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
      if (!pctx || EVP_PKEY_keygen_init(pctx) <= 0 || EVP_PKEY_keygen(pctx, &ephemeral) <= 0)
         err = "Ephemeral key generation failed";
      if (pctx) EVP_PKEY_CTX_free(pctx);
      if (err) goto cleanup;
   }

   size_t len_pub = sizeof(slot->pubkey);
   if (EVP_PKEY_get_raw_public_key(ephemeral, slot->pubkey, &len_pub) != 1 || len_pub != sizeof(slot->pubkey))
      err = "Extracting ephemeral public key failed", goto cleanup;

   size_t len_priv = sizeof(ephemeral_priv);
   if (EVP_PKEY_get_raw_private_key(ephemeral, ephemeral_priv, &len_priv) != 1 || len_priv != sizeof(ephemeral_priv))
      err = "Extracting ephemeral private key failed", goto cleanup;

   /* Step 2: Derive shared secret from ephemeral private + recipient pubkey */
   peer = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, key->x25519.pubkey, sizeof(key->x25519.pubkey));
   if (!peer)
      err = "Creating peer public key failed", goto cleanup;

   ctx = EVP_PKEY_CTX_new(ephemeral, NULL);
   if (!ctx || EVP_PKEY_derive_init(ctx) <= 0 || EVP_PKEY_derive_set_peer(ctx, peer) <= 0)
      err = "Derive init failed", goto cleanup;

   if (EVP_PKEY_derive(ctx, shared_secret, &shared_len) != 1)
      err = "Deriving shared secret failed", goto cleanup;

   /* Step 3: Derive AES wrapping key via HKDF */
   if (RAND_bytes(slot->kdf_salt, sizeof(slot->kdf_salt)) != 1)
      err = "Salt generation failed", goto cleanup;

   {
      EVP_PKEY_CTX *kdf = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
      if (!kdf ||
          EVP_PKEY_derive_init(kdf) <= 0 ||
          EVP_PKEY_CTX_set_hkdf_md(kdf, EVP_sha256()) <= 0 ||
          EVP_PKEY_CTX_set1_hkdf_salt(kdf, slot->kdf_salt, sizeof(slot->kdf_salt)) <= 0 ||
          EVP_PKEY_CTX_set1_hkdf_key(kdf, shared_secret, shared_len) <= 0 ||
          EVP_PKEY_CTX_add1_hkdf_info(kdf, "cmk-wrap", strlen("cmk-wrap")) <= 0 ||
          EVP_PKEY_derive(kdf, aes_wrap_key, &(size_t){ sizeof(aes_wrap_key) }) != 1)
         err = "HKDF failed";
      if (kdf) EVP_PKEY_CTX_free(kdf);
      if (err) goto cleanup
   }

   /* Step 4: Encrypt the AES key from secret using AES-GCM */
   if (RAND_bytes(slot->nonce, sizeof(slot->nonce)) != 1)
      err = "Failed to generate GCM nonce", goto cleanup;

   aes_ctx = EVP_CIPHER_CTX_new();
   if (!aes_ctx ||
       EVP_EncryptInit_ex(aes_ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
       EVP_CIPHER_CTX_ctrl(aes_ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(slot->nonce), NULL) != 1 ||
       EVP_EncryptInit_ex(aes_ctx, NULL, NULL, aes_wrap_key, slot->nonce) != 1 ||
       EVP_EncryptUpdate(aes_ctx, slot->aes_key_encrypted, &outlen,
                         lockbox->aes_key, sizeof(lockbox->aes_key)) != 1 ||
       outlen != sizeof(slot->aes_key_encrypted) ||
       EVP_EncryptFinal_ex(aes_ctx, NULL, &outlen) != 1 ||
       EVP_CIPHER_CTX_ctrl(aes_ctx, EVP_CTRL_GCM_GET_TAG, sizeof(slot->gcm_tag), slot->gcm_tag) != 1)
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
      memset(slot, 0, sizeof(*slot));
      unsigned long ssl_err = ERR_get_error();
      char ssl_err_str[256] = {0};
      if (ssl_err) {
         ERR_error_string_n(ssl_err, ssl_err_str, sizeof(ssl_err_str));
         croak("%s: %s", err, ssl_err_str);
      } else {
      croak("%s", err);
   }
}

void cmk_key_slot_import(cmk_key_slot *slot, HV *in) {
   SV **sv;

   if (!slot || !in)
      croak("Null argument to cmk_key_slot_import");

   memset(slot, 0, sizeof(*slot));

   sv = hv_fetchs(in, "pubkey", 0);
   if (sv && SvOK(*sv)) {
      STRLEN len; const char *data = SvPVbyte(*sv, len);
      if (len == sizeof(slot->pubkey))
         memcpy(slot->pubkey, data, len);
   }
   sv = hv_fetchs(in, "kdf_salt", 0);
   if (sv && SvOK(*sv)) {
      STRLEN len; const char *data = SvPVbyte(*sv, len);
      if (len == sizeof(slot->kdf_salt))
         memcpy(slot->kdf_salt, data, len);
   }
   sv = hv_fetchs(in, "aes_key_encrypted", 0);
   if (sv && SvOK(*sv)) {
      STRLEN len; const char *data = SvPVbyte(*sv, len);
      if (len == sizeof(slot->aes_key_encrypted))
         memcpy(slot->aes_key_encrypted, data, len);
   }
   sv = hv_fetchs(in, "nonce", 0);
   if (sv && SvOK(*sv)) {
      STRLEN len; const char *data = SvPVbyte(*sv, len);
      if (len == sizeof(slot->nonce))
         memcpy(slot->nonce, data, len);
   }
   sv = hv_fetchs(in, "gcm_tag", 0);
   if (sv && SvOK(*sv)) {
      STRLEN len; const char *data = SvPVbyte(*sv, len);
      if (len == sizeof(slot->gcm_tag))
         memcpy(slot->gcm_tag, data, len);
   }
}

void cmk_key_slot_export(cmk_key_slot *slot, HV *out) {
   if (!slot || !out)
      croak("Null argument to cmk_key_slot_export");

   hv_stores(out, "pubkey", newSVpvn((char*)slot->pubkey, sizeof(slot->pubkey)));
   hv_stores(out, "kdf_salt", newSVpvn((char*)slot->kdf_salt, sizeof(slot->kdf_salt)));
   hv_stores(out, "aes_key_encrypted", newSVpvn((char*)slot->aes_key_encrypted, sizeof(slot->aes_key_encrypted)));
   hv_stores(out, "nonce", newSVpvn((char*)slot->nonce, sizeof(slot->nonce)));
   hv_stores(out, "gcm_tag", newSVpvn((char*)slot->gcm_tag, sizeof(slot->gcm_tag)));
}

void cmk_key_slot_destroy(cmk_key_slot *slot) {
   if (!slot)
      return;
   OPENSSL_cleanse(slot, sizeof(*slot));
}
}

void cmk_lockbox_unlock(cmk_lockbox *lockbox,
                        const cmk_key_slot *slot,
                        const cmk_key *key
) {
   const char *err = NULL;
   EVP_PKEY *self = NULL, *peer = NULL;
   EVP_PKEY_CTX *kex_ctx = NULL;
   unsigned char shared_secret[EVP_MAX_KEY_LENGTH];
   size_t shared_len = sizeof(shared_secret);
   unsigned char aes_wrap_key[CMK_AES_KEYLEN];
   EVP_CIPHER_CTX *aes_ctx = NULL;
   int outlen = 0;

   if (!lockbox || !slot || !key)
      croak("Null argument to cmk_lockbox_unlock");

   if (!key->x25519.unlocked)
      croak("Key must be unlocked to derive AES key");

   if (!slot->gcm_tag || !slot->nonce)
      croak("Locked AES key missing nonce or tag");

   memset(lockbox, 0, sizeof(*lockbox));

   /* Step 1: Derive shared secret (self privkey + peer pubkey) */
   self = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, key->x25519.privkey, sizeof(key->x25519.privkey));
   if (!self)
      err = "Failed to create local private key", goto cleanup;

   peer = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, slot->pubkey, sizeof(slot->pubkey));
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
          EVP_PKEY_CTX_set1_hkdf_salt(kdf, slot->kdf_salt, sizeof(slot->kdf_salt)) <= 0 ||
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
       EVP_CIPHER_CTX_ctrl(aes_ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(slot->nonce), NULL) != 1 ||
       EVP_DecryptInit_ex(aes_ctx, NULL, NULL, aes_wrap_key, slot->nonce) != 1 ||
       EVP_DecryptUpdate(aes_ctx, lockbox->aes_key, &outlen,
                         slot->aes_key_encrypted, sizeof(slot->aes_key_encrypted)) != 1 ||
       outlen != sizeof(lockbox->aes_key) ||
       EVP_CIPHER_CTX_ctrl(aes_ctx, EVP_CTRL_GCM_SET_TAG, sizeof(slot->gcm_tag), (void *)slot->gcm_tag) != 1 ||
       EVP_DecryptFinal_ex(aes_ctx, NULL, &outlen) != 1)
      err = "Failed to decrypt AES key", goto cleanup;

   memcpy(lockbox->nonce, slot->nonce, sizeof(lockbox->nonce));
   memcpy(lockbox->gcm_tag, slot->gcm_tag, sizeof(lockbox->gcm_tag));
   lockbox->unlocked = true;
   lockbox->gcm_tag_initialized = true;

cleanup:
   OPENSSL_cleanse(shared_secret, sizeof(shared_secret));
   OPENSSL_cleanse(aes_wrap_key, sizeof(aes_wrap_key));
   if (aes_ctx) EVP_CIPHER_CTX_free(aes_ctx);
   if (kex_ctx) EVP_PKEY_CTX_free(kex_ctx);
   if (peer) EVP_PKEY_free(peer);
   if (self) EVP_PKEY_free(self);

   if (err) {
      OPENSSL_cleanse(lockbox->aes_key, sizeof(lockbox->aes_key));
      lockbox->unlocked = false;
      lockbox->gcm_tag_initialized = false;

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
