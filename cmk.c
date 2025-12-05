#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"
#include "ppport.h"

#include "CryptMultiKey_config.h"

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <openssl/kdf.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#ifndef HAVE_BOOL
   #define bool int
   #define true 1
   #define false 0
#endif

#include "cmk.h"

#define GOTO_CLEANUP_CROAK(msg) do { err= msg; goto cleanup; } while(0)

#define CMK_X25519_PUBKEY_LEN 32
#define CMK_X25519_PRIVKEY_LEN 32
#define CMK_AES_NONCE_LEN 12
#define CMK_AES_KEYLEN 32
#define CMK_GCM_TAG_LEN 16
#define CMK_PBKDF2_SALT_LEN 16
#define CMK_KDF_SALT_LEN 32
#define CMK_WRAP_KEY_LEN 32  /* AES-256 */

char* cmk_prepare_sv_buffer(SV *sv, size_t size) {
   STRLEN len;
   char *p;
   if (!SvOK(sv)) /* avoid "uninitialized value in subroutine" warning */
      sv_setpvs(sv, "");
   p= SvPVbyte_force(sv, len);
   if (len < size) {
      SvGROW(sv, size+1);
      SvCUR_set(sv, size);
      p= SvPVX(sv);
      p[size]= '\0';
   }
   else if (len > size) {
      SvCUR_set(sv, size);
      p[size]= '\0';
   }
   return p;
}

/* Generate a version 4 (random) UUID into the provided SV.
 * UUID v4 format: xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx
 * where x is random hex digit, y is one of 8,9,a,b
 * 
 * Byte layout:
 * - Bytes 0-15: 16 random bytes with specific bits set:
 *   - Byte 6: high nibble = 0x4 (version 4)
 *   - Byte 8: high 2 bits = 0b10 (variant RFC4122)
 */
SV* cmk_generate_uuid_v4(SV *buf_sv) {
   U8 *byte_pos, *hex_pos, *next_dash;
   U8 *buf= (U8*) cmk_prepare_sv_buffer(buf_sv, 36);
   /* Generate 16 random bytes */
   if (RAND_bytes((char*) buf, 16) != 1)
      croak("RAND_bytes failed");
   /* Set version to 4 (bits 12-15 of time_hi_and_version field = byte 6, high nibble) */
   buf[6] = (buf[6] & 0x0F) | 0x40;
   /* Set variant to RFC4122 (bits 6-7 of clock_seq_hi_and_reserved = byte 8, high 2 bits = 0b10) */
   buf[8] = (buf[8] & 0x3F) | 0x80;
   /* convert the 16 bytes to hex notation with dashes (36 chars long) */
   for (hex_pos= buf + 35, byte_pos= buf + 15, next_dash= buf + 10; byte_pos >= buf; byte_pos--) {
      *hex_pos-- = "0123456789ABCDEF"[*byte_pos >> 4];
      *hex_pos-- = "0123456789ABCDEF"[*byte_pos & 0xF];
      if (byte_pos == next_dash && next_dash != buf + 2) {
         *hex_pos-- = '-';
         next_dash -= 2;
      }
   }
   return buf_sv;
}

/**********************************************************************************************
 * OpenSSL Utilities
 */

static void
cmk_croak_with_ssl_error(const char *err) {
   unsigned long ssl_err = ERR_get_error();
   char ssl_err_str[256] = {0};
   if (ssl_err) {
      ERR_error_string_n(ssl_err, ssl_err_str, sizeof ssl_err_str);
      croak("%s: %s", err, ssl_err_str);
   } else {
      croak("%s", err);
   }
}

// The goal here is to detect whether EVP_PKEY exists in the lowest-overhead manner.
// Falls back to i2d_PrivateKey which will fail if private half isn't present.
static int
cmk_EVP_PKEY_has_private(const EVP_PKEY *pkey) {
   switch (EVP_PKEY_base_id(pkey)) {
#if 0
   case EVP_PKEY_RSA: {
      const BIGNUM *n, *e, *d;
      const RSA *rsa = EVP_PKEY_get0_RSA(pkey);
      RSA_get0_key(rsa, &n, &e, &d);
      return d != NULL;
   }

   case EVP_PKEY_EC: {
      const BIGNUM *priv = NULL;
      const EC_KEY *ec = EVP_PKEY_get0_EC_KEY(pkey);
      priv = EC_KEY_get0_private_key(ec);
      return priv != NULL;
   }
#endif
   case EVP_PKEY_ED25519:
   case EVP_PKEY_X25519:
   case EVP_PKEY_ED448:
   case EVP_PKEY_X448: {
      size_t len = 0;
      return EVP_PKEY_get_raw_private_key(pkey, NULL, &len) == 1 && len > 0;
   }

   default:
     /* Unknown type: fallback to i2d_PrivateKey probe */
     return i2d_PrivateKey((EVP_PKEY*)pkey, NULL) > 0;
   }
}

// Clone a EVP_PKEY.  Oddly there doesn't seem to be an API for it, so just serialize and
// immediately deserialize.
static EVP_PKEY *
cmk_EVP_PKEY_dup(EVP_PKEY *pkey) {
   const char *err = NULL;
   EVP_PKEY *clone = NULL;
   int len;
   U8 *buf = NULL;

   /* First, see if there is a private key encoding */
   len = i2d_PrivateKey(pkey, NULL);
   if (len > 0) {
      /* Full private+public key available: clone via private key only */
      if (!(buf = (U8*) safemalloc((Size_t)len)))
         GOTO_CLEANUP_CROAK("malloc failed in magic_dup (priv)");

      unsigned char *p = buf;
      if (i2d_PrivateKey(pkey, &p) != len)
         GOTO_CLEANUP_CROAK("i2d_PrivateKey failed in magic_dup");

      const unsigned char *cp = buf;
      if (!d2i_PrivateKey(EVP_PKEY_base_id(pkey), &clone, &cp, (long)len))
         GOTO_CLEANUP_CROAK("d2i_PrivateKey failed in magic_dup");
   } else {
      /* No private key (or encoding failed): fall back to public-only */
      len = i2d_PUBKEY(pkey, NULL);
      if (len <= 0)
         GOTO_CLEANUP_CROAK("i2d_PUBKEY failed in magic_dup");

      if (!(buf = (U8*) safemalloc((Size_t)len)))
         GOTO_CLEANUP_CROAK("malloc failed in magic_dup (pub)");

      unsigned char *p = buf;
      if (i2d_PUBKEY(pkey, &p) != len)
         GOTO_CLEANUP_CROAK("i2d_PUBKEY failed in magic_dup");

      const unsigned char *cp = buf;
      if (!d2i_PUBKEY(&clone, &cp, (long)len))
         GOTO_CLEANUP_CROAK("d2i_PUBKEY failed in magic_dup");
   }
cleanup:
   if (buf) {
      /* buf may contain private key DER */
      OPENSSL_cleanse(buf, len);
      Safefree(buf);
   }

   if (err) {
      if (clone)
         EVP_PKEY_free(clone);
      cmk_croak_with_ssl_error(err);
   }

   return clone;
}

/* Key generation based on string parameters.  I'm attempting to use the same names as OpenSSL3
 * but implement it in 1.1 compatible code.
 */
EVP_PKEY *cmk_EVP_PKEY_keygen(const char *type, const char **params, int param_count) {
   const char *err= NULL;
   EVP_PKEY_CTX *ctx= NULL;
   EVP_PKEY *pkey= NULL;
   BIGNUM *bignum= NULL;
   int type_len= strlen(type);

   if (type_len == 6 && foldEQ(type, "x25519", 6)) {
      if (param_count > 0)
         GOTO_CLEANUP_CROAK("x25519 does not take any parameters");
      ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
      if (!ctx || EVP_PKEY_keygen_init(ctx) <= 0)
         GOTO_CLEANUP_CROAK("keygen init (x25519) failed");
   }  
   else if (type_len == 7 && foldEQ(type, "ED25519", 7)) {
      if (param_count > 0)
         GOTO_CLEANUP_CROAK("x25519 does not take any parameters");
      ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
      if (!ctx || EVP_PKEY_keygen_init(ctx) <= 0)
         GOTO_CLEANUP_CROAK("keygen init (ED25519) failed");
   }
   else if (type_len == 3 && foldEQ(type, "RSA", 3)) {
      int i, bits= 4096;
      ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
      if (!ctx || EVP_PKEY_keygen_init(ctx) <= 0)
         GOTO_CLEANUP_CROAK("keygen init (RSA) failed");
      for (i= 0; i < param_count; i++) {
         const char *p = params[i];
         const char *eq = strchr(p, '=');
         int len= eq? eq - p : strlen(p);
         const char *value= eq? eq + 1 : "";
         if (len == 6 && memcmp(p, "pubexp", 6) == 0
            || len == 17 && memcmp(p, "rsa_keygen_pubexp", 17) == 0
         ) {
            char *end;
            long exp= strtol(value, &end, 10);
            if (*end != '\0' || end == value)
               GOTO_CLEANUP_CROAK("invalid rsa_keygen_pubexp");
            bignum = BN_new();
            if (!bignum || !BN_set_word(bignum, exp))
               GOTO_CLEANUP_CROAK("BN_new/BN_set_word failed");
            if (EVP_PKEY_CTX_set_rsa_keygen_pubexp(ctx, bignum) <= 0)
               GOTO_CLEANUP_CROAK("set_rsa_keygen_pubexp failed");
         }
         else if (len == 4 && memcmp(p, "bits", 4) == 0
            || len == 15 && memcmp(p, "rsa-keygen-bits", 15) == 0
         ) {
            char *end;
            bits= strtol(value, &end, 10);
            if (*end != '\0' || end == value)
               GOTO_CLEANUP_CROAK("invalid 'rsa-keygen-bits' value");
         }
         else {
            GOTO_CLEANUP_CROAK("Unknown RSA parameter");
         }
      }
      if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0)
         GOTO_CLEANUP_CROAK("set_rsa_keygen_bits failed");
   }
   else if (type_len == 2 && foldEQ(type, "EC", 2)) {
      int i;
      ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
      if (!ctx || EVP_PKEY_keygen_init(ctx) <= 0)
         GOTO_CLEANUP_CROAK("keygen init (EC) failed");
      for (i= 0; i < param_count; i++) {
         const char *p = params[i];
         const char *eq = strchr(p, '=');
         int len= eq? eq - p : strlen(p);
         const char *value= eq? eq + 1 : "";
         if (len == 5 && memcmp(p, "group", 5) == 0
            || len == 16 && memcmp(p, "ec_paramgen_curve", 16) == 0
         ) {
            int curve_nid = OBJ_txt2nid(value);
            if (curve_nid == NID_undef)
               GOTO_CLEANUP_CROAK("unknown EC group");
            if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, curve_nid) <= 0)
               GOTO_CLEANUP_CROAK("set_ec_paramgen_curve_nid failed");

            if (EVP_PKEY_CTX_set_ec_param_enc(ctx, OPENSSL_EC_NAMED_CURVE) <= 0)
               GOTO_CLEANUP_CROAK("set_ec_param_enc failed");
         }
         else {
            GOTO_CLEANUP_CROAK("Unknown EC parameter");
         }
      }
   }
   else {
      croak("unknown key type '%s'", type);
   }
   if (EVP_PKEY_keygen(ctx, &pkey) <= 0)
      GOTO_CLEANUP_CROAK("keygen failed");
cleanup:
   if (ctx)
      EVP_PKEY_CTX_free(ctx);
   if (bignum)
      BN_free(bignum);
   if (err)
      cmk_croak_with_ssl_error(err);
   return pkey;
}

/* MAGIC for storing a EVP_PKEY object on an arbitrary SV
 * Crypt::MultiKey::Key objects hold the public key in MAGIC, and the field
 * $key->private is a SecretBuffer object which can hold the decrypted private key.
 */
#ifdef USE_ITHREADS
static int cmk_EVP_PKEY_magic_dup(pTHX_ MAGIC *mg, CLONE_PARAMS *param) {
   if (mg->mg_ptr)
      mg->mg_ptr= cmk_EVP_PKEY_dup((EVP_PKEY*) mg->mg_ptr);
   PERL_UNUSED_VAR(param);
   return 0;
};
#define SET_MGf_DUP_FLAG(mg) do { magic->mg_flags |= MGf_DUP; } while (0)
#else
#define cmk_EVP_PKEY_magic_dup 0
#define SET_MGf_DUP_FLAG(mg) ((void)0)
#endif

static int cmk_EVP_PKEY_magic_free(pTHX_ SV *sv, MAGIC *mg) {
   if (mg->mg_ptr) EVP_PKEY_free((EVP_PKEY*) mg->mg_ptr);
}

static MGVTBL cmk_EVP_PKEY_magic_vtbl = {
   NULL, NULL, NULL, NULL,
   cmk_EVP_PKEY_magic_free,
   NULL,
   cmk_EVP_PKEY_magic_dup
#ifdef MGf_LOCAL
   ,NULL
#endif
};

/* Crypt::MultiKey::Key stores a EVP_KEY in Magic.  OpenSSL routines can rewrite the pointer,
 * so instead of load/save API I just return a pointer-to-pointer that can be written.
 * If EVP_PKEY magic doesn't exist, it gets created with a pointer that is initially NULL.
 */
EVP_PKEY **
cmk_EVP_PKEY_p_from_magic(SV *sv, bool autocreate) {
   MAGIC *magic= SvMAGICAL(sv)? mg_findext(sv, PERL_MAGIC_ext, &cmk_EVP_PKEY_magic_vtbl) : NULL;
   if (!magic && autocreate) {
      magic= sv_magicext(sv, NULL, PERL_MAGIC_ext, &cmk_EVP_PKEY_magic_vtbl, NULL, 0);
      SET_MGf_DUP_FLAG(magic);
   }
   return !magic? NULL : (EVP_PKEY**) &magic->mg_ptr;
}

/******************************** Key API ***********************************/

/* Return the public key for the Crypt::MultiKey::Key object.  This will lazily deserialize
 * the 'pubkey' attribute which is a "ASN.1 SubjectPublicKeyInfo structure defined in RFC5280"
 */
EVP_PKEY *
cmk_key_get_pubkey(SV *objref) {
   HV *hv= (objref && SvROK(objref) && SvTYPE(SvRV(objref)) == SVt_PVHV)? (HV*) SvRV(objref) : NULL;
   STRLEN len;
   EVP_PKEY **key_p;

   if (!hv)
      croak("Not a Crypt::MultiKey::Key");
   
   /* Return cached? */
   key_p= cmk_EVP_PKEY_p_from_magic((SV*) hv, true);
   if (!*key_p) { /* locate and parse key 'public' */
      STRLEN len;
      const U8 *buf;
      SV **field= hv_fetchs(hv, "public", 0);
      if (!(field && *field && SvOK(*field)))
         croak("Missing 'public' attribute");
      buf= (U8*) secret_buffer_SvPVbyte(*field, &len);
      if (!len || !d2i_PUBKEY(key_p, &buf, len) || !*key_p)
         croak("Decoding 'public' attribute failed");
   }
   return *key_p;
}

/* Return the private key (includes public key) for the Crypt::MultiKey::Key object.
 * This is cached on the SecretBuffer object of attribute 'private', or decoded from it.
 */
EVP_PKEY *
cmk_key_get_privkey(SV *objref) {
   HV *hv= (objref && SvROK(objref) && SvTYPE(SvRV(objref)) == SVt_PVHV)? (HV*) SvRV(objref) : NULL;
   SV **field;
   EVP_PKEY **key_p;

   if (!hv)
      croak("Not a Crypt::MultiKey::Key");

   field= hv_fetchs(hv, "private", 0);
   if (!(field && *field && SvOK(*field)))
      croak("Missing 'private' attribute");

   /* is it cached? */
   key_p= cmk_EVP_PKEY_p_from_magic(SvROK(*field)? SvRV(*field) : *field, true);
   if (!*key_p) {
      STRLEN len;
      const U8 *buf= (U8*) secret_buffer_SvPVbyte(*field, &len);
      EVP_PKEY *pubkey= cmk_key_get_pubkey(objref);
      if (!len || !d2i_PrivateKey(EVP_PKEY_base_id(pubkey), key_p, &buf, len) || !*key_p)
         croak("Decoding 'private' attribute failed");
   }
   return *key_p;
}

/* Generate a key, and store the results in the fields (and MAGIC) of Crypt::MultiKey::Key
 * This parses out the ":param=value" from the end of the string.
 */
EVP_PKEY *
cmk_key_keygen(SV *objref, const char *type_and_params) {
   const char *param_start= strchr(type_and_params, ':');
   if (param_start) {
      char *parambuf, *ch, **params;
      int param_count= 0;
      STRLEN len= strlen(type_and_params);
      /* count params */
      { const char *ch= param_start;
         do {
            if (ch[1] != ':' && ch[1] != '\0')
               ++param_count;
         } while ((ch= strchr(ch+1, ':')));
      }
      /* create a writable buffer so we can replace ':' with NUL */
      Newx(parambuf, len, char);
      SAVEFREEPV(parambuf);
      memcpy(parambuf, type_and_params, len);
      Newx(params, param_count, char*);
      SAVEFREEPV(params);
      param_count= 0;
      {
         char *ch= strchr(parambuf, ':');;
         do {
            *ch= '\0';
            if (ch[1] != ':' && ch[1] != '\0')
               params[param_count++]= ch+1;
         } while ((ch= strchr(ch+1, ':')));
      }
      return cmk_key_keygen_params(objref, parambuf, (const char **) params, param_count);
   }
   return cmk_key_keygen_params(objref, type_and_params, NULL, 0);
}

/* Generate a key, and store the results in the fields (and MAGIC) of Crypt::MultiKey::Key
 * This takes a list of string parameters for things like RSA bits or EC group.
 */
EVP_PKEY *
cmk_key_keygen_params(SV *objref, const char *type, const char **params, int param_count) {
   const char *err;
   HV *hv= (objref && SvROK(objref) && SvTYPE(SvRV(objref)) == SVt_PVHV)? (HV*) SvRV(objref) : NULL;
   SV *public_buf= sv_newmortal(), *private_ref;
   secret_buffer *sb= secret_buffer_new(0, &private_ref);
   EVP_PKEY **key_p, *new_key= NULL;
   STRLEN len;
   int serialized_len;
   U8 *buf;

   if (!hv)
      croak("Not a Crypt::MultiKey::Key");

   new_key= cmk_EVP_PKEY_keygen(type, params, param_count);

   /* encode the public key into a scalar */
   serialized_len= i2d_PUBKEY(new_key, NULL);
   if (serialized_len <= 0)
      GOTO_CLEANUP_CROAK("Can't serialize public key");
   buf= (U8*) cmk_prepare_sv_buffer(public_buf, serialized_len);
   if (i2d_PUBKEY(new_key, &buf) != serialized_len)
      GOTO_CLEANUP_CROAK("Can't serialize public key");

   /* encode the private key into a SecretBuffer */
   serialized_len= i2d_PrivateKey(new_key, NULL);
   if (serialized_len <= 0)
      GOTO_CLEANUP_CROAK("Can't serialize private key");
   secret_buffer_set_len(sb, serialized_len);
   buf= sb->data;
   if (i2d_PrivateKey(new_key, &buf) != serialized_len)
      GOTO_CLEANUP_CROAK("Can't serialize private key");

   /* Attach the full key to the HV of the secret_buffer, which becomes the 'private' field */
   *cmk_EVP_PKEY_p_from_magic(sb->wrapper, 1)= new_key;
   new_key= NULL; /* prevent cleanup below */

   /* store the hash fields */
   if (!hv_stores(hv, "private", private_ref))
      GOTO_CLEANUP_CROAK("can't set ->{private}");
   SvREFCNT_inc(private_ref); /* was mortal */

   if (!hv_stores(hv, "public", public_buf))
      GOTO_CLEANUP_CROAK("can't set ->{public}");
   SvREFCNT_inc(public_buf); /* was mortal */

cleanup:
   if (err) {
      if (new_key)
         EVP_PKEY_free(new_key);
      cmk_croak_with_ssl_error(err);
   }
   return new_key;
}

#if 0
/* Create the 'private_encrypted' field of the Key object from the 'private' field
 * using AES with an aes_key derived from the supplied password.  The field 'pbkdf2_iter'
 * is consulted to determine whether to use pbkdf2, and pbk_salt field is generated if so.
 * The 'private' field is unmodified.
 * Dies on failure.
 */
void cmk_key_encrypt_private(cmk_key *key, const U8 *pass, size_t pass_len) {
   SV **field, *priv_enc_ref= NULL;
   U8 *priv;
   STRLEN priv_len= 0;
   int outlen, more_outlen;
   const char *err= NULL;
   secret_buffer *priv_enc= NULL, *cipher_key= NULL;
   EVP_CIPHER *cipher= NULL;
   EVP_CIPHER_CTX ctx;
   EVP_CIPHER_CTX_init(&ctx);

   if (!key->priv)
      croak("Cannot encrypt key when 'private' attribute isn't loaded");
   switch (key->type) {
   case CMK_KEY_TYPE_X25519:
      /* validate the key length */
      if (key->priv_len != CMK_X25519_PRIVKEY_LEN)
         croak("x25519 private key must be %d bytes but got %d", CMK_X25519_PRIVKEY_LEN, (int)key->priv_len);
      break;
   default:
      croak("Unhandled key type");
   }

   /* determine cipher */
   field= hv_fetchs(obj_hv, "private_encrypted_cipher", 1);
   if (!field || !*field)
      croak("Can't access private_encrypted_cipher");
   if (!SvOK(*field))
      sv_setpvs(*field, "AES-256-ECB");
   cipher= EVP_get_cipherbyname(SvPV_nolen(*field));
   if (!cipher)
      croak("Unknown cipher %s", SvPV_nolen(*field));
   if (EVP_CIPHER_CTX_iv_length(cipher) != 0)
      croak("Currently no support for ciphers with nonzero IV size");
   /* set the cipher key buffer to the length required */
   cipher_key= secret_buffer_new(0, NULL);
   secret_buffer_set_len(cipher_key, EVP_CIPHER_key_length(cipher));

   if (key->pbkdf2_iter > 0) {
      unsigned char salt[CMK_PBKDF2_SALT_LEN];
      SV *salt_ref= NULL;
      secret_buffer *salt= secret_buffer_new(CMK_PBKDF2_SALT_LEN, &sb_ref);

      secret_buffer_set_len(salt, CMK_PBKDF2_SALT_LEN);
      if (RAND_bytes(salt->data, CMK_PBKDF2_SALT_LEN)) != 1)
         err = "Salt generation failed", goto cleanup;

      if (PKCS5_PBKDF2_HMAC(pass, pass_len, salt->data, salt->len,
                            key->pbkdf2_iter, EVP_sha256(),
                            cipher_key->len, cipher_key->data) != 1)
         err = "PBKDF2 failed", goto cleanup;
      /* save the salt to an object field */
      field= hv_fetchs(key->hv, "kdf_salt", 1);
      if (!field || !*field) croak("Can't write kdf_salt attribute");
      sv_setsv(*field, salt_ref);
   } else {
      /* Else pass *is* the key for the cipher */
      if (pass_len != cipher_key->len)
         croak("Password must be exactly %d bytes if not using PBKDF2", (int)cipher_key->len);
      memcpy(cipher_key->data, pass, pass_len);
   }

   /* prepare destination buffer */
   priv_enc= secret_buffer_new(priv_len + EVP_CIPHER_block_size(cipher)*2, &priv_enc_ref);

   /* Encrypt private key */
   if (EVP_EncryptInit_ex(&ctx, cipher, NULL, cipher_key->data, NULL) != 1)
      err = "EncryptInit failed", goto cleanup;

   if (EVP_EncryptUpdate(&ctx, priv_enc->data, &outlen, priv, priv_len) != 1)
      err = "EncryptUpdate failed", goto cleanup;
   priv_enc->len= outlen;

   if (EVP_EncryptFinal_ex(&ctx, priv_enc->data + priv_enc->len, &outlen) != 1)
      err = "EncryptFinal failed", goto cleanup;
   priv_enc->len += outlen;
   
   /* store private_encrypted */
   field= hv_fetchs(obj_hv, "private_encrypted", 1);
   if (!field || !*field)
      err = "Can't write private_encrypted attribute", goto cleanup;
   sv_setsv(*field, priv_enc_ref);

cleanup:
   EVP_CIPHER_CTX_cleanup(&ctx);
   /* all SecretBuffers are cleaned up automatically */
   if (err)
      cmk_croak_with_ssl_error(err);
}

/* Create the 'private' field of the Key object from the 'private_encrypted' field
 * using AES with an aes_key reconstructed from the supplied password.
 * Dies on failure.
 */
void cmk_key_decrypt_private(SV *key_obj, const U8 *pass, size_t pass_len) {
}
#endif

/* This function encrypts a secret using a public key.  It stores the ciphertext and all
 * parameters required for decryption into the "slot" hash.
 * For RSA keys, this generates an AES wrapper key, encrypts the secret with the wrapper,
 * and then encrypts the wrapper key using RSA.
 * For DSA-like key types, this creates an ephemeral key, derives the shared secret,
 * uses the shared secret to encrypt the secret, then stores the public half of the ephemeral
 * key along side the other fields.
 */
void cmk_key_encrypt(EVP_PKEY *public_key, const U8 *secret, size_t secret_len, HV *enc_out) {
   const char *err = NULL;
   SV *hv_store_val= NULL;
   EVP_PKEY *ephemeral = NULL;
   EVP_PKEY_CTX *pctx = NULL;
   EVP_PKEY_CTX *ctx = NULL;
   EVP_PKEY_CTX *kdf = NULL;
   EVP_PKEY_CTX *rsa_ctx = NULL;
   EVP_CIPHER_CTX *aes_ctx = NULL;

   U8 *shared_secret = NULL;
   size_t shared_len = 0;

   U8 aes_wrap_key[CMK_WRAP_KEY_LEN];
   U8 kdf_salt[CMK_KDF_SALT_LEN];
   U8 nonce[CMK_AES_NONCE_LEN];
   U8 gcm_tag[CMK_GCM_TAG_LEN];

   U8 *secret_ct = NULL;
   size_t secret_ct_len = 0;

   U8 *ephemeral_pub_der = NULL;    /* DER ephemeral pub for X25519 */
   int ephemeral_pub_der_len = 0;

   U8 *rsa_ct = NULL;      /* RSA ciphertext of wrap key */
   size_t rsa_ct_len = 0;

   int type = 0;
   int outlen = 0;

   if (!enc_out || !public_key || !secret || secret_len == 0)
      croak("invalid arguments");

   /* RSA keys encrypt/decrypt directly, but DSA-style keys need to create an ephermeral
    * key to perform a handshake with, to produce a shared secret.
    */
   type= EVP_PKEY_base_id(public_key);
   if (type == EVP_PKEY_X25519 || type == EVP_PKEY_X448
    || type == EVP_PKEY_EC     || type == EVP_PKEY_DH
   ) {
      /* 1. Generate ephemeral keypair of same type */
      pctx = EVP_PKEY_CTX_new_id(type, NULL);
      if (!pctx ||
         EVP_PKEY_keygen_init(pctx) <= 0 ||
         EVP_PKEY_keygen(pctx, &ephemeral) <= 0
      )
         GOTO_CLEANUP_CROAK("Ephemeral key generation failed");

      /* 2. Derive shared secret: ephemeral (private) + MultiKey::Key object (public) */
      ctx= EVP_PKEY_CTX_new(ephemeral, NULL);
      if (!ctx ||
         EVP_PKEY_derive_init(ctx) <= 0 ||
         EVP_PKEY_derive_set_peer(ctx, public_key) <= 0
      )
         GOTO_CLEANUP_CROAK("Derive init failed");

      /* Query required length */
      if (EVP_PKEY_derive(ctx, NULL, &shared_len) <= 0 || shared_len == 0)
         GOTO_CLEANUP_CROAK("Derive (size) failed");

      shared_secret = OPENSSL_malloc(shared_len);
      if (!shared_secret)
         GOTO_CLEANUP_CROAK("malloc for shared_secret failed");

      if (EVP_PKEY_derive(ctx, shared_secret, &shared_len) <= 0)
         GOTO_CLEANUP_CROAK("Deriving shared secret failed");

      /* 3. DER-encode ephemeral public key (SPKI) for storage */
      if ((ephemeral_pub_der_len = i2d_PUBKEY(ephemeral, NULL)) <= 0)
         GOTO_CLEANUP_CROAK("i2d_PUBKEY (size) failed");

      if (!(ephemeral_pub_der = OPENSSL_malloc(ephemeral_pub_der_len)))
         GOTO_CLEANUP_CROAK("malloc for ephemeral pub DER failed");

      if (i2d_PUBKEY(ephemeral, &ephemeral_pub_der) != ephemeral_pub_der_len)
         GOTO_CLEANUP_CROAK("i2d_PUBKEY failed");

      /* 4. HKDF(shared_secret) -> aes_wrap_key */
      if (RAND_bytes(kdf_salt, sizeof kdf_salt) != 1)
         GOTO_CLEANUP_CROAK("Salt generation failed");

      kdf = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
      if (!kdf ||
         EVP_PKEY_derive_init(kdf) <= 0 ||
         EVP_PKEY_CTX_set_hkdf_md(kdf, EVP_sha256()) <= 0 ||
         EVP_PKEY_CTX_set1_hkdf_salt(kdf, kdf_salt, sizeof kdf_salt) <= 0 ||
         EVP_PKEY_CTX_set1_hkdf_key(kdf, shared_secret, shared_len) <= 0 ||
         EVP_PKEY_CTX_add1_hkdf_info(kdf, (unsigned char *)"cmk-wrap", 8) <= 0 ||
         EVP_PKEY_derive(kdf, aes_wrap_key, &(size_t){ CMK_WRAP_KEY_LEN }) <= 0
      )
         GOTO_CLEANUP_CROAK("HKDF failed");
   }
   else if (type == EVP_PKEY_RSA || type == EVP_PKEY_RSA_PSS) {
      /* ---- RSA branch (RSA-OAEP) ---- */

      /* 1. Generate random wrap key */
      if (RAND_bytes(aes_wrap_key, sizeof aes_wrap_key) != 1)
         GOTO_CLEANUP_CROAK("RAND_bytes for wrap key failed");

      /* 2. RSA-OAEP encrypt wrap key with public_key */
      rsa_ctx = EVP_PKEY_CTX_new(public_key, NULL);
      if (!rsa_ctx
         || EVP_PKEY_encrypt_init(rsa_ctx) <= 0
         || EVP_PKEY_CTX_set_rsa_padding(rsa_ctx, RSA_PKCS1_OAEP_PADDING) <= 0
         || EVP_PKEY_CTX_set_rsa_oaep_md(rsa_ctx, EVP_sha256()) <= 0
         || EVP_PKEY_CTX_set_rsa_mgf1_md(rsa_ctx, EVP_sha256()) <= 0
      )
         GOTO_CLEANUP_CROAK("RSA encrypt init failed");

      if (EVP_PKEY_encrypt(rsa_ctx, NULL, &rsa_ct_len, aes_wrap_key, sizeof(aes_wrap_key)) <= 0
            || rsa_ct_len == 0
         )
         GOTO_CLEANUP_CROAK("RSA encrypt size query failed");

      if (!(rsa_ct = OPENSSL_malloc(rsa_ct_len)))
         GOTO_CLEANUP_CROAK("malloc for RSA ciphertext failed");

      if (EVP_PKEY_encrypt(rsa_ctx, rsa_ct, &rsa_ct_len, aes_wrap_key, sizeof(aes_wrap_key)) <= 0)
         GOTO_CLEANUP_CROAK("RSA encrypt failed");
   }
   else {
      GOTO_CLEANUP_CROAK("Unsupported key type");
   }

   /* ---------- AES-GCM encrypt the coffer cipher_key using aes_wrap_key ---------- */

   if (RAND_bytes(nonce, sizeof nonce) != 1)
      GOTO_CLEANUP_CROAK("Failed to generate GCM nonce");

   secret_ct_len = secret_len;
   if (!(secret_ct = OPENSSL_malloc(secret_ct_len)))
      GOTO_CLEANUP_CROAK("malloc for vault ciphertext failed");

   aes_ctx = EVP_CIPHER_CTX_new();
   if (!aes_ctx
      || EVP_EncryptInit_ex(aes_ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1
      || EVP_CIPHER_CTX_ctrl(aes_ctx, EVP_CTRL_GCM_SET_IVLEN, (int)sizeof(nonce), NULL) != 1
      || EVP_EncryptInit_ex(aes_ctx, NULL, NULL, aes_wrap_key, nonce) != 1
   )
      GOTO_CLEANUP_CROAK("AES-GCM init failed");

   if (EVP_EncryptUpdate(aes_ctx, secret_ct, &outlen, secret, (int)secret_len) != 1
      || (size_t)outlen != secret_ct_len
   )
      GOTO_CLEANUP_CROAK("AES-GCM encrypt failed");

   if (EVP_EncryptFinal_ex(aes_ctx, NULL, &outlen) != 1)
      GOTO_CLEANUP_CROAK("AES-GCM final failed");

   if (EVP_CIPHER_CTX_ctrl(aes_ctx, EVP_CTRL_GCM_GET_TAG, (int)sizeof(gcm_tag), gcm_tag) != 1)
      GOTO_CLEANUP_CROAK("AES-GCM get tag failed");

   /* ---------- Store public results in slot HV ---------- */
   if (kdf)
      if (!hv_stores(enc_out, "kdf_salt", (hv_store_val= newSVpvn(kdf_salt, sizeof(kdf_salt)))))
         GOTO_CLEANUP_CROAK("write ->{kdf_salt}");

   if (ephemeral_pub_der)
      if (!hv_stores(enc_out, "ephemeral_pubkey", (hv_store_val= newSVpvn(ephemeral_pub_der, ephemeral_pub_der_len))))
         GOTO_CLEANUP_CROAK("write ->{ephemeral_pubkey}");

   if (rsa_ct)
      if (!hv_stores(enc_out, "encrypted_wrap_key", (hv_store_val= newSVpvn(rsa_ct, rsa_ct_len))))
         GOTO_CLEANUP_CROAK("write ->{encrypted_wrap_key}");

   if (!hv_stores(enc_out, "aes_gcm_nonce", (hv_store_val= newSVpvn(nonce, sizeof nonce))))
      GOTO_CLEANUP_CROAK("write ->{aes_gcm_nonce}");

   if (!hv_stores(enc_out, "aes_gcm_tag",   (hv_store_val= newSVpvn(gcm_tag, sizeof gcm_tag))))
      GOTO_CLEANUP_CROAK("write ->{aes_gcm_tag}");

   if (!hv_stores(enc_out, "encrypted_secret", (hv_store_val= newSVpvn(secret_ct, (STRLEN)secret_ct_len))))
      GOTO_CLEANUP_CROAK("write ->{encrypted_secret}");

cleanup:
   if (shared_secret)
      OPENSSL_clear_free(shared_secret, shared_len);

   OPENSSL_cleanse(aes_wrap_key, sizeof aes_wrap_key);

   if (ctx) EVP_PKEY_CTX_free(ctx);
   if (kdf) EVP_PKEY_CTX_free(kdf);
   if (pctx) EVP_PKEY_CTX_free(pctx);
   if (rsa_ctx) EVP_PKEY_CTX_free(rsa_ctx);

   if (ephemeral) EVP_PKEY_free(ephemeral);
   if (aes_ctx) EVP_CIPHER_CTX_free(aes_ctx);

   if (ephemeral_pub_der) OPENSSL_free(ephemeral_pub_der);
   if (rsa_ct) OPENSSL_free(rsa_ct);
   if (secret_ct) OPENSSL_free(secret_ct);

   if (err) {
      if (hv_store_val) /* if hv_stores fails, the thing we tried to store needs freed */
         SvREFCNT_dec(hv_store_val);
      cmk_croak_with_ssl_error(err);
   }
}

/* This function decrypts a secret from a key slot using a private key.
 * It reverses the process of cmk_key_slot_create by:
 * - For RSA keys: decrypting the wrapper key, then using it to decrypt the secret
 * - For DSA-like keys: deriving the shared secret from the ephemeral public key,
 *   then using it to decrypt the secret
 */
void cmk_key_decrypt(EVP_PKEY *private_key, HV *enc_in, secret_buffer *secret_out) {
   const char *err = NULL;
   EVP_PKEY *ephemeral_pub = NULL;
   EVP_PKEY_CTX *ctx = NULL;
   EVP_PKEY_CTX *kdf = NULL;
   EVP_PKEY_CTX *rsa_ctx = NULL;
   EVP_CIPHER_CTX *aes_ctx = NULL;

   U8 *shared_secret = NULL;
   size_t shared_len = 0;

   U8 aes_wrap_key[CMK_WRAP_KEY_LEN];

   SV **svp;
   U8 *kdf_salt = NULL;
   STRLEN kdf_salt_len = 0;
   U8 *nonce = NULL;
   STRLEN nonce_len = 0;
   U8 *gcm_tag = NULL;
   STRLEN gcm_tag_len = 0;
   U8 *secret_ct = NULL;
   STRLEN secret_ct_len = 0;
   U8 *ephemeral_pub_der = NULL;
   STRLEN ephemeral_pub_der_len = 0;
   U8 *rsa_ct = NULL;
   size_t rsa_ct_len = 0;

   U8 *secret_pt = NULL;
   int outlen = 0;
   int type = 0;

   if (!enc_in || !private_key || !secret_out)
      croak("invalid arguments");

   /* Extract required fields from slot hash */
   svp = hv_fetchs(enc_in, "aes_gcm_nonce", 0);
   if (!svp || !*svp) GOTO_CLEANUP_CROAK("Missing aes_gcm_nonce");
   nonce = (U8*)SvPV(*svp, nonce_len);
   if (nonce_len != CMK_AES_NONCE_LEN)
      GOTO_CLEANUP_CROAK("Invalid aes_gcm_nonce length");

   svp = hv_fetchs(enc_in, "aes_gcm_tag", 0);
   if (!svp || !*svp) GOTO_CLEANUP_CROAK("Missing aes_gcm_tag");
   gcm_tag = (U8*)SvPV(*svp, gcm_tag_len);
   if (gcm_tag_len != CMK_GCM_TAG_LEN)
      GOTO_CLEANUP_CROAK("Invalid aes_gcm_tag length");

   svp = hv_fetchs(enc_in, "encrypted_secret", 0);
   if (!svp || !*svp) GOTO_CLEANUP_CROAK("Missing encrypted_coffer_key");
   secret_ct = (U8*)SvPV(*svp, secret_ct_len);

   /* Determine key type and decrypt accordingly */
   type = EVP_PKEY_base_id(private_key);

   if (type == EVP_PKEY_X25519 || type == EVP_PKEY_X448
    || type == EVP_PKEY_EC     || type == EVP_PKEY_DH
   ) {
      /* ---- DSA-like branch: derive shared secret from ephemeral public key ---- */

      /* 1. Extract ephemeral public key and KDF salt */
      svp = hv_fetchs(enc_in, "ephemeral_pubkey", 0);
      if (!svp || !*svp) GOTO_CLEANUP_CROAK("Missing ephemeral_pubkey");
      ephemeral_pub_der = (U8*)SvPV(*svp, ephemeral_pub_der_len);

      svp = hv_fetchs(enc_in, "kdf_salt", 0);
      if (!svp || !*svp) GOTO_CLEANUP_CROAK("Missing kdf_salt");
      kdf_salt = (U8*)SvPV(*svp, kdf_salt_len);
      if (kdf_salt_len != CMK_KDF_SALT_LEN)
         GOTO_CLEANUP_CROAK("Invalid kdf_salt length");

      /* 2. Decode ephemeral public key from DER */
      {
         const U8 *p = ephemeral_pub_der;  /* d2i advances the pointer */
         ephemeral_pub = d2i_PUBKEY(NULL, &p, ephemeral_pub_der_len);
         if (!ephemeral_pub)
            GOTO_CLEANUP_CROAK("Failed to decode ephemeral public key");
      }

      /* 3. Derive shared secret: private_key + ephemeral_pub */
      ctx = EVP_PKEY_CTX_new(private_key, NULL);
      if (!ctx ||
         EVP_PKEY_derive_init(ctx) <= 0 ||
         EVP_PKEY_derive_set_peer(ctx, ephemeral_pub) <= 0
      )
         GOTO_CLEANUP_CROAK("Derive init failed");

      /* Query required length */
      if (EVP_PKEY_derive(ctx, NULL, &shared_len) <= 0 || shared_len == 0)
         GOTO_CLEANUP_CROAK("Derive (size) failed");

      shared_secret = OPENSSL_malloc(shared_len);
      if (!shared_secret)
         GOTO_CLEANUP_CROAK("malloc for shared_secret failed");

      if (EVP_PKEY_derive(ctx, shared_secret, &shared_len) <= 0)
         GOTO_CLEANUP_CROAK("Deriving shared secret failed");

      /* 4. HKDF(shared_secret) -> aes_wrap_key */
      kdf = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
      if (!kdf ||
         EVP_PKEY_derive_init(kdf) <= 0 ||
         EVP_PKEY_CTX_set_hkdf_md(kdf, EVP_sha256()) <= 0 ||
         EVP_PKEY_CTX_set1_hkdf_salt(kdf, kdf_salt, kdf_salt_len) <= 0 ||
         EVP_PKEY_CTX_set1_hkdf_key(kdf, shared_secret, shared_len) <= 0 ||
         EVP_PKEY_CTX_add1_hkdf_info(kdf, (unsigned char *)"cmk-wrap", 8) <= 0 ||
         EVP_PKEY_derive(kdf, aes_wrap_key, &(size_t){ CMK_WRAP_KEY_LEN }) <= 0
      )
         GOTO_CLEANUP_CROAK("HKDF failed");
   }
   else if (type == EVP_PKEY_RSA || type == EVP_PKEY_RSA_PSS) {
      /* ---- RSA branch: decrypt wrap key using RSA-OAEP ---- */

      /* 1. Extract encrypted wrap key */
      svp = hv_fetchs(enc_in, "encrypted_wrap_key", 0);
      if (!svp || !*svp) GOTO_CLEANUP_CROAK("Missing encrypted_wrap_key");
      rsa_ct = (U8*)SvPV(*svp, rsa_ct_len);

      /* 2. RSA-OAEP decrypt to get wrap key */
      rsa_ctx = EVP_PKEY_CTX_new(private_key, NULL);
      if (!rsa_ctx
         || EVP_PKEY_decrypt_init(rsa_ctx) <= 0
         || EVP_PKEY_CTX_set_rsa_padding(rsa_ctx, RSA_PKCS1_OAEP_PADDING) <= 0
         || EVP_PKEY_CTX_set_rsa_oaep_md(rsa_ctx, EVP_sha256()) <= 0
         || EVP_PKEY_CTX_set_rsa_mgf1_md(rsa_ctx, EVP_sha256()) <= 0
      )
         GOTO_CLEANUP_CROAK("RSA decrypt init failed");

      {
         size_t wrap_key_len = sizeof(aes_wrap_key);
         if (EVP_PKEY_decrypt(rsa_ctx, aes_wrap_key, &wrap_key_len, rsa_ct, rsa_ct_len) <= 0
               || wrap_key_len != CMK_WRAP_KEY_LEN
            )
            GOTO_CLEANUP_CROAK("RSA decrypt failed");
      }
   }
   else {
      GOTO_CLEANUP_CROAK("Unsupported key type");
   }

   /* ---------- AES-GCM decrypt the secret using aes_wrap_key ---------- */

   secret_pt = OPENSSL_malloc(secret_ct_len);
   if (!secret_pt)
      GOTO_CLEANUP_CROAK("malloc for plaintext failed");

   aes_ctx = EVP_CIPHER_CTX_new();
   if (!aes_ctx
      || EVP_DecryptInit_ex(aes_ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1
      || EVP_CIPHER_CTX_ctrl(aes_ctx, EVP_CTRL_GCM_SET_IVLEN, (int)nonce_len, NULL) != 1
      || EVP_DecryptInit_ex(aes_ctx, NULL, NULL, aes_wrap_key, nonce) != 1
   )
      GOTO_CLEANUP_CROAK("AES-GCM decrypt init failed");

   if (EVP_DecryptUpdate(aes_ctx, secret_pt, &outlen, secret_ct, (int)secret_ct_len) != 1)
      GOTO_CLEANUP_CROAK("AES-GCM decrypt failed");

   /* Set expected tag */
   if (EVP_CIPHER_CTX_ctrl(aes_ctx, EVP_CTRL_GCM_SET_TAG, (int)gcm_tag_len, gcm_tag) != 1)
      GOTO_CLEANUP_CROAK("AES-GCM set tag failed");

   /* Finalize and verify tag */
   {
      int final_len = 0;
      if (EVP_DecryptFinal_ex(aes_ctx, secret_pt + outlen, &final_len) != 1)
         GOTO_CLEANUP_CROAK("AES-GCM decrypt final failed (authentication failed)");
      outlen += final_len;
   }

   /* Copy decrypted secret to output buffer */
   secret_buffer_set_len(secret_out, (size_t)outlen);
   memcpy(secret_out->data, secret_pt, (size_t)outlen);

cleanup:
   if (shared_secret)
      OPENSSL_clear_free(shared_secret, shared_len);

   OPENSSL_cleanse(aes_wrap_key, sizeof aes_wrap_key);

   if (secret_pt) {
      OPENSSL_cleanse(secret_pt, secret_ct_len);
      OPENSSL_free(secret_pt);
   }

   if (ctx) EVP_PKEY_CTX_free(ctx);
   if (kdf) EVP_PKEY_CTX_free(kdf);
   if (rsa_ctx) EVP_PKEY_CTX_free(rsa_ctx);

   if (ephemeral_pub) EVP_PKEY_free(ephemeral_pub);
   if (aes_ctx) EVP_CIPHER_CTX_free(aes_ctx);

   if (err)
      cmk_croak_with_ssl_error(err);
}

#if 0
void cmk_key_encrypt_privkey(cmk_key *key, secret_buffer *pw, int pbkdf2_iter) {
   EVP_CIPHER_CTX *ctx = NULL;
   unsigned char aes_key[CMK_AES_KEYLEN];

   if (!key->have_privkey)
      croak("Cannot encrypt key when private key isn't loaded");

   if (format == CMK_KEYFORMAT_X25519) {
      if (pbkdf2_iter > 0) {
         /* Derive AES key from password */
         if (RAND_bytes(key->x25519.kdf_salt, sizeof(key->x25519.kdf_salt)) != 1)
            err = "Salt generation failed", goto cleanup;

         if (PKCS5_PBKDF2_HMAC(pw->data, pw->len,
                               key->x25519.kdf_salt, sizeof(key->x25519.kdf_salt),
                               pbkdf2_iter, EVP_sha256(),
                               sizeof(aes_key), aes_key) != 1)
            err = "PBKDF2 failed", goto cleanup;
      } else {
         /* Else pw *is* the AES key */
         if (pw->len != sizeof(aes_key))
            croak("Password must be exactly %d bytes if not using PBKDF2", (int)sizeof(aes_key));
         memcpy(aes_key, pw->data, sizeof(aes_key));
         memset(key->x25519.kdf_salt, 0, sizeof(key->x25519.kdf_salt));
      }

      /* Encrypt private key with AES-256-ECB (no padding) */
      ctx = EVP_CIPHER_CTX_new();
      if (!ctx || EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, aes_key, NULL) != 1)
         err = "EncryptInit failed", goto cleanup;

      if (EVP_CIPHER_CTX_set_padding(ctx, 0) != 1)
         err = "Disabling AES padding failed", goto cleanup;

      if (EVP_EncryptUpdate(ctx, key->x25519.privkey_encrypted, &outlen,
                            key->x25519.privkey, sizeof(key->x25519.privkey)) != 1
          || outlen != sizeof(key->x25519.privkey_encrypted)
      )
         err = "EncryptUpdate failed", goto cleanup;

      if (EVP_EncryptFinal_ex(ctx, key->x25519.privkey_encrypted + outlen, &outlen) != 1)
         err = "EncryptFinal failed", goto cleanup;

      key->x25519.pbkdf2_iterations = pbkdf2_iter;
      key->have_privkey_encrypted = 1;
   } else {
      croak("Unsupported key format");
   }

cleanup:
   OPENSSL_cleanse(aes_key, sizeof(aes_key));
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

void cmk_key_decrypt_privkey(cmk_key *key, secret_buffer *pw) {
   const char *err = NULL;
   int outlen = 0;
   unsigned char aes_key[CMK_AES_KEYLEN];
   EVP_CIPHER_CTX *ctx = NULL;
   EVP_PKEY *pkey = NULL;
   unsigned char derived_pub[CMK_PUBKEY_LEN];
   size_t len = sizeof(derived_pub);

   if (!key || !pw)
      croak("Null argument to cmk_key_decrypt");

   if (!key->have_privkey_encrypted)
      croak("Key object does not contain encrypted private key");

   if (format == CMK_KEYFORMAT_X25519) {
      /* Derive AES key */
      if (key->x25519.pbkdf2_iterations > 0) {
         if (PKCS5_PBKDF2_HMAC(pw->data, pw->len,
                               key->x25519.kdf_salt, sizeof(key->x25519.kdf_salt),
                               key->x25519.pbkdf2_iterations, EVP_sha256(),
                               sizeof(aes_key), aes_key) != 1)
            err = "PBKDF2 failed", goto cleanup;
      } else {
         if (pw->len != sizeof(aes_key))
            croak("Password must be exactly %d bytes when PBKDF2 is not used", (int)sizeof(aes_key));
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

      key->have_privkey = true;
   }
cleanup:
   OPENSSL_cleanse(aes_key, sizeof(aes_key));
   if (ctx) EVP_CIPHER_CTX_free(ctx);
   if (pkey) EVP_PKEY_free(pkey);
   if (err) {
      OPENSSL_cleanse(key->privkey, sizeof(key->privkey));
      key->have_privkey= false;

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

void cmk_key_disable(cmk_key *key) {
   if (!key)
      return;

   OPENSSL_cleanse(key->x25519.privkey, sizeof(key->x25519.privkey));
   key->x25519.decrypted = false;
}

/******************************* Vault API **********************************/

void cmk_vault_create(cmk_vault *vault) {
   if (!vault)
      croak("Null argument to cmk_vault_create");

   memset(vault, 0, sizeof(*vault));

   if (RAND_bytes(vault->aes_key, sizeof(vault->aes_key)) != 1)
      croak("Failed to generate AES key");

   if (RAND_bytes(vault->nonce, sizeof(vault->nonce)) != 1)
      croak("Failed to generate nonce");

   vault->unlocked = true;
   vault->gcm_tag_initialized = false;
}

void cmk_vault_import(cmk_vault *vault, HV *in) {
   SV **sv;

   if (!vault || !in)
      croak("Null argument to cmk_vault_import");

   memset(vault, 0, sizeof(*vault));

   sv = hv_fetchs(in, "nonce", 0);
   if (sv && SvOK(*sv)) {
      STRLEN len;
      const char *data = SvPVbyte(*sv, len);
      if (len == sizeof(vault->nonce))
         memcpy(vault->nonce, data, len);
   }

   sv = hv_fetchs(in, "gcm_tag", 0);
   if (sv && SvOK(*sv)) {
      STRLEN len;
      const char *data = SvPVbyte(*sv, len);
      if (len == sizeof(vault->gcm_tag)) {
         memcpy(vault->gcm_tag, data, len);
         vault->gcm_tag_initialized = true;
      }
   }
}

void cmk_vault_export(cmk_vault *vault, HV *out) {
   if (!vault || !out)
      croak("Null argument to cmk_vault_export");

   hv_stores(out, "nonce", newSVpvn((char*)vault->nonce, sizeof(vault->nonce)));
   hv_stores(out, "gcm_tag", newSVpvn((char*)vault->gcm_tag, sizeof(vault->gcm_tag)));
   if (vault->unlocked)
      hv_stores(out, "aes_key", newSVpvn((char*)vault->aes_key, sizeof(vault->aes_key)));
}

void cmk_vault_lock(cmk_vault *vault) {
   if (!vault)
      return;
   OPENSSL_cleanse(vault->aes_key, sizeof(vault->aes_key));
   vault->unlocked = false;
}

void cmk_vault_destroy(cmk_vault *vault) {
   if (!vault)
      return;
   OPENSSL_cleanse(vault, sizeof(*vault));
}

void cmk_vault_encrypt_buffer(cmk_vault *vault,
                                const secret_buffer *in,
                                secret_buffer *out
) {
   const char *err = NULL;
   int outlen = 0, finallen = 0;
   EVP_CIPHER_CTX *ctx = NULL;

   if (!vault || !in || !out)
      croak("Null argument to cmk_vault_encrypt_buffer");

   if (!vault->unlocked)
      croak("Secret must be unlocked before encryption");

   ctx = EVP_CIPHER_CTX_new();
   if (!ctx)
      err = "Failed to create AES context", goto cleanup;

   if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
      err = "EncryptInit_ex failed", goto cleanup;

   if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                           sizeof(vault->nonce), NULL) != 1)
      err = "Set IV length failed", goto cleanup;

   if (EVP_EncryptInit_ex(ctx, NULL, NULL,
                          vault->aes_key, vault->nonce) != 1)
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
                           sizeof(vault->gcm_tag), vault->gcm_tag) != 1)
      err = "Failed to get GCM tag", goto cleanup;

   vault->gcm_tag_initialized = true;
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

void cmk_vault_decrypt_buffer(cmk_vault *vault,
                                const secret_buffer *in,
                                secret_buffer *out
) {
   const char *err = NULL;
   int outlen = 0, finallen = 0;
   EVP_CIPHER_CTX *ctx = NULL;

   if (!vault || !in || !out)
      croak("Null argument to cmk_vault_decrypt_buffer");

   if (!vault->unlocked)
      croak("Secret must be unlocked before decryption");

   if (!vault->gcm_tag_initialized)
      croak("GCM tag is not initialized in secret");

   ctx = EVP_CIPHER_CTX_new();
   if (!ctx)
      err = "Failed to create AES context", goto cleanup;

   if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
      err = "DecryptInit_ex failed", goto cleanup;

   if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                           sizeof(vault->nonce), NULL) != 1)
      err = "Set IV length failed", goto cleanup;

   if (EVP_DecryptInit_ex(ctx, NULL, NULL,
                          vault->aes_key, vault->nonce) != 1)
      err = "DecryptInit with key/IV failed", goto cleanup;

   secret_buffer_alloc_at_least(out, in->len);
   if (EVP_DecryptUpdate(ctx, (unsigned char*)out->data, &outlen,
                         (unsigned char*)in->data, in->len) != 1 ||
       (size_t)outlen != in->len)
      err = "DecryptUpdate failed", goto cleanup;

   if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,
                           sizeof(vault->gcm_tag), (void *)vault->gcm_tag) != 1)
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

void cmk_key_slot_create(HV *slot, EVP_PKEY *public_key, char *cipher_key, size_t cipher_key_len) {
}


void cmk_key_slot_create(cmk_key_slot *slot,
                         cmk_vault *vault,
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

   if (!slot || !vault || !key)
      croak("Null argument to cmk_key_slot_create");

   if (!key->x25519.decrypted)
      croak("Key must be decrypted before wrapping");

   if (!vault->unlocked)
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
                         vault->aes_key, sizeof(vault->aes_key)) != 1 ||
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

void cmk_vault_unlock(cmk_vault *vault,
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

   if (!vault || !slot || !key)
      croak("Null argument to cmk_vault_unlock");

   if (!key->x25519.decrypted)
      croak("Key must be decrypted to derive AES key");

   if (!slot->gcm_tag || !slot->nonce)
      croak("Locked AES key missing nonce or tag");

   memset(vault, 0, sizeof(*vault));

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
       EVP_DecryptUpdate(aes_ctx, vault->aes_key, &outlen,
                         slot->aes_key_encrypted, sizeof(slot->aes_key_encrypted)) != 1 ||
       outlen != sizeof(vault->aes_key) ||
       EVP_CIPHER_CTX_ctrl(aes_ctx, EVP_CTRL_GCM_SET_TAG, sizeof(slot->gcm_tag), (void *)slot->gcm_tag) != 1 ||
       EVP_DecryptFinal_ex(aes_ctx, NULL, &outlen) != 1)
      err = "Failed to decrypt AES key", goto cleanup;

   memcpy(vault->nonce, slot->nonce, sizeof(vault->nonce));
   memcpy(vault->gcm_tag, slot->gcm_tag, sizeof(vault->gcm_tag));
   vault->unlocked = true;
   vault->gcm_tag_initialized = true;

cleanup:
   OPENSSL_cleanse(shared_secret, sizeof(shared_secret));
   OPENSSL_cleanse(aes_wrap_key, sizeof(aes_wrap_key));
   if (aes_ctx) EVP_CIPHER_CTX_free(aes_ctx);
   if (kex_ctx) EVP_PKEY_CTX_free(kex_ctx);
   if (peer) EVP_PKEY_free(peer);
   if (self) EVP_PKEY_free(self);

   if (err) {
      OPENSSL_cleanse(vault->aes_key, sizeof(vault->aes_key));
      vault->unlocked = false;
      vault->gcm_tag_initialized = false;

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
#endif