#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"
#include "ppport.h"

#include "CryptMultiKey_config.h"

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/pkcs12.h>
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

#define STRINGIFY_MACRO(x) #x
#define GOTO_CLEANUP_CROAK(msg) do { err= msg; goto cleanup; } while(0)

#define CMK_X25519_PUBKEY_LEN 32
#define CMK_X25519_PRIVKEY_LEN 32
#define CMK_AES_NONCE_LEN 12
#define CMK_AES_KEY_LEN 32
#define CMK_GCM_TAG_LEN 16
#define CMK_PBKDF2_SALT_LEN 16
#define CMK_KDF_SALT_LEN 32

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
            if (EVP_PKEY_CTX_set1_rsa_keygen_pubexp(ctx, bignum) <= 0)
               GOTO_CLEANUP_CROAK("EVP_PKEY_CTX_set1_rsa_keygen_pubexp failed");
            BN_free(bignum);
            bignum= NULL;
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
      mg->mg_ptr= (char*) cmk_EVP_PKEY_dup((EVP_PKEY*) mg->mg_ptr);
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

/* Create the 'private_pkcs8' field of the Key object from the 'private' field.
 * The 'private' field is unmodified.
 * Dies on failure.
 */
void cmk_key_encrypt_private(SV *objref, const U8 *pass, size_t pass_len, int kdf_iters) {
   const char *err= NULL;
   HV *hv= (objref && SvROK(objref) && SvTYPE(SvRV(objref)) == SVt_PVHV)? (HV*) SvRV(objref) : NULL;
   EVP_PKEY *pkey= cmk_key_get_privkey(objref);
   PKCS8_PRIV_KEY_INFO *p8inf= NULL;
   X509_SIG *p8= NULL;
   SV *pkcs8_buf= NULL;
   U8 *buf;
   int serialized_len;

   if (!hv)
      croak("Not a Crypt::MultiKey::Key");

   /* Convert EVP_PKEY to PKCS8_PRIV_KEY_INFO */
   p8inf= EVP_PKEY2PKCS8(pkey);
   if (!p8inf)
      GOTO_CLEANUP_CROAK("Failed to convert key to PKCS8 format");

   /* Encrypt with specified iteration count */
   p8= PKCS8_encrypt(
      -1,                          /* use default PKCS#12 PBE algorithm */
      EVP_aes_256_cbc(),           /* cipher */
      (const char *)pass, pass_len,
      NULL, 0,                     /* salt (NULL = auto-generate) */
      kdf_iters,                   /* iteration count */
      p8inf
   );
   if (!p8)
      GOTO_CLEANUP_CROAK("PKCS8 encryption failed");

   /* Serialize to DER format */
   serialized_len= i2d_X509_SIG(p8, NULL);
   if (serialized_len <= 0)
      GOTO_CLEANUP_CROAK("Can't determine PKCS8 serialized length");

   pkcs8_buf= newSVpvs("");
   buf= (U8*) cmk_prepare_sv_buffer(pkcs8_buf, serialized_len);
   if (i2d_X509_SIG(p8, &buf) != serialized_len)
      GOTO_CLEANUP_CROAK("Can't serialize PKCS8");

   /* Store in the hash field */
   if (!hv_stores(hv, "private_pkcs8", pkcs8_buf))
      GOTO_CLEANUP_CROAK("can't set ->{private_pkcs8}");

cleanup:
   if (p8)
      X509_SIG_free(p8);
   if (p8inf)
      PKCS8_PRIV_KEY_INFO_free(p8inf);
   if (err) {
      if (pkcs8_buf) SvREFCNT_dec(pkcs8_buf);
      cmk_croak_with_ssl_error(err);
   }
}

/* Create the 'private' field of the Key object from the 'private_pkcs8' field
 * using the supplied password.
 * Dies on failure.
 */
void cmk_key_decrypt_private(SV *objref, const U8 *pass, size_t pass_len) {
   const char *err= NULL;
   HV *hv= (objref && SvROK(objref) && SvTYPE(SvRV(objref)) == SVt_PVHV)? (HV*) SvRV(objref) : NULL;
   SV **field, *private_ref= NULL;
   secret_buffer *sb= NULL;
   X509_SIG *p8= NULL;
   PKCS8_PRIV_KEY_INFO *p8inf= NULL;
   EVP_PKEY *pkey= NULL, **key_p;
   const U8 *buf;
   U8 *out_buf;
   STRLEN pkcs8_len;
   int serialized_len;

   if (!hv)
      croak("Not a Crypt::MultiKey::Key");

   /* Get the encrypted PKCS8 data */
   field= hv_fetchs(hv, "private_pkcs8", 0);
   if (!(field && *field && SvOK(*field)))
      croak("Missing 'private_pkcs8' attribute");

   buf= (const U8*) SvPVbyte(*field, pkcs8_len);
   if (!pkcs8_len)
      croak("Empty 'private_pkcs8' attribute");

   /* Decode the X509_SIG (encrypted PKCS8) structure */
   if (!d2i_X509_SIG(&p8, &buf, pkcs8_len) || !p8)
      GOTO_CLEANUP_CROAK("Failed to decode PKCS8 structure");

   /* Decrypt to get PKCS8_PRIV_KEY_INFO */
   p8inf= PKCS8_decrypt(p8, (const char *)pass, pass_len);
   if (!p8inf)
      GOTO_CLEANUP_CROAK("PKCS8 decryption failed (wrong password?)");

   /* Convert PKCS8_PRIV_KEY_INFO to EVP_PKEY */
   pkey= EVP_PKCS82PKEY(p8inf);
   if (!pkey)
      GOTO_CLEANUP_CROAK("Failed to convert PKCS8 to EVP_PKEY");

   /* Serialize the private key */
   serialized_len= i2d_PrivateKey(pkey, NULL);
   if (serialized_len <= 0)
      GOTO_CLEANUP_CROAK("Can't serialize private key");

   /* Create SecretBuffer for the private key */
   sb= secret_buffer_new(0, &private_ref);
   secret_buffer_set_len(sb, serialized_len);
   out_buf= sb->data;
   if (i2d_PrivateKey(pkey, &out_buf) != serialized_len)
      GOTO_CLEANUP_CROAK("Can't serialize private key");

   /* Attach the EVP_PKEY to the secret_buffer's wrapper for caching */
   key_p= cmk_EVP_PKEY_p_from_magic(sb->wrapper, 1);
   *key_p= pkey;
   pkey= NULL; /* prevent cleanup below */

   /* Store in the hash field */
   if (!hv_stores(hv, "private", private_ref))
      GOTO_CLEANUP_CROAK("can't set ->{private}");
   SvREFCNT_inc(private_ref); /* was mortal */

cleanup:
   if (pkey)
      EVP_PKEY_free(pkey);
   if (p8inf)
      PKCS8_PRIV_KEY_INFO_free(p8inf);
   if (p8)
      X509_SIG_free(p8);
   if (err)
      cmk_croak_with_ssl_error(err);
}

/* This function encrypts a secret using a public key.  It stores the ciphertext and all
 * parameters required for decryption into the "slot" hash.
 * For RSA keys, this generates an AES wrapper key, encrypts the secret with the wrapper,
 * and then encrypts the wrapper key using RSA.
 * For DSA-like key types, this creates an ephemeral key, derives the shared secret,
 * uses the shared secret to encrypt the secret, then stores the public half of the ephemeral
 * key along side the other fields.
 */
void cmk_key_encrypt(EVP_PKEY *public_key, const U8 *secret, size_t secret_len, HV *enc_out) {
   secret_buffer *aes_key= cmk_key_create_aes_key(public_key, enc_out);
   cmk_aes_encrypt(aes_key, secret, secret_len, enc_out);
   /* aes_key is mortal */
}

secret_buffer *
cmk_key_create_aes_key(EVP_PKEY *public_key, HV *enc_out) {
   const char *err = NULL;
   EVP_PKEY *ephemeral = NULL;
   EVP_PKEY_CTX *pctx = NULL;
   EVP_PKEY_CTX *ctx = NULL;
   EVP_PKEY_CTX *kdf = NULL;
   EVP_PKEY_CTX *rsa_ctx = NULL;
   U8 *shared_secret = NULL;
   size_t shared_len = 0;
   SV *sv= NULL;
   secret_buffer *aes_key= secret_buffer_new(0, NULL);
   int type= EVP_PKEY_base_id(public_key);

   /* RSA keys encrypt/decrypt directly, but DSA-style keys need to create an ephermeral
    * key to perform a handshake with, to produce a shared secret.
    */
   if (type == EVP_PKEY_X25519 || type == EVP_PKEY_X448
    || type == EVP_PKEY_EC     || type == EVP_PKEY_DH
   ) {
      U8 kdf_salt[CMK_KDF_SALT_LEN];
      U8 *ephemeral_pub;    /* DER ephemeral pub for X25519 */
      int ephemeral_pub_len;

      /* Generate ephemeral keypair of same type */
      pctx = EVP_PKEY_CTX_new_id(type, NULL);
      if (!pctx ||
         EVP_PKEY_keygen_init(pctx) <= 0 ||
         EVP_PKEY_keygen(pctx, &ephemeral) <= 0
      )
         GOTO_CLEANUP_CROAK("Ephemeral key generation failed");

      /* Derive shared secret: ephemeral (private) + MultiKey::Key object (public) */
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

      /* HKDF(shared_secret) -> aes_wrap_key */
      if (RAND_bytes(kdf_salt, sizeof kdf_salt) != 1)
         GOTO_CLEANUP_CROAK("Salt generation failed");

      secret_buffer_set_len(aes_key, CMK_AES_KEY_LEN);
      kdf = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
      if (!kdf
         || EVP_PKEY_derive_init(kdf) <= 0
         || EVP_PKEY_CTX_set_hkdf_md(kdf, EVP_sha256()) <= 0
         || EVP_PKEY_CTX_set1_hkdf_salt(kdf, kdf_salt, sizeof kdf_salt) <= 0
         || EVP_PKEY_CTX_set1_hkdf_key(kdf, shared_secret, shared_len) <= 0
         || EVP_PKEY_CTX_add1_hkdf_info(kdf, (unsigned char *)"cmk-wrap", 8) <= 0
         || EVP_PKEY_derive(kdf, aes_key->data, &(size_t){ CMK_AES_KEY_LEN }) <= 0
      )
         GOTO_CLEANUP_CROAK("HKDF failed");

      /* DER-encode ephemeral public key (SPKI) for storage */
      if ((ephemeral_pub_len = i2d_PUBKEY(ephemeral, NULL)) <= 0)
         GOTO_CLEANUP_CROAK("i2d_PUBKEY (size) failed");
      ephemeral_pub= (U8*) cmk_prepare_sv_buffer((sv= newSVpvs("")), ephemeral_pub_len);
      if (i2d_PUBKEY(ephemeral, &ephemeral_pub) != ephemeral_pub_len)
         GOTO_CLEANUP_CROAK("i2d_PUBKEY failed");

      /* Store AES Key, KDF salt, and public half of ephemeral key */
      if (!hv_stores(enc_out, "ephemeral_pubkey", sv)
         || !hv_stores(enc_out, "kdf_salt",       sv= newSVpvn(kdf_salt, sizeof kdf_salt)))
         GOTO_CLEANUP_CROAK("hv_store failed");
      sv= NULL; /* HV takes ownership */
   }
   else if (type == EVP_PKEY_RSA || type == EVP_PKEY_RSA_PSS) {
      size_t rsa_ct_len= 0;
      /* ---- RSA branch (RSA-OAEP) ---- */

      /* Generate random wrap key */
      secret_buffer_set_len(aes_key, CMK_AES_KEY_LEN);
      if (RAND_bytes(aes_key->data, aes_key->len) != 1)
         GOTO_CLEANUP_CROAK("RAND_bytes for wrap key failed");

      /* 2. RSA-OAEP encrypt wrap key with public_key */
      rsa_ctx = EVP_PKEY_CTX_new(public_key, NULL);
      if (!rsa_ctx
         || EVP_PKEY_encrypt_init(rsa_ctx) <= 0
         || EVP_PKEY_CTX_set_rsa_padding(rsa_ctx, RSA_PKCS1_OAEP_PADDING) <= 0
         || EVP_PKEY_CTX_set_rsa_oaep_md(rsa_ctx, EVP_sha256()) <= 0
         || EVP_PKEY_CTX_set_rsa_mgf1_md(rsa_ctx, EVP_sha256()) <= 0)
         GOTO_CLEANUP_CROAK("RSA encrypt init failed");

      if (EVP_PKEY_encrypt(rsa_ctx, NULL, &rsa_ct_len, aes_key->data, aes_key->len) <= 0
         || rsa_ct_len == 0)
         GOTO_CLEANUP_CROAK("RSA encrypt size query failed");

      if (EVP_PKEY_encrypt(rsa_ctx, cmk_prepare_sv_buffer((sv= newSVpvs("")), rsa_ct_len),
            &rsa_ct_len, aes_key->data, aes_key->len) <= 0)
         GOTO_CLEANUP_CROAK("RSA encrypt failed");

      /* Store encrypted aes_key */
      if (!hv_stores(enc_out, "rsa_key_ciphertext", sv))
         GOTO_CLEANUP_CROAK("hv_store failed");
      sv= NULL; /* HV takes ownership */
   }
   else {
      GOTO_CLEANUP_CROAK("Unsupported key type");
   }

cleanup:
   if (shared_secret)
      OPENSSL_clear_free(shared_secret, shared_len);

   if (ctx) EVP_PKEY_CTX_free(ctx);
   if (kdf) EVP_PKEY_CTX_free(kdf);
   if (pctx) EVP_PKEY_CTX_free(pctx);
   if (rsa_ctx) EVP_PKEY_CTX_free(rsa_ctx);
   if (ephemeral) EVP_PKEY_free(ephemeral);
   if (sv) /* if hv_stores fails, the thing we tried to store needs freed */
      SvREFCNT_dec(sv);
   if (err) cmk_croak_with_ssl_error(err);
   return aes_key;
}

/* This function decrypts a secret from a key slot using a private key.
 * It reverses the process of cmk_key_slot_create by:
 * - For RSA keys: decrypting the wrapper key, then using it to decrypt the secret
 * - For DSA-like keys: deriving the shared secret from the ephemeral public key,
 *   then using it to decrypt the secret
 */
void cmk_key_decrypt(EVP_PKEY *private_key, HV *enc_in, secret_buffer *secret_out) {
   secret_buffer *aes_key= cmk_key_recreate_aes_key(private_key, enc_in);
   cmk_aes_decrypt(aes_key, enc_in, secret_out);
   /* aes_key is mortal */
}

secret_buffer *
cmk_key_recreate_aes_key(EVP_PKEY *private_key, HV *enc) {
   const char *err = NULL;
   EVP_PKEY *ephemeral_pub = NULL;
   EVP_PKEY_CTX *ctx = NULL;
   EVP_PKEY_CTX *kdf = NULL;
   EVP_PKEY_CTX *rsa_ctx = NULL;
   U8 *shared_secret = NULL;
   size_t shared_len;
   SV **svp;
   secret_buffer *aes_key= secret_buffer_new(0, NULL);
   int type = EVP_PKEY_base_id(private_key);

   /* Determine key type and decrypt accordingly */
   if (type == EVP_PKEY_X25519 || type == EVP_PKEY_X448
    || type == EVP_PKEY_EC     || type == EVP_PKEY_DH
   ) {
      STRLEN ephemeral_pub_der_len, kdf_salt_len;
      U8 *ephemeral_pub_der, *kdf_salt;
      const U8 *p;
      /* ---- DSA-like branch: derive shared secret from ephemeral public key ---- */

      /* Extract ephemeral public key and KDF salt */
      svp = hv_fetchs(enc, "kdf_salt", 0);
      if (!svp || !*svp || !SvOK(*svp))
         GOTO_CLEANUP_CROAK("Missing kdf_salt");
      kdf_salt = (U8*)secret_buffer_SvPVbyte(*svp, &kdf_salt_len);
      if (kdf_salt_len != CMK_KDF_SALT_LEN)
         GOTO_CLEANUP_CROAK("Invalid kdf_salt length");

      svp = hv_fetchs(enc, "ephemeral_pubkey", 0);
      if (!svp || !*svp || !SvOK(*svp))
         GOTO_CLEANUP_CROAK("Missing ephemeral_pubkey");
      ephemeral_pub_der = (U8*)secret_buffer_SvPVbyte(*svp, &ephemeral_pub_der_len);

      /* Decode ephemeral public key from DER */
      p = ephemeral_pub_der;  /* d2i advances the pointer */
      ephemeral_pub = d2i_PUBKEY(NULL, &p, ephemeral_pub_der_len);
      if (!ephemeral_pub)
         GOTO_CLEANUP_CROAK("Failed to decode ephemeral public key");

      /* Derive shared secret: private_key + ephemeral_pub */
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

      /* HKDF(shared_secret) -> aes_key */
      secret_buffer_set_len(aes_key, CMK_AES_KEY_LEN);
      kdf = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
      if (!kdf ||
         EVP_PKEY_derive_init(kdf) <= 0 ||
         EVP_PKEY_CTX_set_hkdf_md(kdf, EVP_sha256()) <= 0 ||
         EVP_PKEY_CTX_set1_hkdf_salt(kdf, kdf_salt, kdf_salt_len) <= 0 ||
         EVP_PKEY_CTX_set1_hkdf_key(kdf, shared_secret, shared_len) <= 0 ||
         EVP_PKEY_CTX_add1_hkdf_info(kdf, (unsigned char *)"cmk-wrap", 8) <= 0 ||
         EVP_PKEY_derive(kdf, aes_key->data, &(size_t){ CMK_AES_KEY_LEN }) <= 0
      )
         GOTO_CLEANUP_CROAK("HKDF failed");
   }
   else if (type == EVP_PKEY_RSA || type == EVP_PKEY_RSA_PSS) {
      STRLEN rsa_ct_len;
      U8 *rsa_ct;
      size_t decoded_len;
      /* ---- RSA branch: decrypt wrap key using RSA-OAEP ---- */

      /* Extract encrypted wrap key */
      svp = hv_fetchs(enc, "rsa_key_ciphertext", 0);
      if (!svp || !*svp || !SvOK(*svp))
         GOTO_CLEANUP_CROAK("Missing rsa_key_ciphertext");
      rsa_ct = (U8*)secret_buffer_SvPVbyte(*svp, &rsa_ct_len);

      /* RSA-OAEP decrypt to get wrap key */
      rsa_ctx = EVP_PKEY_CTX_new(private_key, NULL);
      if (!rsa_ctx
         || EVP_PKEY_decrypt_init(rsa_ctx) <= 0
         || EVP_PKEY_CTX_set_rsa_padding(rsa_ctx, RSA_PKCS1_OAEP_PADDING) <= 0
         || EVP_PKEY_CTX_set_rsa_oaep_md(rsa_ctx, EVP_sha256()) <= 0
         || EVP_PKEY_CTX_set_rsa_mgf1_md(rsa_ctx, EVP_sha256()) <= 0)
         GOTO_CLEANUP_CROAK("RSA decrypt init failed");

      /* Oddly, this wants a larger size for the buffer, but on the second call it
       * returns the correct number of bytes decoded...  So need to allocate the SecretBuffer
       * larger and then shrink it.
       */
      if (EVP_PKEY_decrypt(rsa_ctx, NULL, &decoded_len, rsa_ct, rsa_ct_len) <= 0)
         GOTO_CLEANUP_CROAK("RSA encrypt size query failed");
      secret_buffer_set_len(aes_key, decoded_len);

      if (EVP_PKEY_decrypt(rsa_ctx, aes_key->data, &decoded_len, rsa_ct, rsa_ct_len) <= 0)
         GOTO_CLEANUP_CROAK("RSA decrypt failed");
      if (decoded_len != CMK_AES_KEY_LEN)
         GOTO_CLEANUP_CROAK("RSA decrypt returned wrong number of bytes?");
      secret_buffer_set_len(aes_key, decoded_len);
   }
   else {
      GOTO_CLEANUP_CROAK("Unsupported key type");
   }

cleanup:
   if (shared_secret) OPENSSL_clear_free(shared_secret, shared_len);
   if (ctx) EVP_PKEY_CTX_free(ctx);
   if (kdf) EVP_PKEY_CTX_free(kdf);
   if (rsa_ctx) EVP_PKEY_CTX_free(rsa_ctx);
   if (ephemeral_pub) EVP_PKEY_free(ephemeral_pub);
   if (err) cmk_croak_with_ssl_error(err);
   return aes_key;
}

/* Perform symmetric encryption using the supplied AES key, storing the ciphertext and parameters
 * into the hash `enc_out`.
 */
void cmk_aes_encrypt(secret_buffer *aes_key, const U8 *secret, size_t secret_len, HV *enc_out) {
   const char *err= NULL;
   EVP_CIPHER_CTX *aes_ctx = NULL;
   U8 nonce[CMK_AES_NONCE_LEN];
   U8 gcm_tag[CMK_GCM_TAG_LEN];
   SV *sv= NULL;
   U8 *ciphertext;
   int outlen;

   if (aes_key->len != CMK_AES_KEY_LEN)
      croak("AES Key must be " STRINGIFY_MACRO(CMK_AES_KEY_LEN) " bytes");

   if (RAND_bytes(nonce, sizeof nonce) != 1)
      GOTO_CLEANUP_CROAK("Failed to generate GCM nonce");

   ciphertext= cmk_prepare_sv_buffer((sv= newSVpvs("")), secret_len);

   aes_ctx = EVP_CIPHER_CTX_new();
   if (!aes_ctx
      || EVP_EncryptInit_ex(aes_ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1
      || EVP_CIPHER_CTX_ctrl(aes_ctx, EVP_CTRL_GCM_SET_IVLEN, (int)sizeof(nonce), NULL) != 1
      || EVP_EncryptInit_ex(aes_ctx, NULL, NULL, aes_key->data, nonce) != 1)
      GOTO_CLEANUP_CROAK("AES-GCM init failed");

   if (EVP_EncryptUpdate(aes_ctx, ciphertext, &outlen, secret, (int)secret_len) != 1
      || (size_t)outlen != secret_len)
      GOTO_CLEANUP_CROAK("AES-GCM encrypt failed");

   if (EVP_EncryptFinal_ex(aes_ctx, NULL, &outlen) != 1)
      GOTO_CLEANUP_CROAK("AES-GCM final failed");

   if (EVP_CIPHER_CTX_ctrl(aes_ctx, EVP_CTRL_GCM_GET_TAG, (int)sizeof(gcm_tag), gcm_tag) != 1)
      GOTO_CLEANUP_CROAK("AES-GCM get tag failed");

   /* Save results into fields of enc_out.  If hv_store fails, 'sv' needs freed */
   if (  !hv_stores(enc_out, "ciphertext",    sv)
      || !hv_stores(enc_out, "cipher",        sv= newSVpvs("AES-256-GCM"))
      || !hv_stores(enc_out, "aes_gcm_nonce", sv= newSVpvn(nonce, sizeof nonce))
      || !hv_stores(enc_out, "aes_gcm_tag",   sv= newSVpvn(gcm_tag, sizeof gcm_tag)))
      GOTO_CLEANUP_CROAK("failed to write output hash keys");
   sv= NULL;

cleanup:
   if (sv) SvREFCNT_dec(sv);
   if (aes_ctx) EVP_CIPHER_CTX_free(aes_ctx);
   if (err) cmk_croak_with_ssl_error(err);
}

/* Perform symmetric decryption using the supplied AES key and ciphertext and parameters in enc_in,
 * storing the original secret into secret_out.
 */
void cmk_aes_decrypt(secret_buffer *aes_key, HV *enc_in, secret_buffer *secret_out) {
   const char *err= NULL;
   EVP_CIPHER_CTX *aes_ctx = NULL;
   U8 nonce[CMK_AES_NONCE_LEN];
   U8 gcm_tag[CMK_GCM_TAG_LEN];
   U8 *buf;
   int outlen, final_len;
   STRLEN len;
   SV **svp;

   svp= hv_fetchs(enc_in, "cipher", 0);
   if (!svp || !*svp || !SvOK(*svp))
      croak("Missing 'cipher'");
   buf= (U8*) secret_buffer_SvPVbyte(*svp, &len);
   if (len != 11 || memcmp(buf, "AES-256-GCM", 11) != 0)
      croak("'cipher' must be AES-256-GCM");

   if (aes_key->len != CMK_AES_KEY_LEN)
      croak("AES Key must be " STRINGIFY_MACRO(CMK_AES_KEY_LEN) " bytes");

   svp= hv_fetchs(enc_in, "aes_gcm_nonce", 0);
   if (!svp || !*svp || !SvOK(*svp))
      croak("Missing 'aes_gcm_nonce'");
   buf= (U8*) secret_buffer_SvPVbyte(*svp, &len);
   if (len != sizeof(nonce))
      croak("'aes_gcm_nonce' must be " STRINGIFY_MACRO(CMK_AES_NONCE_LEN) " bytes");
   memcpy(nonce, buf, sizeof(nonce));

   svp= hv_fetchs(enc_in, "aes_gcm_tag", 0);
   if (!svp || !*svp || !SvOK(*svp))
      croak("Missing 'aes_gcm_tag'");
   buf= (U8*) secret_buffer_SvPVbyte(*svp, &len);
   if (len != sizeof(gcm_tag))
      croak("'aes_gcm_tag' must be " STRINGIFY_MACRO(CMK_AES_GCM_TAG_LEN) " bytes");
   memcpy(gcm_tag, buf, sizeof(gcm_tag));

   svp= hv_fetchs(enc_in, "ciphertext", 0);
   if (!svp || !*svp || !SvOK(*svp))
      croak("Missing 'ciphertext'");
   buf= (U8*) secret_buffer_SvPVbyte(*svp, &len);
   secret_buffer_set_len(secret_out, len);
   
   aes_ctx = EVP_CIPHER_CTX_new();
   if (!aes_ctx
      || EVP_DecryptInit_ex(aes_ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1
      || EVP_CIPHER_CTX_ctrl(aes_ctx, EVP_CTRL_GCM_SET_IVLEN, (int)sizeof(nonce), NULL) != 1
      || EVP_DecryptInit_ex(aes_ctx, NULL, NULL, aes_key->data, nonce) != 1
   )
      GOTO_CLEANUP_CROAK("AES-GCM decrypt init failed");

   if (EVP_DecryptUpdate(aes_ctx, secret_out->data, &outlen, buf, (int)len) != 1)
      GOTO_CLEANUP_CROAK("AES-GCM decrypt failed");

   /* Set expected tag */
   if (EVP_CIPHER_CTX_ctrl(aes_ctx, EVP_CTRL_GCM_SET_TAG, (int)sizeof(gcm_tag), gcm_tag) != 1)
      GOTO_CLEANUP_CROAK("AES-GCM set tag failed");

   /* Finalize and verify tag */
   final_len = 0;
   if (EVP_DecryptFinal_ex(aes_ctx, secret_out->data + outlen, &final_len) != 1)
      GOTO_CLEANUP_CROAK("AES-GCM decrypt failed, gcm_tag mismatch");
   outlen += final_len;
   if (outlen != secret_out->len)
      GOTO_CLEANUP_CROAK("AES-GCM decrypt produced incorrect secret length");

cleanup:
   if (aes_ctx) EVP_CIPHER_CTX_free(aes_ctx);
   if (err) cmk_croak_with_ssl_error(err);
}
