#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"
#define NEED_mg_findext
#include "ppport.h"

#include "CryptMultiKey_config.h"
#include <openssl/x509.h>
#include "cmk_fido2.h"

#define GOTO_CLEANUP_CROAK(msg) do { err= msg; goto cleanup; } while(0)

extern MAGIC* cmk_get_X_magic(pTHX_ SV *obj, int flags, const MGVTBL *mg_vtbl, const char *mg_desc);

static SV *new_fido2_err_dualvar(int err_code);
static bool cmk_es256_spki_from_fido_cred(const fido_cred_t *cred, U8 **der_out, int *der_len_out);
static es256_pk_t *cmk_es256_pk_from_spki_der(const U8 *der, size_t der_len);


/* Return AV (which caller must free) of the available FIDO2 devices. */
AV *
cmk_fido2_list_devices() {
   AV *ret= NULL;
   fido_dev_info_t *devlist= NULL;
   size_t max_devices= 64, count= 0, i;
   int rc;

   fido_init(0);
   devlist= fido_dev_info_new(max_devices);
   if (!devlist)
      croak("fido_dev_info_new failed");

   rc= fido_dev_info_manifest(devlist, max_devices, &count);
   if (rc != FIDO_OK) {
      fido_dev_info_free(&devlist, max_devices);
      croak("fido_dev_info_manifest failed: %s", fido_strerr(rc));
   }

   ret= newAV();
   for (i= 0; i < count; i++) {
      const fido_dev_info_t *info= fido_dev_info_ptr(devlist, i);
      if (info) {
         fido_dev_t *dev= fido_dev_new_with_info(info);
         if (fido_dev_open_with_info(dev) == FIDO_OK) {
            SV *objref= cmk_fido2_wrap_dev(dev);
            cmk_fido2_dev_load_info_attrs(objref, info);
            av_push(ret, objref);
         } else {
            fido_dev_free(&dev);
         }
      }
   }

   fido_dev_info_free(&devlist, max_devices);
   return ret;
}

void
cmk_fido2_dev_load_info_attrs(SV *dev_objref, const fido_dev_info_t *info) {
   HV *hv= (HV*) SvRV(dev_objref);
   const char *str;
   if ((str= fido_dev_info_path(info)) && *str)
      hv_stores(hv, "path", newSVpv(str, 0));
   if ((str= fido_dev_info_manufacturer_string(info)) && *str)
      hv_stores(hv, "manufacturer", newSVpv(str, 0));
   if ((str= fido_dev_info_product_string(info)) && *str)
      hv_stores(hv, "product", newSVpv(str, 0));
   hv_stores(hv, "product_id", newSViv(fido_dev_info_product(info)));
   hv_stores(hv, "vendor_id", newSViv(fido_dev_info_vendor(info)));
}

HV*
cmk_fido2_dev_load_cbor_attrs(SV *dev_objref) {
   const char *err = NULL;
   fido_cbor_info_t *info = NULL;
   fido_dev_t *dev = cmk_fido2_dev_from_magic(dev_objref, CMK_MAGIC_OR_DIE);
   HV *hv= NULL, *obj_hv = (HV *)SvRV(dev_objref);
   SV **el= hv_fetchs(obj_hv, "_cbor_attrs", 0);
   size_t len, i;
   int rc = 0;

   /* return existing hashref */
   if (el && *el && SvROK(*el) && SvTYPE(SvRV(*el)) == SVt_PVHV)
      return (HV*) SvRV(*el);
   /* else we need to build it */

   if ((info = fido_cbor_info_new()) == NULL)
      croak("fido_cbor_info_new failed");

   if ((rc = fido_dev_get_cbor_info(dev, info)) != FIDO_OK)
      GOTO_CLEANUP_CROAK("fido_dev_get_cbor_info");

   hv= newHV();
   /* aaguid: raw 16-byte value */
   if (fido_cbor_info_aaguid_ptr(info) &&
       (len = fido_cbor_info_aaguid_len(info)) > 0) {
      hv_stores(hv, "aaguid",
         newSVpvn((const char *)fido_cbor_info_aaguid_ptr(info), len));
   }

   /* extensions: arrayref[string] */
   if (fido_cbor_info_extensions_ptr(info) &&
       (len = fido_cbor_info_extensions_len(info)) > 0) {
      AV *av = newAV();
      char **ptr = fido_cbor_info_extensions_ptr(info);
      for (i = 0; i < len; i++)
         av_push(av, newSVpv(ptr[i] ? ptr[i] : "", 0));
      hv_stores(hv, "extensions", newRV_noinc((SV *)av));
   }

   /* protocols: arrayref[int] (PIN protocol versions) */
   if (fido_cbor_info_protocols_ptr(info) &&
       (len = fido_cbor_info_protocols_len(info)) > 0) {
      AV *av = newAV();
      const uint8_t *ptr = fido_cbor_info_protocols_ptr(info);
      for (i = 0; i < len; i++)
         av_push(av, newSViv((IV)ptr[i]));
      hv_stores(hv, "protocols", newRV_noinc((SV *)av));
   }

   /* transports: arrayref[string] */
   if (fido_cbor_info_transports_ptr(info) &&
       (len = fido_cbor_info_transports_len(info)) > 0) {
      AV *av = newAV();
      char **ptr = fido_cbor_info_transports_ptr(info);
      for (i = 0; i < len; i++)
         av_push(av, newSVpv(ptr[i] ? ptr[i] : "", 0));
      hv_stores(hv, "transports", newRV_noinc((SV *)av));
   }

   /* versions: arrayref[string] */
   if (fido_cbor_info_versions_ptr(info) &&
       (len = fido_cbor_info_versions_len(info)) > 0) {
      AV *av = newAV();
      char **ptr = fido_cbor_info_versions_ptr(info);
      for (i = 0; i < len; i++)
         av_push(av, newSVpv(ptr[i] ? ptr[i] : "", 0));
      hv_stores(hv, "versions", newRV_noinc((SV *)av));
   }

   /* options: hashref{name => bool} */
   if (fido_cbor_info_options_name_ptr(info) &&
       fido_cbor_info_options_value_ptr(info) &&
       (len = fido_cbor_info_options_len(info)) > 0) {
      HV *opt_hv = newHV();
      char **names = fido_cbor_info_options_name_ptr(info);
      const bool *vals = fido_cbor_info_options_value_ptr(info);
      for (i = 0; i < len; i++) {
         if (names[i])
            hv_store(opt_hv, names[i], (I32)strlen(names[i]),
               newSViv(vals[i] ? 1 : 0), 0);
      }
      hv_stores(hv, "options", newRV_noinc((SV *)opt_hv));
   }

   /* algorithms: arrayref[{ type => "...", cose => N }] */
   len = fido_cbor_info_algorithm_count(info);
   if (len > 0) {
      AV *av = newAV();
      for (i = 0; i < len; i++) {
         HV *alg_hv = newHV();
         const char *type = fido_cbor_info_algorithm_type(info, i);
         int cose = fido_cbor_info_algorithm_cose(info, i);

         if (type)
            hv_stores(alg_hv, "type", newSVpv(type, 0));
         hv_stores(alg_hv, "cose", newSViv((IV)cose));

         av_push(av, newRV_noinc((SV *)alg_hv));
      }
      hv_stores(hv, "algorithms", newRV_noinc((SV *)av));
   }

   /* certifications: hashref{name => uint64} */
   if (fido_cbor_info_certs_name_ptr(info) &&
       fido_cbor_info_certs_value_ptr(info) &&
       (len = fido_cbor_info_certs_len(info)) > 0) {
      HV *cert_hv = newHV();
      char **names = fido_cbor_info_certs_name_ptr(info);
      const uint64_t *vals = fido_cbor_info_certs_value_ptr(info);
      for (i = 0; i < len; i++) {
         if (names[i])
            hv_store(cert_hv, names[i], (I32)strlen(names[i]),
               newSVuv((UV)vals[i]), 0);
      }
      hv_stores(hv, "certifications", newRV_noinc((SV *)cert_hv));
   }

   /* scalar numeric / boolean fields */
   hv_stores(hv, "maxmsgsiz",
      newSVuv((UV)fido_cbor_info_maxmsgsiz(info)));
   hv_stores(hv, "maxcredbloblen",
      newSVuv((UV)fido_cbor_info_maxcredbloblen(info)));
   hv_stores(hv, "maxcredcntlst",
      newSVuv((UV)fido_cbor_info_maxcredcntlst(info)));
   hv_stores(hv, "maxcredidlen",
      newSVuv((UV)fido_cbor_info_maxcredidlen(info)));
   hv_stores(hv, "maxlargeblob",
      newSVuv((UV)fido_cbor_info_maxlargeblob(info)));
   hv_stores(hv, "maxrpid_minpinlen",
      newSVuv((UV)fido_cbor_info_maxrpid_minpinlen(info)));
   hv_stores(hv, "minpinlen",
      newSVuv((UV)fido_cbor_info_minpinlen(info)));
   hv_stores(hv, "fwversion",
      newSVuv((UV)fido_cbor_info_fwversion(info)));
   hv_stores(hv, "uv_attempts",
      newSVuv((UV)fido_cbor_info_uv_attempts(info)));
   hv_stores(hv, "uv_modality",
      newSVuv((UV)fido_cbor_info_uv_modality(info)));
   hv_stores(hv, "rk_remaining",
      newSViv((IV)fido_cbor_info_rk_remaining(info)));
   hv_stores(hv, "new_pin_required",
      newSViv(fido_cbor_info_new_pin_required(info) ? 1 : 0));

   hv_stores(obj_hv, "_cbor_attrs", newRV_noinc((SV*)hv));
cleanup:
   if (info)
      fido_cbor_info_free(&info);
   if (err) {
      if (hv)
         SvREFCNT_dec((SV*)hv);
      if (rc) {
         cmk_fido2_set_last_err(dev_objref, rc);
         croak("%s: %s", err, fido_strerr(rc));
      }
      croak("%s", err);
   }
   return hv;
}

/* Request a FIDO2 device to create a new credential */
SV *
cmk_fido2_make_credential(SV *dev_objref, const char *pin,
  bool discoverable,
  const char *rp_domain, const char *rp_name,
  const char *user_name, const char *user_display_name, const char *user_icon
) {
   const char *err= NULL;
   fido_dev_t *dev = cmk_fido2_dev_from_magic(dev_objref, CMK_MAGIC_OR_DIE);
   unsigned char user_id[32];
   unsigned char clientdata_hash[32];
   EVP_MD_CTX *mdctx = NULL;
   fido_cred_t *cred = NULL;
   const unsigned char *cred_id_ptr = NULL;
   size_t cred_id_len = 0;
   unsigned char *spki_der = NULL;
   int spki_der_len = 0;
   int rc = FIDO_ERR_INTERNAL;
   bool ok = false;
   HV *out= NULL;

   if (!dev || !rp_domain || !rp_name || !user_name || !user_display_name)
      croak("cmk_fido2_make_credential: null parameter");

   /*
    * Stable opaque user id. This is credential metadata, not a secret.
    */
   mdctx = EVP_MD_CTX_new();
   if (!mdctx)
      croak("EVP_MD_CTX_new failed");
   if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1
    || EVP_DigestUpdate(mdctx, user_name, strlen(user_name)) != 1
    || EVP_DigestFinal_ex(mdctx, user_id, NULL) != 1) {
      EVP_MD_CTX_free(mdctx);
      croak("failed to derive fido2 user id");
   }
   EVP_MD_CTX_free(mdctx);
   mdctx = NULL;

   /*
    * In direct CTAP usage here, we are not using WebAuthn origin/challenge
    * semantics or attestation verification for makeCredential. libfido2/CTAP
    * still require a clientDataHash parameter, but its specific value is not
    * used by this module, so zeroes are sufficient.
    */
   memset(clientdata_hash, 0, sizeof(clientdata_hash));

   if (!(cred = fido_cred_new()))
      GOTO_CLEANUP_CROAK("fido_cred_new failed");

   rc = fido_cred_set_type(cred, COSE_ES256);
   if (rc != FIDO_OK)
      GOTO_CLEANUP_CROAK("fido_cred_set_type(COSE_ES256) failed");

   rc = fido_cred_set_rp(cred, rp_domain, rp_name);
   if (rc != FIDO_OK)
      GOTO_CLEANUP_CROAK("fido_cred_set_rp failed");

   rc = fido_cred_set_user(cred,
      user_id, sizeof(user_id),
      user_name,
      user_display_name,
      user_icon
   );
   if (rc != FIDO_OK)
      GOTO_CLEANUP_CROAK("fido_cred_set_user failed");

   rc = fido_cred_set_rk(cred, discoverable ? FIDO_OPT_TRUE : FIDO_OPT_FALSE);
   if (rc != FIDO_OK)
      GOTO_CLEANUP_CROAK("fido_cred_set_rk failed");

   rc = fido_cred_set_extensions(cred, FIDO_EXT_HMAC_SECRET);
   if (rc != FIDO_OK)
      GOTO_CLEANUP_CROAK("fido_cred_set_extensions(FIDO_EXT_HMAC_SECRET) failed");

   rc = fido_cred_set_clientdata_hash(cred, clientdata_hash, sizeof(clientdata_hash));
   if (rc != FIDO_OK)
      GOTO_CLEANUP_CROAK("fido_cred_set_clientdata_hash failed");

   rc = fido_dev_make_cred(dev, cred, NULL);
   if (rc != FIDO_OK)
      GOTO_CLEANUP_CROAK("fido_dev_make_cred failed");

   cred_id_ptr = fido_cred_id_ptr(cred);
   cred_id_len = fido_cred_id_len(cred);
   if (!cred_id_ptr || cred_id_len == 0)
      GOTO_CLEANUP_CROAK("libfido2 returned success but no credential id");

   if (!cmk_es256_spki_from_fido_cred(cred, &spki_der, &spki_der_len))
      GOTO_CLEANUP_CROAK("libfido2 returned success but public key conversion failed");

   out= newHV();
   hv_stores(out, "id", newSVpvn(cred_id_ptr, cred_id_len));
   hv_stores(out, "pubkey", newSVpvn(spki_der, (size_t)spki_der_len));
   hv_stores(out, "cose_alg", newSVpvs("ES256"));

cleanup:
   if (spki_der)
      OPENSSL_free(spki_der);
   if (cred)
      fido_cred_free(&cred);
   if (err) {
      if (rc != FIDO_OK) {
         cmk_fido2_set_last_err(dev_objref, rc);
         croak("%s: %s", err, cmk_fido2_err_name(rc));
      }
      croak("%s", err);
   }

   return newRV_noinc((SV*)out);
}

/* Perform challenge/response using hmac-secret API of the FIDO2 protocol.
 * This can supply multiple credentials and succeed if any of them are the correct credential
 *   for this hardware authenticator.
 */

typedef struct {
   const U8 *id, *pubkey;
   STRLEN id_len, pubkey_len;
   int cose_alg;
} cmk_fido_cred_attrs;

int
cmk_fido2_assert_hmac_secret(SV *dev_objref, const char *pin,
   const char *rp_domain, AV *credentials, const U8 *salt, size_t salt_len,
   secret_buffer *out
) {
   const char *err= NULL;
   fido_dev_t *dev = cmk_fido2_dev_from_magic(dev_objref, CMK_MAGIC_OR_DIE);
   char err_buf[256];
   unsigned char clientdata_hash[32];
   fido_assert_t *assert = NULL;
   int rc = FIDO_ERR_INTERNAL;
   int matched = -1;
   SSize_t ncred, i;
   size_t nstmt, stmt_idx;
   cmk_fido_cred_attrs *cred= NULL;

   if (!dev || !rp_domain || !credentials || !salt || salt_len == 0 || !out)
      croak("cmk_fido2_try_all_assert_hmac_secret: null or empty parameter");

   memset(clientdata_hash, 0, sizeof(clientdata_hash));

   ncred = av_len(credentials) + 1;
   if (ncred <= 0)
      return -1;
   Newxz(cred, ncred, cmk_fido_cred_attrs);
   SAVEFREEPV(cred); /* automatic cleanup */
   for (i = 0; i < ncred; i++) {
      HV *cred_hv;
      STRLEN cred_id_len = 0;
      const U8* cred_id;
      SV **el= av_fetch(credentials, i, 0);
      if (!el || !*el || !SvROK(*el) || SvTYPE(SvRV(*el)) != SVt_PVHV)
         croak("Invalid credential[%ld]; must be hashref", (long)i);
      cred_hv= (HV*) SvRV(*el);
      /* id is bytes as previously received from fido2 */
      el= hv_fetchs(cred_hv, "id", 0);
      if (!el || !*el || !SvOK(*el))
         croak("Invalid credential[%ld]; must have ->{id}", (long)i);
      cred[i].id= secret_buffer_SvPVbyte(*el, &cred[i].id_len);
      /* pubkey is bytes of SubjectPublicKeyInfo */
      el= hv_fetchs(cred_hv, "pubkey", 0);
      if (!el || !*el || !SvOK(*el))
         croak("Invalid credential[%ld]; must have ->{pubkey}", (long)i);
      cred[i].pubkey= secret_buffer_SvPVbyte(*el, &cred[i].pubkey_len);
      /* cose_alg is optional */
      if ((el= hv_fetchs(cred_hv, "cose_alg", 0)) && *el && SvOK(*el)) {
         STRLEN len;
         const char *name= SvPV(*el, len);
         if (len == 5 && memcmp("ES256", name, len) == 0) {
            cred[i].cose_alg= COSE_ES256;
         } else {
            croak("Unknown cose_alg '%s' in credential[%ld]", name, (long)i);
         }
      } else {
         cred[i].cose_alg= COSE_ES256;
      }
   }

   if (!(assert = fido_assert_new()))
      GOTO_CLEANUP_CROAK("fido_assert_new failed");

   rc = fido_assert_set_rp(assert, rp_domain);
   if (rc != FIDO_OK)
      GOTO_CLEANUP_CROAK("fido_assert_set_rp failed");

   rc = fido_assert_set_clientdata_hash(assert, clientdata_hash, sizeof(clientdata_hash));
   if (rc != FIDO_OK)
      GOTO_CLEANUP_CROAK("fido_assert_set_clientdata_hash failed");

   rc = fido_assert_set_extensions(assert, FIDO_EXT_HMAC_SECRET);
   if (rc != FIDO_OK)
      GOTO_CLEANUP_CROAK("fido_assert_set_extensions(FIDO_EXT_HMAC_SECRET) failed");

   rc = fido_assert_set_hmac_salt(assert, (const U8 *)salt, salt_len);
   if (rc != FIDO_OK)
      GOTO_CLEANUP_CROAK("fido_assert_set_hmac_salt failed");

   /*
    * Keep policy stable. Touch required, UV not requested.
    * If you later expose UV policy, make sure you keep it consistent
    * for a given stored object.
    */
   rc = fido_assert_set_up(assert, FIDO_OPT_TRUE);
   if (rc != FIDO_OK)
      GOTO_CLEANUP_CROAK("fido_assert_set_up failed");

   rc = fido_assert_set_uv(assert, FIDO_OPT_FALSE);
   if (rc != FIDO_OK)
      GOTO_CLEANUP_CROAK("fido_assert_set_uv failed");

   for (i = 0; i < ncred; i++) {
      rc = fido_assert_allow_cred(assert, cred[i].id, cred[i].id_len);
      if (rc != FIDO_OK)
         GOTO_CLEANUP_CROAK("fido_assert_allow_cred failed");
   }

   rc = fido_dev_get_assert(dev, assert, pin);
   if (rc != FIDO_OK) {
      /* only croak on PIN errors */
      switch (rc) {
      case FIDO_ERR_PIN_INVALID:
      case FIDO_ERR_PIN_BLOCKED:
      case FIDO_ERR_PIN_AUTH_INVALID:
      case FIDO_ERR_PIN_AUTH_BLOCKED:
      case FIDO_ERR_PIN_NOT_SET:
      case FIDO_ERR_PIN_REQUIRED:
      case FIDO_ERR_PIN_POLICY_VIOLATION:
      case FIDO_ERR_PIN_TOKEN_EXPIRED:
         GOTO_CLEANUP_CROAK("pin error");
      /* return -2 for timeouts */
      case FIDO_ERR_TIMEOUT:
      case FIDO_ERR_ACTION_TIMEOUT:
      case FIDO_ERR_USER_ACTION_TIMEOUT:
         matched = -2;
         goto cleanup;
      /* -1 for everything else */
      default:
         matched = -1;
         goto cleanup;
      }
   }

   nstmt = fido_assert_count(assert);
   for (stmt_idx = 0; stmt_idx < nstmt; stmt_idx++) {
      const U8 *ret_id_ptr = fido_assert_id_ptr(assert, stmt_idx);
      size_t ret_id_len = fido_assert_id_len(assert, stmt_idx);

      if (!ret_id_ptr || ret_id_len == 0)
         GOTO_CLEANUP_CROAK("libfido2 returned success but no assertion credential id");

      /* loop through the credential array again looking for which one matched */
      for (i = 0; i < ncred; i++) {
         if (ret_id_len != cred[i].id_len || memcmp(ret_id_ptr, cred[i].id, ret_id_len) != 0)
            continue;

         switch (cred[i].cose_alg) {
            case COSE_ES256: {
               es256_pk_t *pk = cmk_es256_pk_from_spki_der(cred[i].pubkey, cred[i].pubkey_len);
               const unsigned char *secret_ptr;
               size_t secret_len;

               if (!pk) {
                  rc= FIDO_OK; /* don't include fido error in exception */
                  snprintf(err_buf, sizeof(err_buf), "failed to parse ES256 public key for credential[%ld]", (long)i);
                  err= err_buf;
                  goto cleanup;
               }

               rc = fido_assert_verify(assert, stmt_idx, COSE_ES256, pk);
               es256_pk_free(&pk);

               if (rc != FIDO_OK)
                  break; /* not this credential after all */

               secret_ptr = fido_assert_hmac_secret_ptr(assert, stmt_idx);
               secret_len = fido_assert_hmac_secret_len(assert, stmt_idx);

               if (!secret_ptr || secret_len == 0)
                  GOTO_CLEANUP_CROAK("libfido2 returned success+verified assertion but no hmac-secret");

               secret_buffer_set_len(out, out->len + secret_len);
               memcpy(out->data + out->len - secret_len, secret_ptr, secret_len);
               matched = (int)i;
               goto cleanup;
            }

            default:
               rc= FIDO_OK; /* don't include fido error in exception */
               snprintf(err_buf, sizeof(err_buf), "unsupported cose_alg=%d in credentials[%ld]",
                  (int)cred[i].cose_alg, (long)i);
               err= err_buf;
               goto cleanup;
         }
      }
   }

   matched = -1;

cleanup:
   OPENSSL_cleanse(clientdata_hash, sizeof(clientdata_hash));
   if (assert)
      fido_assert_free(&assert);
   if (err) {
      if (rc != FIDO_OK) {
         cmk_fido2_set_last_err(dev_objref, rc);
         croak("%s: %s", err, fido_strerr(rc));
      }
      croak("%s", err);
   }

   return matched;
}

static bool
cmk_es256_spki_from_fido_cred(const fido_cred_t *cred,
                              unsigned char **der_out,
                              int *der_len_out)
{
   const unsigned char *pub_ptr = NULL;
   size_t pub_len = 0;
   es256_pk_t *es256 = NULL;
   EVP_PKEY *pkey = NULL;
   unsigned char *der = NULL;
   int der_len = -1;
   bool ok = false;

   pub_ptr = fido_cred_pubkey_ptr(cred);
   pub_len = fido_cred_pubkey_len(cred);
   if (!pub_ptr || pub_len == 0)
      return false;

   es256 = es256_pk_new();
   if (!es256)
      goto cleanup;
   if (es256_pk_from_ptr(es256, pub_ptr, pub_len) != FIDO_OK)
      goto cleanup;

   pkey = es256_pk_to_EVP_PKEY(es256);
   if (!pkey)
      goto cleanup;

   der_len = i2d_PUBKEY(pkey, &der);
   if (der_len <= 0 || !der)
      goto cleanup;

   *der_out = der;
   *der_len_out = der_len;
   der = NULL;
   ok = true;

cleanup:
   if (der)
      OPENSSL_free(der);
   if (pkey)
      EVP_PKEY_free(pkey);
   if (es256)
      es256_pk_free(&es256);
   return ok;
}

static es256_pk_t *
cmk_es256_pk_from_spki_der(const unsigned char *der, size_t der_len) {
   es256_pk_t *pk = NULL;
   const unsigned char *p = der;
   EVP_PKEY *pkey = d2i_PUBKEY(NULL, &p, (long)der_len);
   if (pkey) {
      pk = es256_pk_new();
      if (pk) {
         if (es256_pk_from_EVP_PKEY(pk, pkey) != FIDO_OK) {
            es256_pk_free(&pk);
            pk = NULL;
         }
      }
      EVP_PKEY_free(pkey);
   }
   return pk;
}

const char *cmk_fido2_err_name(int err_code) {
   #define ERR_CASE(x) case x: return #x;
   switch (err_code) {
   ERR_CASE(FIDO_ERR_SUCCESS)
   ERR_CASE(FIDO_ERR_INVALID_COMMAND)
   ERR_CASE(FIDO_ERR_INVALID_PARAMETER)
   ERR_CASE(FIDO_ERR_INVALID_LENGTH)
   ERR_CASE(FIDO_ERR_INVALID_SEQ)
   ERR_CASE(FIDO_ERR_TIMEOUT)
   ERR_CASE(FIDO_ERR_CHANNEL_BUSY)
   ERR_CASE(FIDO_ERR_LOCK_REQUIRED)
   ERR_CASE(FIDO_ERR_INVALID_CHANNEL)
   ERR_CASE(FIDO_ERR_CBOR_UNEXPECTED_TYPE)
   ERR_CASE(FIDO_ERR_INVALID_CBOR)
   ERR_CASE(FIDO_ERR_MISSING_PARAMETER)
   ERR_CASE(FIDO_ERR_LIMIT_EXCEEDED)
   ERR_CASE(FIDO_ERR_UNSUPPORTED_EXTENSION)
   ERR_CASE(FIDO_ERR_FP_DATABASE_FULL)
   ERR_CASE(FIDO_ERR_LARGEBLOB_STORAGE_FULL)
   ERR_CASE(FIDO_ERR_CREDENTIAL_EXCLUDED)
   ERR_CASE(FIDO_ERR_PROCESSING)
   ERR_CASE(FIDO_ERR_INVALID_CREDENTIAL)
   ERR_CASE(FIDO_ERR_USER_ACTION_PENDING)
   ERR_CASE(FIDO_ERR_OPERATION_PENDING)
   ERR_CASE(FIDO_ERR_NO_OPERATIONS)
   ERR_CASE(FIDO_ERR_UNSUPPORTED_ALGORITHM)
   ERR_CASE(FIDO_ERR_OPERATION_DENIED)
   ERR_CASE(FIDO_ERR_KEY_STORE_FULL)
   ERR_CASE(FIDO_ERR_NOT_BUSY)
   ERR_CASE(FIDO_ERR_NO_OPERATION_PENDING)
   ERR_CASE(FIDO_ERR_UNSUPPORTED_OPTION)
   ERR_CASE(FIDO_ERR_INVALID_OPTION)
   ERR_CASE(FIDO_ERR_KEEPALIVE_CANCEL)
   ERR_CASE(FIDO_ERR_NO_CREDENTIALS)
   ERR_CASE(FIDO_ERR_USER_ACTION_TIMEOUT)
   ERR_CASE(FIDO_ERR_NOT_ALLOWED)
   ERR_CASE(FIDO_ERR_PIN_INVALID)
   ERR_CASE(FIDO_ERR_PIN_BLOCKED)
   ERR_CASE(FIDO_ERR_PIN_AUTH_INVALID)
   ERR_CASE(FIDO_ERR_PIN_AUTH_BLOCKED)
   ERR_CASE(FIDO_ERR_PIN_NOT_SET)
   ERR_CASE(FIDO_ERR_PIN_REQUIRED)
   ERR_CASE(FIDO_ERR_PIN_POLICY_VIOLATION)
   ERR_CASE(FIDO_ERR_PIN_TOKEN_EXPIRED)
   ERR_CASE(FIDO_ERR_REQUEST_TOO_LARGE)
   ERR_CASE(FIDO_ERR_ACTION_TIMEOUT)
   ERR_CASE(FIDO_ERR_UP_REQUIRED)
   ERR_CASE(FIDO_ERR_UV_BLOCKED)
   ERR_CASE(FIDO_ERR_UV_INVALID)
   ERR_CASE(FIDO_ERR_UNAUTHORIZED_PERM)
   ERR_CASE(FIDO_ERR_ERR_OTHER)
   ERR_CASE(FIDO_ERR_SPEC_LAST)
   default: (void)0;
   }
   return NULL;
   #undef ERR_CASE
}
SV *new_fido2_err_dualvar(int err_code) {
   const char *name= cmk_fido2_err_name(err_code);
   SV *sv;
   if (name) {
      sv= newSVpv(name, 0);
      SvUPGRADE(sv, SVt_PVNV);
      SvIV_set(sv, err_code);
      SvIOK_on(sv);
   } else {
      sv= newSViv(err_code);
   }
   return sv;
}

void cmk_fido2_set_last_err(SV *dev_objref, int err_code) {
   SV *err;
   if (!dev_objref || !SvROK(dev_objref) || SvTYPE(SvRV(dev_objref)) != SVt_PVHV)
      croak("BUG: Not a device object");
   err= new_fido2_err_dualvar(err_code);
   if (!hv_stores((HV*)SvRV(dev_objref), "fido_err", err))
      /* was tied, and SV not claimed */
      SvREFCNT_dec(err);
}

/******************** MAGIC for storing fido_dev_t on ::FIDO2::Device **********************/

#ifdef USE_ITHREADS
static int cmk_fido2_dev_magic_dup(pTHX_ MAGIC *mg, CLONE_PARAMS *param) {
   if (mg->mg_ptr) {
      /* After clone, the original ::FIDO2::Device has the pointer and the clone has NULL.
       * The clone can be re-opened on demand when methods look for the magic and find a
       * NULL pointer. */
      mg->mg_ptr= NULL;
   }
   PERL_UNUSED_VAR(param);
   return 0;
};
#else
#define cmk_fido2_dev_magic_dup 0
#endif

static int cmk_fido2_dev_magic_free(pTHX_ SV *sv, MAGIC *mg) {
   if (mg->mg_ptr) {
      fido_dev_t *dev= (fido_dev_t*) mg->mg_ptr;
      fido_dev_close(dev);
      fido_dev_free(&dev);
      mg->mg_ptr= NULL;
   }
   return 0;
}

static MGVTBL cmk_fido2_dev_magic_vtbl = {
   NULL, NULL, NULL, NULL,
   cmk_fido2_dev_magic_free,
   NULL,
   cmk_fido2_dev_magic_dup
#ifdef MGf_LOCAL
   ,NULL
#endif
};

/* Get the fido_dev_t from a Crypt::MultiKey::FIDO2::Device object */
fido_dev_t *cmk_fido2_dev_from_magic(SV *objref, int flags) {
   dTHX;
   MAGIC *magic= cmk_get_X_magic(aTHX_ objref, flags, &cmk_fido2_dev_magic_vtbl, "fido_dev_t");
   /* after clone, mg_ptr is NULL but ->{path} tell us which device to re-open */
   if (magic && !magic->mg_ptr) {
      SV **el= hv_fetchs((HV*)SvRV(objref), "path", 0);
      if (el && *el && SvOK(*el)) {
         fido_dev_t *dev;
         /* There's a chance that this is the first libfido2 function called in a new thread */
         fido_init(0);

         dev= fido_dev_new();
         if (fido_dev_open(dev, SvPV_nolen(*el)) == FIDO_OK) {
            magic->mg_ptr= (char*) dev;
         } else {
            fido_dev_free(&dev);
            croak("Failed to re-open '%s'", SvPV_nolen(*el));
         }
      }
   }
   return magic? (fido_dev_t*) magic->mg_ptr : NULL;
}

void cmk_fido2_dev_set_magic(SV *objref, fido_dev_t *dev) {
   dTHX;
   MAGIC *mg= cmk_get_X_magic(aTHX_ objref, CMK_MAGIC_AUTOCREATE, &cmk_fido2_dev_magic_vtbl, "fido_dev_t");
   if (mg->mg_ptr) {
      fido_dev_t *olddev= (fido_dev_t*) mg->mg_ptr;
      fido_dev_close(olddev);
      fido_dev_free(&olddev);
   }
   mg->mg_ptr= (char*) dev;
}

/* Wrap a fido_dev_t with a blessed Crypt::MultiKey::FIDO2::Device object, which will then
 * own and control the lifespan of the fido_dev_t.  The info may be provided to populate
 * some attributes of the new object.
 */
SV *cmk_fido2_wrap_dev(fido_dev_t *dev) {
   dTHX;
   HV *hv= newHV();
   SV *ref= newRV_noinc((SV*) hv);
   MAGIC *mg;
   sv_bless(ref, gv_stashpv("Crypt::MultiKey::FIDO2::Device", GV_ADD));
   cmk_fido2_dev_set_magic(ref, dev);
   return ref;
}
