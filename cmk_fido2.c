#ifdef HAVE_LIBFIDO2
#include <fido.h>
#endif

bool
cmk_fido2_available(void) {
#ifdef HAVE_LIBFIDO2
   return true;
#else
   return false;
#endif
}

AV *
cmk_fido2_list_devices(void) {
#ifdef HAVE_LIBFIDO2
   HV *device;
   AV *ret= newAV();
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

   for (i= 0; i < count; i++) {
      const fido_dev_info_t *di= fido_dev_info_ptr(devlist, i);
      const char *path= di? fido_dev_info_path(di) : NULL;
      device= newHV();
      if (path)
         hv_store(device, "path", 4, newSVpv(path, 0), 0);
      av_push(ret, newRV_noinc((SV*) device));
   }

   fido_dev_info_free(&devlist, max_devices);
   return ret;
#else
   return NULL;
#endif
}

secret_buffer *
cmk_fido2_make_credential(const char *device_path, const char *credential_name) {
#ifdef HAVE_LIBFIDO2
   unsigned char user_id[32];
   unsigned char clientdata_hash[32];
   EVP_MD_CTX *mdctx= NULL;
   fido_dev_t *dev= NULL;
   fido_cred_t *cred= NULL;
   const unsigned char *cred_id_ptr;
   size_t cred_id_len;
   int rc= FIDO_ERR_INTERNAL;
   secret_buffer *cred_id= NULL;

   /* Build stable hashes from the provided name for user id and client data. */
   mdctx= EVP_MD_CTX_new();
   if (!mdctx)
      croak("EVP_MD_CTX_new failed");
   if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1
    || EVP_DigestUpdate(mdctx, credential_name, strlen(credential_name)) != 1
    || EVP_DigestFinal_ex(mdctx, user_id, NULL) != 1) {
      EVP_MD_CTX_free(mdctx);
      croak("Failed to derive fido2 credential user id");
   }
   if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1
    || EVP_DigestUpdate(mdctx, "makecred:", 9) != 1
    || EVP_DigestUpdate(mdctx, credential_name, strlen(credential_name)) != 1
    || EVP_DigestFinal_ex(mdctx, clientdata_hash, NULL) != 1) {
      EVP_MD_CTX_free(mdctx);
      croak("Failed to derive fido2 make-credential client data hash");
   }
   EVP_MD_CTX_free(mdctx);
   mdctx= NULL;

   fido_init(0);
   dev= fido_dev_new();
   cred= fido_cred_new();
   if (!dev || !cred)
      goto cleanup;

   rc= fido_dev_open(dev, device_path);
   if (rc != FIDO_OK)
      goto cleanup;

   rc= fido_cred_set_type(cred, COSE_ES256);
   if (rc != FIDO_OK)
      goto cleanup;
   rc= fido_cred_set_rp(cred, "crypt-multikey.local", "Crypt::MultiKey");
   if (rc != FIDO_OK)
      goto cleanup;
   rc= fido_cred_set_user(cred, user_id, sizeof(user_id), credential_name, credential_name, NULL);
   if (rc != FIDO_OK)
      goto cleanup;
   rc= fido_cred_set_extensions(cred, FIDO_EXT_HMAC_SECRET);
   if (rc != FIDO_OK)
      goto cleanup;
   rc= fido_cred_set_clientdata_hash(cred, clientdata_hash, sizeof(clientdata_hash));
   if (rc != FIDO_OK)
      goto cleanup;

   rc= fido_dev_make_cred(dev, cred, NULL);
   if (rc != FIDO_OK)
      goto cleanup;

   cred_id_len= fido_cred_id_len(cred);
   cred_id_ptr= fido_cred_id_ptr(cred);
   if (!cred_id_ptr || !cred_id_len)
      croak("fido2 make-credential returned an empty credential id");

   cred_id= secret_buffer_new(cred_id_len, NULL);
   memcpy(cred_id->data, cred_id_ptr, cred_id_len);
   cred_id->len= cred_id_len;

cleanup:
   OPENSSL_cleanse(user_id, sizeof(user_id));
   OPENSSL_cleanse(clientdata_hash, sizeof(clientdata_hash));
   if (cred)
      fido_cred_free(&cred);
   if (dev) {
      (void) fido_dev_close(dev);
      fido_dev_free(&dev);
   }
   if (!cred_id)
      croak("fido2 make-credential failed: %s", fido_strerr(rc));
   return cred_id;
#else
   (void) device_path;
   (void) credential_name;
   croak("libfido2 support not available");
#endif
}

/* Perform a CTAP2 hmac-secret assertion on the selected authenticator. */
secret_buffer *
cmk_fido2_chalresp(const char *device_path, const U8 *challenge, STRLEN challenge_len,
   const U8 *cred_id, STRLEN cred_id_len) {
#ifdef HAVE_LIBFIDO2
   unsigned char challenge_hash[32];
   EVP_MD_CTX *mdctx= NULL;
   fido_dev_t *dev= NULL;
   fido_assert_t *assert= NULL;
   const unsigned char *resp_buf;
   size_t resp_len;
   int rc= FIDO_ERR_INTERNAL;
   secret_buffer *resp= NULL;

   mdctx= EVP_MD_CTX_new();
   if (!mdctx)
      croak("EVP_MD_CTX_new failed");
   if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1
    || EVP_DigestUpdate(mdctx, challenge, challenge_len) != 1
    || EVP_DigestFinal_ex(mdctx, challenge_hash, NULL) != 1) {
      EVP_MD_CTX_free(mdctx);
      croak("Failed to hash challenge bytes for fido2 hmac-secret");
   }
   EVP_MD_CTX_free(mdctx);
   mdctx= NULL;

   fido_init(0);
   dev= fido_dev_new();
   assert= fido_assert_new();
   if (!dev || !assert)
      goto cleanup;

   rc= fido_dev_open(dev, device_path);
   if (rc != FIDO_OK)
      goto cleanup;
   rc= fido_assert_set_rp(assert, "crypt-multikey.local");
   if (rc != FIDO_OK)
      goto cleanup;
   rc= fido_assert_set_extensions(assert, FIDO_EXT_HMAC_SECRET);
   if (rc != FIDO_OK)
      goto cleanup;
   rc= fido_assert_set_clientdata_hash(assert, challenge_hash, sizeof(challenge_hash));
   if (rc != FIDO_OK)
      goto cleanup;
   rc= fido_assert_set_hmac_salt(assert, challenge_hash, sizeof(challenge_hash));
   if (rc != FIDO_OK)
      goto cleanup;

   if (cred_id && cred_id_len) {
      rc= fido_assert_allow_cred(assert, cred_id, cred_id_len);
      if (rc != FIDO_OK)
         goto cleanup;
   }

   rc= fido_dev_get_assert(dev, assert, NULL);
   if (rc != FIDO_OK)
      goto cleanup;
   if (fido_assert_count(assert) < 1)
      croak("No assertions returned for fido2 hmac-secret request");

   resp_len= fido_assert_hmac_secret_len(assert, 0);
   resp_buf= fido_assert_hmac_secret_ptr(assert, 0);
   if (!resp_buf || !resp_len)
      croak("fido2 assertion returned an empty hmac-secret");

   resp= secret_buffer_new(resp_len, NULL);
   memcpy(resp->data, resp_buf, resp_len);
   resp->len= resp_len;

cleanup:
   OPENSSL_cleanse(challenge_hash, sizeof(challenge_hash));
   if (assert)
      fido_assert_free(&assert);
   if (dev) {
      (void) fido_dev_close(dev);
      fido_dev_free(&dev);
   }
   if (!resp)
      croak("fido2 challenge-response failed: %s", fido_strerr(rc));
   return resp;
#else
   (void) device_path;
   (void) challenge;
   (void) challenge_len;
   (void) cred_id;
   (void) cred_id_len;
   croak("libfido2 support not available");
#endif
}
