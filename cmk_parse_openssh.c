static bool cmk_parse_uint32(secret_buffer_parse *parse, uint32_t *out);
static bool cmk_parse_ssh_string(secret_buffer_parse *parse, const U8 **out, size_t *out_len);
static bool cmk_parse_ssh_mpint(secret_buffer_parse *parse, BIGNUM **bignum_out);
static bool cmk_parse_bytes_eq(secret_buffer_parse *parse, const char *literal, size_t lit_len);
static int cmk_curve_nid_from_ssh_name(const U8 *name, size_t name_len);
static const EVP_CIPHER *cmk_openssh_cipher_by_name(const U8 *ciphername, size_t ciphername_len,
                           int *key_len_out, int *iv_len_out, int *blk_len_out);
static bool cmk_parse_openssh_privkey_inner(secret_buffer_parse *parse, cmk_pkey *pk);
static EVP_PKEY *cmk_parse_openssh_rsa_priv_record(secret_buffer_parse *parse);
static EVP_PKEY *cmk_parse_openssh_ecdsa_priv_record(secret_buffer_parse *parse);
static EVP_PKEY *cmk_parse_openssh_ed25519_priv_record(secret_buffer_parse *parse);
static secret_buffer *cmk_openssh_decrypt_private_blob(
   const U8 *ciphername, size_t ciphername_len,
   const U8 *kdfname, size_t kdfname_len,
   const U8 *kdfopts, size_t kdfopts_len,
   const U8 *enc, size_t enc_len,
   const U8 *pw, size_t pw_len,
   const char **err_out);
static bool cmk_bcrypt_pbkdf(const U8 *pass, size_t pass_len,
                             const U8 *salt, size_t salt_len,
                             uint32_t rounds,
                             U8 *out, size_t out_len,
                             const char **err_out);
static bool
cmk_parse_openssh_bcrypt_kdfopts(const U8 *kdfopts, size_t kdfopts_len,
                                const U8 **salt_out, size_t *salt_len_out,
                                uint32_t *rounds_out,
                                const char **err_out);

void
cmk_pkey_import_openssh_pubkey(cmk_pkey *pk, const U8 *data, STRLEN data_len) {
   const char *err= NULL;
   EVP_PKEY *pkey = NULL;
   EC_KEY *eckey = NULL;
   RSA *rsa = NULL;
   BIGNUM *rsa_e = NULL, *rsa_n = NULL;
   const U8 *alg;
   size_t alg_len;
   secret_buffer_parse parse;

   memset(&parse, 0, sizeof(parse));
   parse.pos= (U8*) data;
   parse.lim= (U8*) data + data_len;

   /* SSH pubkey format begins with name of algorithm */
   if (!cmk_parse_ssh_string(&parse, &alg, &alg_len))
      GOTO_CLEANUP_CROAK("SSH blob truncated (alg)");

   /* RSA */
   if ((alg_len == 7 && memcmp(alg, "ssh-rsa", 7) == 0)) {
      if (!cmk_parse_ssh_mpint(&parse, &rsa_e))
         GOTO_CLEANUP_CROAK("Failed to parse rsa 'e' parameter");
      if (!cmk_parse_ssh_mpint(&parse, &rsa_n))
         GOTO_CLEANUP_CROAK("Failed to parse rsa 'n' parameter");

      rsa = RSA_new();
      if (!rsa) GOTO_CLEANUP_CROAK("RSA_new failed");

      if (RSA_set0_key(rsa, rsa_n, rsa_e, NULL) != 1)
         GOTO_CLEANUP_CROAK("RSA_set0_key failed");
      /* RSA takes ownership of n,e on success, don't need cleaned up now */
      rsa_n = NULL; rsa_e = NULL;

      if (!(pkey = EVP_PKEY_new()))
         GOTO_CLEANUP_CROAK("EVP_PKEY_new failed");
      if (EVP_PKEY_assign_RSA(pkey, rsa) != 1)
         GOTO_CLEANUP_CROAK("EVP_PKEY_assign_RSA failed");
      /* EVP_PKEY owns rsa now */
      rsa = NULL;
   }
   /* ED25519 */
   else if ((alg_len == 11) && memcmp(alg, "ssh-ed25519", 11) == 0) {
      const U8 *pk;
      size_t pk_len;

      if (!cmk_parse_ssh_string(&parse, &pk, &pk_len))
         GOTO_CLEANUP_CROAK("SSH blob truncated (pk)");
      if (pk_len != 32)
         GOTO_CLEANUP_CROAK("Invalid Ed25519 public key length");

      pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, pk, pk_len);
      if (!pkey) GOTO_CLEANUP_CROAK("EVP_PKEY_new_raw_public_key failed");
   }
   /* ECDSA */
   else if ((alg_len >= 11) && memcmp(alg, "ecdsa-sha2-", 11) == 0) {
      const U8 *curve, *q;
      size_t curve_len, q_len;
      int nid;

      if (!cmk_parse_ssh_string(&parse, &curve, &curve_len))
         GOTO_CLEANUP_CROAK("SSH blob truncated (curve)");

      /* Some blobs repeat curve in alg suffix; OpenSSH expects curve string here */
      nid = cmk_curve_nid_from_ssh_name(curve, curve_len);
      if (nid == NID_undef)
         GOTO_CLEANUP_CROAK("Unsupported ECDSA curve");

      if (!cmk_parse_ssh_string(&parse, &q, &q_len))
         GOTO_CLEANUP_CROAK("SSH blob truncated (Q)");

      eckey = EC_KEY_new_by_curve_name(nid);
      if (!eckey) GOTO_CLEANUP_CROAK("EC_KEY_new_by_curve_name failed");

      /* Parse octet-encoded public point into EC_KEY */
      {
         const unsigned char *qtmp = q;
         if (o2i_ECPublicKey(&eckey, &qtmp, (long)q_len) == NULL)
            GOTO_CLEANUP_CROAK("o2i_ECPublicKey failed");
         /* o2i_ECPublicKey advances qtmp; ignore */
      }

      if (!(pkey = EVP_PKEY_new()))
         GOTO_CLEANUP_CROAK("EVP_PKEY_new failed");
      if (EVP_PKEY_assign_EC_KEY(pkey, eckey) != 1)
         GOTO_CLEANUP_CROAK("EVP_PKEY_assign_EC_KEY failed");
      /* EVP_PKEY owns eckey now */
      eckey = NULL;
   }
   else {
      GOTO_CLEANUP_CROAK("Unsupported SSH algorithm");
   }
   if (parse.pos < parse.lim)
      GOTO_CLEANUP_CROAK("Extra bytes in buffer following SSH pubkey");

cleanup:
   if (rsa) RSA_free(rsa);
   if (rsa_e) BN_free(rsa_e);
   if (rsa_n) BN_free(rsa_n);
   if (eckey) EC_KEY_free(eckey);
   if (err) {
      if (pkey) EVP_PKEY_free(pkey);
      cmk_croak_with_ssl_error("import_openssh_pubkey", err);
   } else {
      if (*pk) EVP_PKEY_free(*pk);
      *pk= pkey;
   }
}

/* Parse an OpenSSH "openssh-key-v1" private key container and store either the private or
 * public key into 'pk'.  If the key is unencrypted, this always loads the private key.
 * If the key is encrypted and password was not provided, this falls back to loading the public
 * key, which is stored as plaintext alongside the encrypted private key.
 * If the key is encrypted and the password is provided, this attempts to decrypt and load the
 * private key and croaks on failure.
 *
 * This function expects `data` to be the raw decoded bytes of the PEM block:
 *
 *    -----BEGIN OPENSSH PRIVATE KEY-----
 *    (base64)
 *    -----END OPENSSH PRIVATE KEY-----
 *
 * The base64 decoding is performed by the caller (Perl layer).
 *
 * Only the first key can be imported, though the container format supports multiple.
 *
 * ------------------------------------------------------------------------
 * OUTER CONTAINER FORMAT  (from OpenSSH PROTOCOL.key)
 * ------------------------------------------------------------------------
 *
 *   byte[]   "openssh-key-v1\0"    (15-byte magic including NUL)
 *
 *   string   ciphername            SSH string (uint32 len + bytes)
 *   string   kdfname               SSH string
 *   string   kdfoptions            SSH string
 *   uint32   nkeys
 *
 *   string   publickey[nkeys]      SSH string(s), each containing a complete public key blob
 *
 *   string   privatekey_blob       SSH string containing either:
 *                                     - plaintext private key structure (if ciphername="none")
 *                                     - encrypted private key structure (otherwise)
 *
 * SSH "string" encoding is:
 *     uint32 length (big-endian)
 *     <length> bytes of data (not NUL terminated)
 *
 * ------------------------------------------------------------------------
 * INNER PLAINTEXT PRIVATE KEY BLOB FORMAT
 * ------------------------------------------------------------------------
 *
 * The privatekey_blob contains:
 *
 *   uint32  checkint1
 *   uint32  checkint2
 *
 *   (checkint1 must equal checkint2; mismatch indicates wrong
 *    passphrase or corrupted data in encrypted variants)
 *
 *   For each key (normally exactly 1):
 *
 *       string  keytype
 *       ...     keytype-specific fields (see below)
 *       string  comment
 *
 *   padding bytes:
 *       1, 2, 3, ... up to cipher block size boundary.
 *       For unencrypted keys, padding is still present and follows
 *       the same incrementing pattern.
 *
 *  (no attempt is made to validate the padding)
 *
 * ------------------------------------------------------------------------
 * KEYTYPE-SPECIFIC INNER FORMATS
 * ------------------------------------------------------------------------
 *
 * ssh-rsa:
 *
 *     mpint  n
 *     mpint  e
 *     mpint  d
 *     mpint  iqmp     (q^{-1} mod p)
 *     mpint  p
 *     mpint  q
 *
 * ssh-ed25519:
 *
 *     string  public_key      (32 bytes)
 *     string  private_key     (64 bytes: seed||public_key)
 *
 *     The first 32 bytes of private_key are the Ed25519 seed.
 *
 * ecdsa-sha2-<curve>:
 *
 *     string  curve_name      (e.g. "nistp256")
 *     string  public_point    (octet form, typically uncompressed)
 *     mpint   private_scalar
 *
 */
void
cmk_pkey_import_openssh_privkey(cmk_pkey *pk, const U8 *data, STRLEN data_len,
                                const char *pw, STRLEN pw_len
) {
   const char *err = NULL;

   secret_buffer_parse outer, inner;
   const U8 *ciphername=NULL, *kdfname=NULL, *kdfopts=NULL;
   size_t ciphername_len=0, kdfname_len=0, kdfopts_len=0;
   uint32_t nkeys=0;

   const U8 *pubblob0=NULL, *privblob=NULL;
   size_t pubblob0_len=0, privblob_len=0;

   secret_buffer *plain_sb = NULL;

   memset(&outer, 0, sizeof(outer));
   outer.pos = data;
   outer.lim = data + data_len;

   if (!cmk_parse_bytes_eq(&outer, "openssh-key-v1\0", 15))
      croak(outer.error ? outer.error : "Bad OpenSSH key magic (expected 'openssh-key-v1')");

   if (!cmk_parse_ssh_string(&outer, &ciphername, &ciphername_len) ||
       !cmk_parse_ssh_string(&outer, &kdfname, &kdfname_len) ||
       !cmk_parse_ssh_string(&outer, &kdfopts, &kdfopts_len) ||
       !cmk_parse_uint32(&outer, &nkeys)) {
      croak("Truncated OpenSSH header");
   }

   if (nkeys < 1)
      croak("OpenSSH key contains no public keys");

   if (!cmk_parse_ssh_string(&outer, &pubblob0, &pubblob0_len))
      croak("Truncated OpenSSH public key");

   for (uint32_t i=1; i<nkeys; i++) {
      const U8 *tmp=NULL;
      size_t tmp_len=0;
      if (!cmk_parse_ssh_string(&outer, &tmp, &tmp_len))
         croak("Truncated OpenSSH public key list");
   }

   if (!cmk_parse_ssh_string(&outer, &privblob, &privblob_len))
      croak("Truncated OpenSSH private blob");

   memset(&inner, 0, sizeof(inner));
   /* Unencrypted? */
   if ((ciphername_len == 4 && memcmp(ciphername, "none", 4) == 0) &&
       (kdfname_len == 4 && memcmp(kdfname, "none", 4) == 0)
   ) {
      inner.pos = privblob;
      inner.lim = privblob + privblob_len;
   }
   else if (!pw) {
      /* Encrypted, but caller didn't supply password, so just load the public key. */
      cmk_pkey_import_openssh_pubkey(pk, pubblob0, (STRLEN)pubblob0_len);
      return;
   }
   else {
      /* caller supplied a password -> MUST either decrypt+parse or die */
      plain_sb = cmk_openssh_decrypt_private_blob(ciphername, ciphername_len,
                                                  kdfname, kdfname_len,
                                                  kdfopts, kdfopts_len,
                                                  privblob, privblob_len,
                                                  (const U8*)pw, (size_t)pw_len,
                                                  &err);
      if (!plain_sb)
         croak("Failed to decrypt OpenSSH private key: %s", err);
//      warn("# decrypted privblob %ld bytes into %ld bytes of 'inner'\n", (long)privblob_len, (long)plain_sb->len);
      inner.pos = plain_sb->data;
      inner.lim = plain_sb->data + plain_sb->len;
   }
   if (!cmk_parse_openssh_privkey_inner(&inner, pk))
      croak("Failed to parse OpenSSH private key: %s", inner.error);
}

bool
cmk_parse_openssh_privkey_inner(secret_buffer_parse *parse, cmk_pkey *pk) {
   uint32_t c1, c2;
   const U8 *keytype;
   size_t keytype_len;
   EVP_PKEY *pkey = NULL;

   if (!cmk_parse_uint32(parse, &c1) || !cmk_parse_uint32(parse, &c2))
      return false;

   if (c1 != c2) {
      parse->error = "checkint mismatch (wrong passphrase or corrupt key file)";
      return false;
   }

   if (!cmk_parse_ssh_string(parse, &keytype, &keytype_len))
      return false;

   if (keytype_len == 7 && memcmp(keytype, "ssh-rsa", 7) == 0) {
      pkey = cmk_parse_openssh_rsa_priv_record(parse);
   }
   else if (keytype_len >= 11 && memcmp(keytype, "ecdsa-sha2-", 11) == 0) {
      pkey = cmk_parse_openssh_ecdsa_priv_record(parse);
   }
   else if (keytype_len == 11 && memcmp(keytype, "ssh-ed25519", 11) == 0) {
      pkey = cmk_parse_openssh_ed25519_priv_record(parse);
   }
   else {
      parse->error = "Unsupported OpenSSH private key type";
      return false;
   }

   if (!pkey) {
      if (!parse->error) parse->error = "Failed to parse OpenSSH private key record";
      return false;
   }

   /* ignore comment for now */
#if 0
   {
      const U8 *comment;
      size_t comment_len;
      if (!cmk_parse_ssh_string(parse, &comment, &comment_len)) {
         EVP_PKEY_free(pkey);
         return NULL;
      }
   }
#endif
   /* padding may follow; optional validation could be added */
   if (*pk) EVP_PKEY_free(*pk);
   *pk= pkey;
   return true;
}

static EVP_PKEY *
cmk_parse_openssh_rsa_priv_record(secret_buffer_parse *parse) {
   const char *err = NULL;
   EVP_PKEY *pkey = NULL;
   RSA *rsa = NULL;

   BIGNUM *n=NULL,*e=NULL,*d=NULL,*iqmp=NULL,*p=NULL,*q=NULL;

   if (!cmk_parse_ssh_mpint(parse, &n) ||
       !cmk_parse_ssh_mpint(parse, &e) ||
       !cmk_parse_ssh_mpint(parse, &d) ||
       !cmk_parse_ssh_mpint(parse, &iqmp) ||
       !cmk_parse_ssh_mpint(parse, &p) ||
       !cmk_parse_ssh_mpint(parse, &q)) {
      /* parse->error already set */
      goto cleanup;
   }

   rsa = RSA_new();
   if (!rsa) { parse->error = "RSA_new failed"; goto cleanup; }

   if (RSA_set0_key(rsa, n, e, d) != 1) {
      parse->error = "RSA_set0_key failed";
      goto cleanup;
   }
   n=e=d=NULL;

   if (RSA_set0_factors(rsa, p, q) != 1) {
      parse->error = "RSA_set0_factors failed";
      goto cleanup;
   }
   p=q=NULL;

   /* OpenSSH provides iqmp; dmp1/dmq1 absent */
   if (RSA_set0_crt_params(rsa, NULL, NULL, iqmp) != 1) {
      parse->error = "RSA_set0_crt_params failed";
      goto cleanup;
   }
   iqmp=NULL;

   pkey = EVP_PKEY_new();
   if (!pkey) { parse->error = "EVP_PKEY_new failed"; goto cleanup; }
   if (EVP_PKEY_assign_RSA(pkey, rsa) != 1) {
      parse->error = "EVP_PKEY_assign_RSA failed";
      goto cleanup;
   }
   rsa = NULL;

cleanup:
   if (rsa) RSA_free(rsa);
   if (n) BN_free(n);
   if (e) BN_free(e);
   if (d) BN_free(d);
   if (p) BN_free(p);
   if (q) BN_free(q);
   if (iqmp) BN_free(iqmp);

   return pkey;
}

static EVP_PKEY *
cmk_parse_openssh_ecdsa_priv_record(secret_buffer_parse *parse) {
   EVP_PKEY *pkey = NULL;
   EC_KEY *eckey = NULL;

   const U8 *curve=NULL,*q=NULL;
   size_t curve_len=0,q_len=0;
   int nid;
   BIGNUM *d = NULL;

   if (!cmk_parse_ssh_string(parse, &curve, &curve_len)) return NULL;

   nid = cmk_curve_nid_from_ssh_name(curve, curve_len);
   if (nid == NID_undef) { parse->error = "Unsupported ECDSA curve"; goto cleanup; }

   if (!cmk_parse_ssh_string(parse, &q, &q_len)) return NULL;
   if (!cmk_parse_ssh_mpint(parse, &d)) return NULL;

   eckey = EC_KEY_new_by_curve_name(nid);
   if (!eckey) { parse->error = "EC_KEY_new_by_curve_name failed"; goto cleanup; }

   {
      const unsigned char *qtmp = q;
      if (o2i_ECPublicKey(&eckey, &qtmp, (long)q_len) == NULL) {
         parse->error = "o2i_ECPublicKey failed";
         goto cleanup;
      }
   }

   if (EC_KEY_set_private_key(eckey, d) != 1) {
      parse->error = "EC_KEY_set_private_key failed";
      goto cleanup;
   }

   pkey = EVP_PKEY_new();
   if (!pkey) { parse->error = "EVP_PKEY_new failed"; goto cleanup; }
   if (EVP_PKEY_assign_EC_KEY(pkey, eckey) != 1) {
      parse->error = "EVP_PKEY_assign_EC_KEY failed";
      goto cleanup;
   }
   eckey = NULL;

cleanup:
   if (d) BN_free(d);
   if (eckey) EC_KEY_free(eckey);
   return pkey;
}

static EVP_PKEY *
cmk_parse_openssh_ed25519_priv_record(secret_buffer_parse *parse) {
   EVP_PKEY *pkey = NULL;
   const U8 *pub=NULL, *seed32=NULL;
   size_t pub_len=0, seed_pub_len=0;

   if (!cmk_parse_ssh_string(parse, &pub, &pub_len)) return NULL;
   if (pub_len != 32) { parse->error = "Invalid Ed25519 public key length"; return NULL; }

   /* OpenSSH stores Ed25519 privatekey as string of 64 bytes (seed||pub). */
   if (!cmk_parse_ssh_string(parse, &seed32, &seed_pub_len))
      return NULL;
   if (seed_pub_len != 64) { parse->error = "Invalid Ed25519 private key length"; return NULL; }

   pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, seed32, 32);
   if (!pkey) { parse->error = "EVP_PKEY_new_raw_private_key failed"; return NULL; }

   return pkey;
}

static secret_buffer *
cmk_openssh_decrypt_private_blob(const U8 *ciphername, size_t ciphername_len,
                                 const U8 *kdfname, size_t kdfname_len,
                                 const U8 *kdfopts, size_t kdfopts_len,
                                 const U8 *enc, size_t enc_len,
                                 const U8 *pw, size_t pw_len,
                                 const char **err_out) {
   const char *err= NULL;
   const EVP_CIPHER *cipher = NULL;
   EVP_CIPHER_CTX *ctx = NULL;

   const U8 *salt = NULL;
   size_t salt_len = 0;
   uint32_t rounds = 0;

   int key_len = 0, iv_len = 0, blk_len = 0;
   size_t keyiv_len = 0;

   secret_buffer *keyiv_sb = NULL;
   secret_buffer *plain_sb = NULL;

   int outl1 = 0, outl2 = 0;

   cipher = cmk_openssh_cipher_by_name(ciphername, ciphername_len, &key_len, &iv_len, &blk_len);
   if (!cipher) {
      *err_out = "Unsupported OpenSSH cipher";
      return NULL;
   }

   /* OpenSSH encrypted keys typically have kdfname="bcrypt" */
   if (kdfname_len == 6 && memcmp(kdfname, "bcrypt", 6) == 0) {
      /* Parse OpenSSH bcrypt kdfoptions.
       * kdfoptions is an SSH string containing: string salt; uint32 rounds;
       */
      secret_buffer_parse p;
      memset(&p, 0, sizeof(p));
      p.pos = kdfopts;
      p.lim = kdfopts + kdfopts_len;

      if (!cmk_parse_ssh_string(&p, &salt, &salt_len)
         || !cmk_parse_uint32(&p, &rounds))
         GOTO_CLEANUP_CROAK("Error parsing bcrypt kdfoptions");

      /* Derive key+iv into a secret buffer */
      keyiv_len = key_len + iv_len;
      keyiv_sb = secret_buffer_new(keyiv_len, NULL);
      keyiv_sb->len= keyiv_len;
      /* Run bcrypt on the password and salt to produce the key & iv */
      if (!cmk_bcrypt_pbkdf((const U8*)pw, pw_len, salt, salt_len, rounds,
                        keyiv_sb->data, keyiv_len, &err))
         goto cleanup;
   }
   else {
      warn("# unsupported OpenSSH key derivation function '%.*s'", (int)kdfname_len, kdfname);
      GOTO_CLEANUP_CROAK("unsupported OpenSSH key derivation function (currently only bcrypt is implemented)");
   }

   /* Allocate plaintext buffer in secret memory.
    * For CTR mode: ciphertext length == plaintext length.
    */
   plain_sb = secret_buffer_new(enc_len, NULL);
   plain_sb->len= enc_len;

   ctx = EVP_CIPHER_CTX_new();
   if (!ctx) GOTO_CLEANUP_CROAK("EVP_CIPHER_CTX_new failed");

   if (EVP_DecryptInit_ex(ctx, cipher, NULL,
                         keyiv_sb->data,
                         keyiv_sb->data + key_len) != 1)
      GOTO_CLEANUP_CROAK("EVP_DecryptInit_ex failed");

   if (EVP_DecryptUpdate(ctx, plain_sb->data, &outl1, enc, (int)enc_len) != 1)
      GOTO_CLEANUP_CROAK("EVP_DecryptUpdate failed");

   /* CTR produces no padding; Final should succeed and usually outputs 0 bytes. */
   if (EVP_DecryptFinal_ex(ctx, plain_sb->data + outl1, &outl2) != 1)
      /* Wrong password *might* still pass CTR decryption; we rely on checkints later.
       * A Final failure here is more “cipher misuse” than “wrong pw”.
       */
      GOTO_CLEANUP_CROAK("EVP_DecryptFinal_ex failed");

   /* Adjust length if Final produced bytes (shouldn't for CTR) */
   if ((size_t)(outl1 + outl2) != enc_len)
      /* Keep strict; if you add CBC later, you’ll want different logic */
      GOTO_CLEANUP_CROAK("Unexpected decrypted length");

cleanup:
   if (ctx) EVP_CIPHER_CTX_free(ctx);
   if (err) {
      *err_out= err;
      return NULL;
   }
   return plain_sb;
}

/* Only CTR for now (easy to extend) */
static const EVP_CIPHER *
cmk_openssh_cipher_by_name(const U8 *ciphername, size_t ciphername_len,
                           int *key_len_out, int *iv_len_out, int *blk_len_out)
{
   if (ciphername_len == 10 && memcmp(ciphername, "aes256-ctr", 10) == 0) {
      const EVP_CIPHER *c = EVP_aes_256_ctr();
      if (!c) return NULL;
      if (key_len_out) *key_len_out = EVP_CIPHER_key_length(c);
      if (iv_len_out)  *iv_len_out  = EVP_CIPHER_iv_length(c);
      if (blk_len_out) *blk_len_out = EVP_CIPHER_block_size(c);
      return c;
   }
   warn("# unhandled cipher '%.*s'", (int)ciphername_len, ciphername);

   /* TODO later:
    * - aes128-ctr, aes192-ctr
    * - aes256-gcm@openssh.com (tag handling)
    * - chacha20-poly1305@openssh.com (OpenSSH special)
    */
   return NULL;
}

/* Read big-endian u32 from SSH wire format */
static bool
cmk_parse_uint32(secret_buffer_parse *parse, uint32_t *out) {
   uint32_t v;
   if (parse->lim - parse->pos < 4) {
      parse->error= "Truncated input";
      return false;
   }
   memcpy(&v, parse->pos, 4);
   parse->pos += 4;
   *out= be32toh(v);
   return true;
}

/* Read SSH "string": u32 length + bytes (not NUL-terminated) */
static bool
cmk_parse_ssh_string(secret_buffer_parse *parse, const U8 **out, size_t *out_len) {
   uint32_t len;
   if (!cmk_parse_uint32(parse, &len))
      return false;
   if (parse->lim - parse->pos < len) {
      parse->error= "Truncated input";
      return false;
   }
   *out= parse->pos;
   *out_len= len;
   parse->pos += len;
   return true;
}

/* Read SSH "mpint": same encoding as string, but interpreted as two's complement integer.
 * Returns success or failure, and on success updates bignum_out to point to a new SSL BIGNUM
 * which the caller must free.
 */
static bool
cmk_parse_ssh_mpint(secret_buffer_parse *parse, BIGNUM **bignum_out) {
   const U8 *buf;
   size_t blen;
   BIGNUM *bn = NULL;

   if (!cmk_parse_ssh_string(parse, &buf, &blen))
      return false;

   if (blen == 0) {
      /* mpint zero */
      *bignum_out= BN_new(); /* BN_new() initializes to 0 */
      return true;
   }

   /* If highest bit set, this would be negative in two's complement.
    * That should not happen for key parameters; treat as parse error.
    */
   if (buf[0] & 0x80) {
      parse->error= "Found negative BIGINT";
      return false;
   }

   if (!(bn= BN_bin2bn(buf, (int)blen, NULL))) {
      parse->error= "BN_bin2bn failed";
      return false;
   }
   *bignum_out= bn;
   return true;
}

/* Ensure the next bytes match a string literal */
static bool
cmk_parse_bytes_eq(secret_buffer_parse *parse, const char *literal, size_t lit_len) {
   if ((size_t)(parse->lim - parse->pos) < lit_len) {
      parse->error = "Truncated input";
      return false;
   }
   if (memcmp(parse->pos, literal, lit_len) != 0) {
      parse->error = "Bad magic";
      return false;
   }
   parse->pos += lit_len;
   return true;
}

static int
cmk_curve_nid_from_ssh_name(const U8 *name, size_t name_len) {
   /* OpenSSH uses: nistp256 / nistp384 / nistp521 */
   if (name_len == 8 && memcmp(name, "nistp256", 8) == 0) return NID_X9_62_prime256v1;
   if (name_len == 8 && memcmp(name, "nistp384", 8) == 0) return NID_secp384r1;
   if (name_len == 8 && memcmp(name, "nistp521", 8) == 0) return NID_secp521r1;
   return NID_undef;
}

#include "cmk_bcrypt_pbkdf.c"
