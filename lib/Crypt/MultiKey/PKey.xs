MODULE = Crypt::MultiKey                PACKAGE = Crypt::MultiKey::PKey

void
algorithm(pkey)
   maybe_cmk_pkey *pkey
   PPCODE:
      ST(0)= sv_newmortal();
      if (pkey && *pkey)
         cmk_pkey_get_algorithm_name(pkey, ST(0));
      XSRETURN(1);

void
_keygen(pkey, type)
   auto_cmk_pkey *pkey
   const char *type
   PPCODE:
      cmk_pkey_keygen(pkey, type);

bool
has_public(pkey)
   maybe_cmk_pkey *pkey
   CODE:
      RETVAL= pkey && cmk_pkey_has_public(pkey);
   OUTPUT:
      RETVAL

bool
has_private(pkey)
   maybe_cmk_pkey *pkey
   CODE:
      RETVAL= pkey && cmk_pkey_has_private(pkey);
   OUTPUT:
      RETVAL

void
_clear_key(pkey)
   maybe_cmk_pkey *pkey
   PPCODE:
      if (pkey && *pkey) {
         EVP_PKEY_free(*pkey);
         *pkey= NULL;
      }

void
_import_spki(pkey, buffer)
   auto_cmk_pkey *pkey
   SV *buffer
   INIT:
      STRLEN len;
      const U8 *buf= (const U8*) secret_buffer_SvPVbyte(buffer, &len);
   PPCODE:
      cmk_pkey_import_spki(pkey, buf, len);

void
_export_spki(pkey, buf)
   cmk_pubkey *pkey
   SV *buf
   PPCODE:
      cmk_pkey_export_spki(pkey, buf);

void
_import_pkcs8(pkey, buffer, pass_sv=&PL_sv_undef)
   auto_cmk_pkey *pkey
   SV *buffer
   SV *pass_sv
   INIT:
      STRLEN len, pass_len= 0;
      const U8 *buf= (const U8*) secret_buffer_SvPVbyte(buffer, &len);
      const char *pass= SvOK(pass_sv)? secret_buffer_SvPVbyte(pass_sv, &pass_len) : NULL;
   PPCODE:
      cmk_pkey_import_pkcs8(pkey, buf, len, pass, pass_len);

void
_import_openssh_privkey(pkey, buffer, pass_sv=&PL_sv_undef)
   auto_cmk_pkey *pkey
   SV *buffer
   SV *pass_sv
   INIT:
      STRLEN len, pass_len= 0;
      const U8 *buf= (const U8*) secret_buffer_SvPVbyte(buffer, &len);
      const char *pass= SvOK(pass_sv)? secret_buffer_SvPVbyte(pass_sv, &pass_len) : NULL;
   PPCODE:
      cmk_pkey_import_openssh_privkey(pkey, buf, len, pass, pass_len);

void
_import_openssh_pubkey(pkey, buffer)
   auto_cmk_pkey *pkey
   SV *buffer
   INIT:
      STRLEN len;
      const U8 *buf= (const U8*) secret_buffer_SvPVbyte(buffer, &len);
   PPCODE:
      cmk_pkey_import_openssh_pubkey(pkey, buf, len);

void
_export_pkcs8(pkey, buf, pass_sv=&PL_sv_undef, kdf_iter=100000)
   cmk_privkey *pkey
   SV *buf
   SV *pass_sv
   int kdf_iter
   INIT:
      STRLEN pass_len= 0;
      const char *pass= SvOK(pass_sv)? secret_buffer_SvPVbyte(pass_sv, &pass_len) : NULL;
      if (SvOK(pass_sv) && !pass_len)
         croak("Empty password supplied; pass undef to skip encryption");
   PPCODE:
      cmk_pkey_export_pkcs8(pkey, pass, pass_len, kdf_iter, buf);

void
generate_key_material(pkey, tumbler, skey_buf)
   cmk_pubkey *pkey
   HV *tumbler
   secret_buffer *skey_buf
   PPCODE:
      cmk_pkey_generate_key_material(pkey, tumbler, skey_buf);

void
recreate_key_material(pkey, tumbler, skey_buf)
   cmk_pubkey *pkey
   HV *tumbler
   secret_buffer *skey_buf
   PPCODE:
      cmk_pkey_recreate_key_material(pkey, tumbler, skey_buf);

void
encrypt(pkey, secret_sv, ciphertext_out=NULL)
   cmk_pubkey *pkey
   SV *secret_sv
   SV *ciphertext_out
   INIT:
      STRLEN secret_len= 0;
      const U8 *secret= (const U8*) secret_buffer_SvPVbyte(secret_sv, &secret_len);
      secret_buffer *skey_buf= secret_buffer_new(0, NULL);
      HV *enc= newHV();
      SV *ciphertext= ciphertext_out;
      bool own_ciphertext= false;
      SV *enc_ref= sv_2mortal(newRV_noinc((SV*) enc)); /* ensure HV gets cleaned up on error */
   PPCODE:
      if (!ciphertext) {
         ciphertext= newSVpvs("");
         own_ciphertext= true;
      }
      if (!hv_stores(enc, "ciphertext", ciphertext)) {
         if (own_ciphertext)
            SvREFCNT_dec(ciphertext);
         croak("failed to create ciphertext field");
      }
      cmk_pkey_generate_key_material(pkey, enc, skey_buf);
      cmk_symmetric_encrypt(enc, cmk_hkdf(enc, skey_buf), secret, secret_len, ciphertext);
      PUSHs(enc_ref);

void
decrypt(pkey, enc, secret_out=NULL)
   cmk_pubkey *pkey
   HV *enc
   secret_buffer *secret_out
   INIT:
      SV *secret_ref= NULL;
      secret_buffer *skey_buf= secret_buffer_new(0, NULL);
   PPCODE:
      SV **svp= hv_fetchs(enc, "ciphertext", 0);
      SV *ciphertext= NULL;
      if (!svp || !*svp || !SvOK(*svp))
         croak("Missing 'ciphertext'");
      ciphertext= *svp;
      if (!secret_out) {
         secret_out= secret_buffer_new(0, &secret_ref);
      } else {
         secret_ref= ST(2);
      }
      cmk_pkey_recreate_key_material(pkey, enc, skey_buf);
      {
         STRLEN ciphertext_len= 0;
         const U8 *ciphertext_buf= (const U8*) secret_buffer_SvPVbyte(ciphertext, &ciphertext_len);
         cmk_symmetric_decrypt(enc, cmk_hkdf(enc, skey_buf), ciphertext_buf, ciphertext_len, secret_out);
      }
      PUSHs(secret_ref);
