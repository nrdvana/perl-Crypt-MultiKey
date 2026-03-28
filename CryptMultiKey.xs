#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"
#include "ppport.h"

#include "CryptMultiKey_config.h"

#ifndef HAVE_BOOL
   #define bool int
   #define true 1
   #define false 0
#endif

#include <openssl/evp.h>
#include <openssl/rand.h>
#include "cmk.h"

/**********************************************************************************************\
* XS Utils
\**********************************************************************************************/

/* For exported constant dualvars */
#define EXPORT_ENUM(x) newCONSTSUB(stash, #x, new_enum_dualvar(aTHX_ x, newSVpvs_share(#x)))
static SV * new_enum_dualvar(pTHX_ IV ival, SV *name) {
   SvUPGRADE(name, SVt_PVNV);
   SvIV_set(name, ival);
   SvIOK_on(name);
   SvREADONLY_on(name);
   return name;
}

#if 0
#define AUTOCREATE CMK_MAGIC_AUTOCREATE
#define OR_DIE     CMK_MAGIC_OR_DIE
#define UNDEF_OK   CMK_MAGIC_UNDEF_OK
static void * X_from_magic(SV *obj, int flags, MGVTBL *vtbl, const char * struct_name, size_t struct_size) {
   SV *sv;
   MAGIC *magic;
   char *p;

   if ((!obj || !SvOK(obj)) && (flags & CMK_MAGIC_UNDEF_OK))
      return NULL;

   if (!sv_isobject(obj)) {
      if (flags & CMK_MAGIC_OR_DIE)
         croak("Not an object");
      return NULL;
   }
   sv = SvRV(obj);
   if (SvMAGICAL(sv) && (magic = mg_findext(sv, PERL_MAGIC_ext, vtbl)))
      return magic->mg_ptr;

   if (flags & CMK_MAGIC_AUTOCREATE) {
      Newxz(p, struct_size, char);
      magic = sv_magicext(sv, NULL, PERL_MAGIC_ext, vtbl, p, 0);
      SET_MGf_DUP_FLAG(mg);
      return p;
   }
   if (flags & CMK_MAGIC_OR_DIE)
      croak("Object lacks '%s' magic", struct_name);
   return NULL;
}
#endif

/* Aliases for typemap, to give useful errors when key state is wrong */
typedef cmk_pkey cmk_pubkey, cmk_privkey, maybe_cmk_pkey, auto_cmk_pkey;

MODULE = Crypt::MultiKey                PACKAGE = Crypt::MultiKey
PROTOTYPES: DISABLE

void
_openssl_version_components()
   INIT:
      int major = (OPENSSL_VERSION_NUMBER >> 28) & 0x0F;
      int minor = (OPENSSL_VERSION_NUMBER >> 20) & 0xFF;
      int patch = (OPENSSL_VERSION_NUMBER >> 12) & 0xFF;
   PPCODE:
      XPUSHs(sv_2mortal(newSViv(major)));
      XPUSHs(sv_2mortal(newSViv(minor)));
      XPUSHs(sv_2mortal(newSViv(patch)));

bool
_have_yubico_otp()
   CODE:
      RETVAL= cmk_yubico_otp_available();
   OUTPUT:
      RETVAL

void
_yubico_otp_ykinfo(fd)
   int fd
   INIT:
      HV *ret;
   PPCODE:
      if ((ret= cmk_yubico_otp_ykinfo(fd)))
         XPUSHs(newRV_noinc((SV*)ret));
      else
         XSRETURN_UNDEF;

void
_yubico_otp_ykchalresp(fd, slot, timeout, challenge)
   int fd
   int slot
   NV timeout
   SV *challenge
   INIT:
      SV *secret_buffer_ref= NULL;
      secret_buffer *response= secret_buffer_new(0, &secret_buffer_ref);
   PPCODE:
      switch(cmk_yubico_otp_ykchalresp(fd, slot, (int)(timeout*1000), challenge, response)) {
      case  0: ST(0)= secret_buffer_ref; XSRETURN(1); break;
      case -1: XSRETURN(0); break;
      case -2: XSRETURN_UNDEF; break;
      default: croak("BUG");
      }

bool
_have_fido2()
   CODE:
      RETVAL= cmk_fido2_available();
   OUTPUT:
      RETVAL

void
_fido2_list_devices()
   PPCODE:
      AV *ret= cmk_fido2_list_devices();
      if (!ret)
         XSRETURN_UNDEF;
      XPUSHs(sv_2mortal(newRV_noinc((SV*)ret)));

void
_fido2_chalresp(device_path, challenge)
   const char *device_path
   SV *challenge
   INIT:
      STRLEN challenge_len;
      const U8 *challenge_buf= (const U8*) secret_buffer_SvPVbyte(challenge, &challenge_len);
      const U8 *cred_id_buf= NULL;
      STRLEN cred_id_len= 0;
   PPCODE:
      if (items > 2 && SvOK(ST(2)))
         cred_id_buf= (const U8*) secret_buffer_SvPVbyte(ST(2), &cred_id_len);
      PUSHs(sv_2mortal(newRV_inc(cmk_fido2_chalresp(device_path, challenge_buf, challenge_len, cred_id_buf, cred_id_len)->wrapper)));

void
_fido2_make_credential(device_path, credential_name)
   const char *device_path
   const char *credential_name
   PPCODE:
      PUSHs(sv_2mortal(newRV_inc(cmk_fido2_make_credential(device_path, credential_name)->wrapper)));



void
_generate_uuid_v4()
   PPCODE:
      XPUSHs(cmk_generate_uuid_v4(sv_newmortal()));

void
sha256(...)
   INIT:
      SV *mortal_buf_ref= NULL;
      secret_buffer *out_sb= secret_buffer_new(32, &mortal_buf_ref);
      out_sb->len= 32;
   PPCODE:
      cmk_sha256( (U8*) out_sb->data, &ST(0), items);
      XPUSHs(mortal_buf_ref);

void
hkdf(params, key_material)
   HV *params
   secret_buffer *key_material
   PPCODE:
      PUSHs(sv_2mortal(newRV_inc(cmk_hkdf(params, key_material)->wrapper)));

void
hmac_sha256(key, ...)
   SV *key
   INIT:
      STRLEN key_len;
      const U8 *key_buf= (const U8*) secret_buffer_SvPVbyte(key, &key_len);
      SV *mortal_buf_ref= NULL;
      secret_buffer *out_sb= secret_buffer_new(32, &mortal_buf_ref);
      out_sb->len= 32;
   PPCODE:
      cmk_hmac_sha256( (U8*) out_sb->data, key_buf, key_len, &ST(1), items-1);
      XPUSHs(mortal_buf_ref);

void
symmetric_encrypt(params, aes_key, secret)
   HV *params
   secret_buffer *aes_key
   SV *secret
   INIT:
      STRLEN len;
      const U8 *buf= (const U8*) secret_buffer_SvPVbyte(secret, &len);
   PPCODE:
      cmk_symmetric_encrypt(params, aes_key, buf, len);
      XSRETURN(1); /* return params hashref */

void
symmetric_decrypt(params, aes_key, secret_out=NULL)
   HV *params
   secret_buffer *aes_key
   secret_buffer *secret_out
   PPCODE:
      if (!secret_out) {
         secret_out= secret_buffer_new(0, &(ST(0)));
      } else {
         ST(0)= ST(2);
      }
      cmk_symmetric_decrypt(params, aes_key, secret_out);
      XSRETURN(1); /* return buffer of secret */

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
encrypt(pkey, secret_sv)
   cmk_pubkey *pkey
   SV *secret_sv
   INIT:
      STRLEN secret_len= 0;
      const U8 *secret= (const U8*) secret_buffer_SvPVbyte(secret_sv, &secret_len);
      secret_buffer *skey_buf= secret_buffer_new(0, NULL);
      HV *enc= newHV();
      SV *enc_ref= sv_2mortal(newRV_noinc((SV*) enc)); /* ensure HV gets cleaned up on error */
   PPCODE:
      cmk_pkey_generate_key_material(pkey, enc, skey_buf);
      cmk_symmetric_encrypt(enc, cmk_hkdf(enc, skey_buf), secret, secret_len);
      PUSHs(enc_ref);

void
decrypt(pkey, enc)
   cmk_pubkey *pkey
   HV *enc
   INIT:
      SV *secret_ref= NULL;
      secret_buffer *secret= secret_buffer_new(0, &secret_ref);
      secret_buffer *skey_buf= secret_buffer_new(0, NULL);
   PPCODE:
      cmk_pkey_recreate_key_material(pkey, enc, skey_buf);
      cmk_symmetric_decrypt(enc, cmk_hkdf(enc, skey_buf), secret);
      PUSHs(secret_ref);

MODULE = Crypt::MultiKey               PACKAGE = Crypt::MultiKey::Coffer

BOOT:
   HV *stash= gv_stashpvs("Crypt::MultiKey", 1);
