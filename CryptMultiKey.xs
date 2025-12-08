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
generate_uuid_v4()
   PPCODE:
      XPUSHs(cmk_generate_uuid_v4(sv_newmortal()));

void
aes_encrypt(aes_key, secret, enc_out=NULL)
   secret_buffer *aes_key
   SV *secret
   HV *enc_out
   INIT:
      STRLEN len;
      const char *buf= secret_buffer_SvPVbyte(secret, &len);
   PPCODE:
      if (!enc_out) {
         enc_out= newHV();
         ST(0)= sv_2mortal(newRV_noinc((SV*)enc_out));
      } else {
         ST(0)= ST(2);
      }
      cmk_aes_encrypt(aes_key, buf, len, enc_out);
      XSRETURN(1);

void
aes_decrypt(aes_key, enc, secret_out=NULL)
   secret_buffer *aes_key
   HV *enc
   secret_buffer *secret_out
   PPCODE:
      if (!secret_out) {
         secret_out= secret_buffer_new(0, &(ST(0)));
      } else {
         ST(0)= ST(2);
      }
      cmk_aes_decrypt(aes_key, enc, secret_out);
      XSRETURN(1);

MODULE = Crypt::MultiKey                PACKAGE = Crypt::MultiKey::PKey

void
_keygen(pkey, type)
   auto_cmk_pkey *pkey
   const char *type
   PPCODE:
      cmk_pkey_keygen(pkey, type);

bool
has_private_loaded(pkey)
   maybe_cmk_pkey *pkey
   CODE:
      RETVAL= pkey && cmk_pkey_has_private(pkey);
   OUTPUT:
      RETVAL

void
_import_pubkey(pkey, buffer)
   auto_cmk_pkey *pkey
   SV *buffer
   INIT:
      STRLEN len;
      const char *buf= secret_buffer_SvPVbyte(buffer, &len);
   PPCODE:
      cmk_pkey_import_pubkey(pkey, buf, len);

void
_import_pkcs8(pkey, buffer, pass_sv=&PL_sv_undef)
   auto_cmk_pkey *pkey
   SV *buffer
   SV *pass_sv
   INIT:
      STRLEN len, pass_len= 0;
      const char *buf= secret_buffer_SvPVbyte(buffer, &len);
      const char *pass= SvOK(pass_sv)? secret_buffer_SvPVbyte(pass_sv, &pass_len) : NULL;
   PPCODE:
      cmk_pkey_import_pkcs8(pkey, buf, len, pass, pass_len);

void
_export_pubkey(pkey, buf)
   cmk_pubkey *pkey
   SV *buf
   PPCODE:
      cmk_pkey_export_pubkey(pkey, buf);

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
encrypt(pkey, secret, enc_out=NULL)
   cmk_pubkey *pkey
   SV *secret
   HV *enc_out
   INIT:
      STRLEN len;
      const char *buf= secret_buffer_SvPVbyte(secret, &len);
   PPCODE:
      if (!enc_out) {
         enc_out= newHV();
         ST(0)= sv_2mortal(newRV_noinc((SV*)enc_out));
      } else {
         ST(0)= ST(2);
      }
      cmk_pkey_encrypt(pkey, buf, len, enc_out);
      XSRETURN(1);

void
decrypt(pkey, enc, secret_out=NULL)
   cmk_privkey *pkey
   HV *enc
   secret_buffer *secret_out
   PPCODE:
      if (!secret_out) {
         secret_out= secret_buffer_new(0, &(ST(0)));
      } else {
         ST(0)= ST(2);
      }
      cmk_pkey_decrypt(pkey, enc, secret_out);
      XSRETURN(1);

MODULE =  Crypt::MultiKey               PACKAGE = Crypt::MultiKey::Coffer

BOOT:
   HV *stash= gv_stashpvs("Crypt::MultiKey", 1);
