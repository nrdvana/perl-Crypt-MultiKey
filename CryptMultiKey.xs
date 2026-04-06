#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"
#include "ppport.h"
#include "cmk.h"

#include <openssl/evp.h>
#include <openssl/rand.h>

/* For exported constant dualvars */
#define EXPORT_ENUM(x) newCONSTSUB(stash, #x, new_enum_dualvar(aTHX_ x, newSVpvs_share(#x)))
static SV * new_enum_dualvar(pTHX_ IV ival, SV *name) {
   SvUPGRADE(name, SVt_PVNV);
   SvIV_set(name, ival);
   SvIOK_on(name);
   SvREADONLY_on(name);
   return name;
}

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

INCLUDE: lib/Crypt/MultiKey/PKey.xs
INCLUDE: conditional.xs

BOOT:
   HV *stash= gv_stashpvs("Crypt::MultiKey", 1);
