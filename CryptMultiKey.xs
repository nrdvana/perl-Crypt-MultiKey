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
/**********************************************************************************************\
* Typemap code that converts from Perl objects to C structs and back
\**********************************************************************************************/

#ifdef USE_ITHREADS
/* currently it is safe to clone all cmk_ structs */
static int cmk_key_magic_dup(pTHX_ MAGIC *mg, CLONE_PARAMS *param) {
   cmk_key *clone;
   PERL_UNUSED_VAR(param);
   Newxz(clone, 1, cmk_key);
   memcpy(clone, mg->mg_ptr, sizeof(cmk_key));
   mg->mg_ptr= (char*) clone;
   return 0;
};
static int cmk_key_slot_magic_dup(pTHX_ MAGIC *mg, CLONE_PARAMS *param) {
   cmk_key_slot *clone;
   PERL_UNUSED_VAR(param);
   Newxz(clone, 1, cmk_key_slot);
   memcpy(clone, mg->mg_ptr, sizeof(cmk_key_slot));
   mg->mg_ptr= (char*) clone;
   return 0;
};
static int cmk_vault_magic_dup(pTHX_ MAGIC *mg, CLONE_PARAMS *param) {
   cmk_vault *clone;
   PERL_UNUSED_VAR(param);
   Newxz(clone, 1, cmk_vault);
   memcpy(clone, mg->mg_ptr, sizeof(cmk_vault));
   mg->mg_ptr= (char*) clone;
   return 0;
};
#define SET_MGf_DUP_FLAG(mg) do { magic->mg_flags |= MGf_DUP; } while (0)
#else
#define cmk_key_magic_dup 0
#define cmk_key_slot_magic_dup 0
#define cmk_vault_magic_dup 0
#define SET_MGf_DUP_FLAG(mg) ((void)0)
#endif

static int cmk_key_magic_free(pTHX_ SV *sv, MAGIC *mg);
static MGVTBL cmk_key_magic_vtbl = {
   NULL, NULL, NULL, NULL,
   cmk_key_magic_free,
   NULL,
   cmk_key_magic_dup
#ifdef MGf_LOCAL
   ,NULL
#endif
};

static int cmk_key_slot_magic_free(pTHX_ SV *sv, MAGIC *mg);
static MGVTBL cmk_key_slot_magic_vtbl = {
   NULL, NULL, NULL, NULL,
   cmk_key_slot_magic_free,
   NULL,
   cmk_key_slot_magic_dup
#ifdef MGf_LOCAL
   ,NULL
#endif
};

static int cmk_vault_magic_free(pTHX_ SV *sv, MAGIC *mg);
static MGVTBL cmk_vault_magic_vtbl = {
   NULL, NULL, NULL, NULL,
   cmk_vault_magic_free,
   NULL,
   cmk_vault_magic_dup
#ifdef MGf_LOCAL
   ,NULL
#endif
};

/* destructor for cmk_key magic */
static int cmk_key_magic_free(pTHX_ SV* sv, MAGIC* mg) {
   if (mg->mg_ptr) {
      cmk_key_destroy((cmk_key*) mg->mg_ptr);
      Safefree(mg->mg_ptr);
      mg->mg_ptr= NULL;
   }
   return 0; /* ignored anyway */
}

/* destructor for cmk_key_slot magic */
static int cmk_key_slot_magic_free(pTHX_ SV* sv, MAGIC* mg) {
   if (mg->mg_ptr) {
      cmk_key_slot_destroy((cmk_key_slot*) mg->mg_ptr);
      Safefree(mg->mg_ptr);
      mg->mg_ptr= NULL;
   }
   return 0; /* ignored anyway */
}

/* destructor for cmk_vault magic */
static int cmk_vault_magic_free(pTHX_ SV* sv, MAGIC* mg) {
   if (mg->mg_ptr) {
      cmk_vault_destroy((cmk_vault*) mg->mg_ptr);
      Safefree(mg->mg_ptr);
      mg->mg_ptr= NULL;
   }
   return 0; /* ignored anyway */
}

/* Given a SV which you expect to be a reference to a blessed object with cmk_key magic,
 * return the secret_buffer struct pointer.
 * With no flags, this returns NULL is any of the above assumption is not correct.
 * Specify AUTOCREATE to create a new secret_buffer (and attach with magic) if it is a blessed
 * object and doesn't have the magic yet.
 * Specify OR_DIE if you want an exception instead of NULL return value.
 * Specify UNDEF_OK if you want input C<undef> to translate to C<NULL> even when OR_DIE is
 * requested.
 */
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

cmk_key * cmk_key_from_magic(SV *obj, int flags) {
   return (cmk_key*) X_from_magic(obj, flags, &cmk_key_magic_vtbl, "Crypt::MultiKey::Key", sizeof(cmk_key));
}
cmk_key_slot * cmk_key_slot_from_magic(SV *obj, int flags) {
   return (cmk_key_slot*) X_from_magic(obj, flags, &cmk_key_slot_magic_vtbl, "Crypt::MultiKey::KeySlot", sizeof(cmk_key_slot));
}
cmk_vault * cmk_vault_from_magic(SV *obj, int flags) {
   return (cmk_vault*) X_from_magic(obj, flags, &cmk_vault_magic_vtbl, "Crypt::MultiKey::vault", sizeof(cmk_vault));
}

typedef cmk_key_pubkey *       maybe_cmk_key;
typedef cmk_key *       auto_cmk_key;
typedef cmk_key_slot *  maybe_cmk_key_slot;
typedef cmk_key_slot *  auto_cmk_key_slot;
typedef cmk_vault *   maybe_cmk_vault;
typedef cmk_vault *   auto_cmk_vault;

#endif

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

MODULE = Crypt::MultiKey                PACKAGE = Crypt::MultiKey::Key

void
_keygen(key_obj, type)
   SV *key_obj
   const char *type
   PPCODE:
      cmk_key_keygen(key_obj, type);
      XSRETURN(1);

bool
_validate_public(key_obj)
   SV *key_obj
   CODE:
      cmk_key_get_pubkey(key_obj);
      RETVAL= true; /* If it didn't croak, then it was valid */
   OUTPUT:
      RETVAL

bool
_validate_private(key_obj)
   SV *key_obj
   CODE:
      cmk_key_get_privkey(key_obj);
      RETVAL= true; /* If it didn't croak, then it was valid */
   OUTPUT:
      RETVAL

void
encrypt(key_obj, secret, enc_out=NULL)
   SV *key_obj
   SV *secret
   HV *enc_out
   INIT:
      EVP_PKEY *pubkey= cmk_key_get_pubkey(key_obj);
      STRLEN len;
      const char *buf= secret_buffer_SvPVbyte(secret, &len);
   PPCODE:
      if (!enc_out) {
         enc_out= newHV();
         ST(0)= sv_2mortal(newRV_noinc((SV*)enc_out));
      } else {
         ST(0)= ST(2);
      }
      cmk_key_encrypt(pubkey, buf, len, enc_out);
      XSRETURN(1);

void
decrypt(key_obj, enc, secret_out=NULL)
   SV *key_obj
   HV *enc
   secret_buffer *secret_out
   INIT:
      EVP_PKEY *privkey= cmk_key_get_privkey(key_obj);
   PPCODE:
      if (!secret_out) {
         secret_out= secret_buffer_new(0, &(ST(0)));
      } else {
         ST(0)= ST(2);
      }
      cmk_key_decrypt(privkey, enc, secret_out);
      XSRETURN(1);

void
encrypt_private(key_obj, pass, kdf_iter=100000)
   SV *key_obj
   SV *pass
   int kdf_iter
   INIT:
      STRLEN len;
      const char *pw_buf= secret_buffer_SvPVbyte(pass, &len);
   PPCODE:
      cmk_key_encrypt_private(key_obj, pw_buf, len, kdf_iter);

void
decrypt_private(key_obj, pass)
   SV *key_obj
   SV *pass
   INIT:
      STRLEN len;
      const char *pw_buf= secret_buffer_SvPVbyte(pass, &len);
   PPCODE:
      cmk_key_decrypt_private(key_obj, pw_buf, len);

MODULE =  Crypt::MultiKey               PACKAGE = Crypt::MultiKey::Coffer

BOOT:
   HV *stash= gv_stashpvs("Crypt::MultiKey", 1);
