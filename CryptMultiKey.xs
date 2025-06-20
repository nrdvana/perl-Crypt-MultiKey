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
static int cmk_lockbox_magic_dup(pTHX_ MAGIC *mg, CLONE_PARAMS *param) {
   cmk_lockbox *clone;
   PERL_UNUSED_VAR(param);
   Newxz(clone, 1, cmk_lockbox);
   memcpy(clone, mg->mg_ptr, sizeof(cmk_lockbox));
   mg->mg_ptr= (char*) clone;
   return 0;
};
#define SET_MGf_DUP_FLAG(mg) do { magic->mg_flags |= MGf_DUP; } while (0)
#else
#define cmk_key_magic_dup 0
#define cmk_key_slot_magic_dup 0
#define cmk_lockbox_magic_dup 0
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

static int cmk_lockbox_magic_free(pTHX_ SV *sv, MAGIC *mg);
static MGVTBL cmk_lockbox_magic_vtbl = {
   NULL, NULL, NULL, NULL,
   cmk_lockbox_magic_free,
   NULL,
   cmk_lockbox_magic_dup
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

/* destructor for cmk_lockbox magic */
static int cmk_lockbox_magic_free(pTHX_ SV* sv, MAGIC* mg) {
   if (mg->mg_ptr) {
      cmk_lockbox_destroy((cmk_lockbox*) mg->mg_ptr);
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
cmk_lockbox * cmk_lockbox_from_magic(SV *obj, int flags) {
   return (cmk_lockbox*) X_from_magic(obj, flags, &cmk_lockbox_magic_vtbl, "Crypt::MultiKey::Lockbox", sizeof(cmk_lockbox));
}

typedef cmk_key *       maybe_cmk_key;
typedef cmk_key *       auto_cmk_key;
typedef cmk_key_slot *  maybe_cmk_key_slot;
typedef cmk_key_slot *  auto_cmk_key_slot;
typedef cmk_lockbox *   maybe_cmk_lockbox;
typedef cmk_lockbox *   auto_cmk_lockbox;
#define KEYFORMAT_X25519 CMK_KEYFORMAT_X25519

/**********************************************************************************************\
* Crypt::MultiKey::Key API
\**********************************************************************************************/
MODULE = Crypt::MultiKey                PACKAGE = Crypt::MultiKey::Key
PROTOTYPES: DISABLE

bool
_is_initialized(key)
   maybe_cmk_key key
   CODE:
      RETVAL = (key != NULL);
   OUTPUT:
      RETVAL

void
_create(key, type, password, pbkdf2_iters)
   auto_cmk_key key
   int type
   secret_buffer *password
   int pbkdf2_iters
   PPCODE:
      cmk_key_create(key, type, password, pbkdf2_iters);

void
import(key, src)
   auto_cmk_key key
   HV *src
   PPCODE:
      cmk_key_import(key, src);

void
export(key, dst)
   auto_cmk_key key
   HV *dst
   PPCODE:
      cmk_key_export(key, dst);
      if (GIMME_V != G_VOID) {
         ST(0)= sv_2mortal(newRV_inc((SV*) dst));
         XSRETURN(1);
      } else {
         XSRETURN(0);
      }

void
unlock(key, buf)
   cmk_key *key
   secret_buffer *buf
   PPCODE:
      cmk_key_unlock(key, buf);

void
lock(key)
   cmk_key *key
   PPCODE:
      cmk_key_lock(key);

MODULE =  Crypt::MultiKey               PACKAGE = Crypt::MultiKey::Lockbox

bool
_is_initialized(lb)
   maybe_cmk_lockbox lb
   CODE:
      RETVAL = (lb != NULL);
   OUTPUT:
      RETVAL

void
_create(lb)
   auto_cmk_lockbox lb
   PPCODE:
      cmk_lockbox_create(lb);

void
import(lb, src)
   auto_cmk_lockbox lb
   HV *src
   PPCODE:
      cmk_lockbox_import(lb, src);

void
export(lb, dst)
   cmk_lockbox *lb
   HV *dst
   PPCODE:
      cmk_lockbox_export(lb, dst);
      if (GIMME_V != G_VOID) {
         ST(0)= sv_2mortal(newRV_inc((SV*) dst));
         XSRETURN(1);
      } else {
         XSRETURN(0);
      }

void
_unlock(lb, slot, key)
   cmk_lockbox *lb
   cmk_key_slot *slot
   cmk_key *key
   PPCODE:
      cmk_lockbox_unlock(lb, slot, key);

void
lock(lb)
   cmk_lockbox *lb
   PPCODE:
      cmk_lockbox_lock(lb);

void
encrypt(lb, plain, cipher)
   cmk_lockbox *lb
   secret_buffer *plain
   secret_buffer *cipher
   PPCODE:
      cmk_lockbox_encrypt_buffer(lb, plain, cipher);
      
void
decrypt(lb, cipher, plain)
   cmk_lockbox *lb
   secret_buffer *cipher
   secret_buffer *plain
   PPCODE:
      cmk_lockbox_decrypt_buffer(lb, cipher, plain);

MODULE = Crypt::MultiKey                PACKAGE = Crypt::MultiKey::KeySlot

bool
_is_initialized(slot)
   maybe_cmk_key_slot slot
   CODE:
      RETVAL = (slot != NULL);
   OUTPUT:
      RETVAL

void
_create(slot, lb, key)
   auto_cmk_key_slot slot
   cmk_lockbox *lb
   cmk_key *key
   PPCODE:
      cmk_key_slot_create(slot, lb, key);

void
import(slot, src)
   auto_cmk_key_slot slot
   HV *src
   PPCODE:
      cmk_key_slot_import(slot, src);

void
export(slot, dst)
   cmk_key_slot *slot
   HV *dst
   PPCODE:
      cmk_key_slot_export(slot, dst);
      if (GIMME_V != G_VOID) {
         ST(0)= sv_2mortal(newRV_inc((SV*) dst));
         XSRETURN(1);
      } else {
         XSRETURN(0);
      }

BOOT:
   HV *stash= gv_stashpvs("Crypt::MultiKey", 1);
   EXPORT_ENUM(KEYFORMAT_X25519);
