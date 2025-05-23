#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"
#include "ppport.h"

#ifdef HAVE_STDBOOL
  #include <stdbool.h>
#elif !defined(bool)
  #define bool int
  #define true 1
  #define false 0
#endif

#include "cmk.h"

/**********************************************************************************************\
* Typemap code that converts from Perl objects to C structs and back
\**********************************************************************************************/

/* destructor for cmk_key magic */
static int cmk_key_magic_free(pTHX_ SV* sv, MAGIC* mg) {
   if (mg->mg_ptr) {
      cmk_key_destroy((cmk_key*) mg->mg_ptr);
      Safefree(mg->mg_ptr);
      mg->mg_ptr= NULL;
   }
   return 0; /* ignored anyway */
}

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
#else
#define cmk_key_magic_dup NULL
#endif

/* Magic virtual method table for cmk_key.
 * Pointer to this struct is also used as an ID for type of magic
 */
static MGVTBL cmk_key_magic_vt= {
   NULL, /* get */
   NULL, /* write */
   NULL, /* length */
   NULL, /* clear */
   cmk_key_magic_free,
   NULL, /* copy */
   cmk_key_magic_dup
#ifdef MGf_LOCAL
   ,NULL
#endif
};

/* destructor for cmk_secret magic */
static int cmk_secret_magic_free(pTHX_ SV* sv, MAGIC* mg) {
   if (mg->mg_ptr) {
      cmk_secret_destroy((cmk_secret*) mg->mg_ptr);
      Safefree(mg->mg_ptr);
      mg->mg_ptr = NULL;
   }
   return 0;
}

#ifdef USE_ITHREADS
static int cmk_secret_magic_dup(pTHX_ MAGIC *mg, CLONE_PARAMS *param) {
   cmk_secret *clone;
   PERL_UNUSED_VAR(param);
   Newxz(clone, 1, cmk_secret);
   memcpy(clone, mg->mg_ptr, sizeof(cmk_secret));
   mg->mg_ptr = (char*) clone;
   return 0;
}
#else
#define cmk_secret_magic_dup NULL
#endif

static MGVTBL cmk_secret_magic_vt = {
   NULL, NULL, NULL, NULL,
   cmk_secret_magic_free,
   NULL,
   cmk_secret_magic_dup
#ifdef MGf_LOCAL
   ,NULL
#endif
};

static int cmk_locked_aes_key_magic_free(pTHX_ SV* sv, MAGIC* mg) {
   if (mg->mg_ptr) {
      Safefree(mg->mg_ptr);
      mg->mg_ptr = NULL;
   }
   return 0;
}

#ifdef USE_ITHREADS
static int cmk_locked_aes_key_magic_dup(pTHX_ MAGIC *mg, CLONE_PARAMS *param) {
   cmk_locked_aes_key *clone;
   PERL_UNUSED_VAR(param);
   Newxz(clone, 1, cmk_locked_aes_key);
   memcpy(clone, mg->mg_ptr, sizeof(cmk_locked_aes_key));
   mg->mg_ptr = (char*) clone;
   return 0;
}
#else
#define cmk_locked_aes_key_magic_dup NULL
#endif

static MGVTBL cmk_locked_aes_key_magic_vt = {
   NULL, NULL, NULL, NULL,
   cmk_locked_aes_key_magic_free,
   NULL,
   cmk_locked_aes_key_magic_dup
#ifdef MGf_LOCAL
   ,NULL
#endif
};

/* Return the cmk_key struct attached to a Perl object via MAGIC.
 * The 'obj' should be a reference to a blessed SV.
 * Use flag OR_DIE for a built-in croak() if the return value would be NULL.
 */
#define OR_DIE     1
#define AUTOCREATE 2
static cmk_key* cmk_key_from_magic(SV *obj, int flags) {
   SV *sv;
   MAGIC* magic;
   cmk_key *key;

   if (!sv_isobject(obj)) {
      if (flags & OR_DIE)
         croak("Not an object");
      return NULL;
   }
   sv= SvRV(obj);
   if (SvMAGICAL(sv) && (magic= mg_findext(sv, PERL_MAGIC_ext, &TreeRBXS_magic_vt)))
      return (struct cmk_key*) magic->mg_ptr;

   if (flags & AUTOCREATE) {
      Newxz(key, 1, cmk_key);
      magic= sv_magicext(sv, NULL, PERL_MAGIC_ext, &cmk_key_magic_vt, (const char*) key, 0);
#ifdef USE_ITHREADS
      magic->mg_flags |= MGf_DUP;
#endif
      return tree;
   }
   if (flags & OR_DIE)
      croak("Object lacks 'cmk_key' magic");
   return NULL;
}

static cmk_locked_aes_key* cmk_locked_aes_key_from_magic(SV *obj, int flags) {
   SV *sv;
   MAGIC *magic;
   cmk_locked_aes_key *lock;

   if (!sv_isobject(obj)) {
      if (flags & OR_DIE)
         croak("Not an object");
      return NULL;
   }
   sv = SvRV(obj);
   if (SvMAGICAL(sv) && (magic = mg_findext(sv, PERL_MAGIC_ext, &cmk_locked_aes_key_magic_vt)))
      return (cmk_locked_aes_key*) magic->mg_ptr;

   if (flags & AUTOCREATE) {
      Newxz(lock, 1, cmk_locked_aes_key);
      magic = sv_magicext(sv, NULL, PERL_MAGIC_ext, &cmk_locked_aes_key_magic_vt, (const char*) lock, 0);
#ifdef USE_ITHREADS
      magic->mg_flags |= MGf_DUP;
#endif
      return lock;
   }
   if (flags & OR_DIE)
      croak("Object lacks 'cmk_locked_aes_key' magic");
   return NULL;
}

static cmk_secret* cmk_secret_from_magic(SV *obj, int flags) {
   SV *sv;
   MAGIC *magic;
   cmk_secret *secret;

   if (!sv_isobject(obj)) {
      if (flags & OR_DIE)
         croak("Not an object");
      return NULL;
   }
   sv = SvRV(obj);
   if (SvMAGICAL(sv) && (magic = mg_findext(sv, PERL_MAGIC_ext, &cmk_secret_magic_vt)))
      return (cmk_secret*) magic->mg_ptr;

   if (flags & AUTOCREATE) {
      Newxz(secret, 1, cmk_secret);
      magic = sv_magicext(sv, NULL, PERL_MAGIC_ext, &cmk_secret_magic_vt, (const char*) secret, 0);
#ifdef USE_ITHREADS
      magic->mg_flags |= MGf_DUP;
#endif
      return secret;
   }
   if (flags & OR_DIE)
      croak("Object lacks 'cmk_secret' magic");
   return NULL;
}

static cmk_secret_buffer* cmk_secret_buffer_from_magic(SV *obj, int flags) {
   SV *sv;
   MAGIC *magic;
   cmk_secret_buffer *buf;

   if (!sv_isobject(obj)) {
      if (flags & OR_DIE)
         croak("Not an object");
      return NULL;
   }
   sv = SvRV(obj);
   if (SvMAGICAL(sv) && (magic = mg_findext(sv, PERL_MAGIC_ext, &cmk_secret_buffer_magic_vt)))
      return (cmk_secret_buffer*) magic->mg_ptr;

   if (flags & AUTOCREATE) {
      Newxz(buf, 1, cmk_secret_buffer);
      magic = sv_magicext(sv, NULL, PERL_MAGIC_ext, &cmk_secret_magic_vt, (const char*) buf, 0);
#ifdef USE_ITHREADS
      magic->mg_flags |= MGf_DUP;
#endif
      return secret;
   }
   if (flags & OR_DIE)
      croak("Object lacks 'cmk_secret_buffer' magic");
   return NULL;
}

typedef cmk_key            *maybe_cmk_key;
typedef cmk_secret         *maybe_cmk_secret;
typedef cmk_locked_aes_key *maybe_cmk_locked_aes_key;
typedef cmk_secret_buffer  *auto_cmk_secret_buffer;

/**********************************************************************************************\
* Crypt::MultiKey::Key API
\**********************************************************************************************/
MODULE = Crypt::MultiKey                 PACKAGE = Crypt::MultiKey::Key

bool
_is_initialized(key)
   maybe_cmk_key key
   CODE:
      RETVAL = (key != NULL);
   OUTPUT:
      RETVAL

void
_init_existing(obj, password, pbkdf_iters)
   SV *obj
   SV *password
   int pbkdf_iters
   INIT:
      cmk_key key;
      STRLEN len;
      const char *pw_str;
   CODE:
      if (cmk_secret_from_magic(obj, 0))
         croak("Already initialized");
      if (!SvPOK(password))
         croak("Password must be a scalar");
      if (pbkdf_iters < 0 || pbkdf_iters == INT_MAX)
         croak("pbkdf_iterations cannot be negative or INT_MAX");
      pw_str= SvPVbyte_force(pw_pv, len);
      /* dies if it fails */
      cmk_key_x25519_create(&key, pw_str, len, pbkdf2_iters);
      /* clone into a dynamic allocation, then wipe it */
      
      
BOOT:
   HV *inc= get_hv("INC", GV_ADD);
   AV *isa;
   hv_stores(inc, "Math::3Space::Projection",                  newSVpvs("Math/3Space.pm"));
   hv_stores(inc, "Math::3Space::Projection::Frustum",         newSVpvs("Math/3Space.pm"));
   isa= get_av("Math::3Space::Projection::Frustum::ISA", GV_ADD);
   av_push(isa, newSVpvs("Math::3Space::Projection"));
