#ifndef CMK_H
#define CMK_H

/* platform compatibility */
#include "CryptMultiKey_config.h"

/* the public API */
#include "CryptMultiKey.h"

/* optional bits */
#ifdef HAVE_LIBFIDO2
  #include "cmk_fido2.h"
#endif
#ifdef HAVE_LINUX_HIDRAW
  #include "cmk_yubico_otp.h"
#endif

/* This file is for things shared by multiple compilation units
 * but which should not be part of the public API. */

extern MAGIC* cmk_get_X_magic(pTHX_ SV *obj, int flags, const MGVTBL *mg_vtbl, const char *mg_desc);

#define STRINGIFY_MACRO(x) #x
#define GOTO_CLEANUP_CROAK(msg) do { err= msg; goto cleanup; } while(0)

#endif
