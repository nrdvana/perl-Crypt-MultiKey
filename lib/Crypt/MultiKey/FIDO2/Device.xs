MODULE = Crypt::MultiKey      PACKAGE = Crypt::MultiKey::FIDO2::Device   PREFIX = fido_dev_

void
open(dev_sv, path)
   SV *dev_sv
   const char *path
   INIT:
      fido_dev_t *dev= NULL;
      int rc;
   PPCODE:
      /* this could be the first function called in a new thread */
      fido_init(0);
      dev= fido_dev_new();
      if (!dev)
         croak("fido_dev_new failed");
      if ((rc= fido_dev_open(dev, path)) == FIDO_OK) {
         cmk_fido2_dev_set_magic(dev_sv, dev);
         hv_stores((HV*)SvRV(dev_sv), "path", newSVpv(path, 0));
         XSRETURN_YES;
      }
      else {
         fido_dev_free(&dev);
         cmk_fido2_set_last_err(dev_sv, rc);
         XSRETURN_UNDEF;
      }

HV*
_cbor_attrs(dev_objref)
   SV *dev_objref
   CODE:
      /* returned HV is owned by dev_objref, gets a new reference created to it */
      RETVAL= cmk_fido2_dev_load_cbor_attrs(dev_objref);
   OUTPUT:
      RETVAL

bool
fido_dev_is_fido2(dev)
   fido_dev_t *dev

bool
fido_dev_supports_pin(dev)
   fido_dev_t *dev

bool
fido_dev_supports_uv(dev)
   fido_dev_t *dev

bool
fido_dev_has_pin(dev)
   fido_dev_t *dev

bool
fido_dev_has_uv(dev)
   fido_dev_t *dev

void
get_touch_begin(dev)
   fido_dev_t *dev
   INIT:
      int rc;
   PPCODE:
      rc= fido_dev_get_touch_begin(dev);
      if (rc == FIDO_OK) {
         XSRETURN_YES;
      } else {
         cmk_fido2_set_last_err(ST(0), rc);
         XSRETURN_UNDEF;
      }

void
get_touch_status(dev, timeout)
   fido_dev_t *dev
   NV timeout
   INIT:
      int rc, touched;
   PPCODE:
      rc= fido_dev_get_touch_status(dev, &touched, (int)(timeout*1000));
      if (rc != FIDO_OK) {
         cmk_fido2_set_last_err(ST(0), rc);
         XSRETURN_UNDEF;
      } else if (touched) {
         XSRETURN_YES;
      } else {
         XSRETURN_NO;
      }

void
cancel(dev)
   fido_dev_t *dev
   INIT:
      int rc;
   PPCODE:
      rc= fido_dev_cancel(dev);
      if (rc == FIDO_OK) {
         XSRETURN_YES;
      } else {
         cmk_fido2_set_last_err(ST(0), rc);
         XSRETURN_UNDEF;
      }

SV*
_make_hmac_secret_credential(dev, pin_sv, discoverable, rp_domain, rp_name, user_name, user_display_name, user_icon=NULL)
   SV *dev
   SV *pin_sv
   bool discoverable
   const char *rp_domain
   const char *rp_name
   const char *user_name
   const char *user_display_name
   const char *user_icon
   INIT:
      const char *pin= SvOK(pin_sv)? SvPV_nolen(pin_sv) : NULL;
   CODE:
      RETVAL= cmk_fido2_make_credential(dev, pin, discoverable, rp_domain, rp_name, user_name, user_display_name, user_icon);
   OUTPUT:
      RETVAL

void
_assert_hmac_secret(dev, pin_sv, rp_domain, credentials, challenge)
   SV *dev
   SV *pin_sv
   const char *rp_domain
   AV *credentials
   SV *challenge
   INIT:
      STRLEN challenge_len;
      const U8 *challenge_buf= (const U8*) secret_buffer_SvPVbyte(challenge, &challenge_len);
      SV *resp_ref= NULL;
      secret_buffer *resp= secret_buffer_new(0, &resp_ref);
      int cred_idx;
      const char *pin= SvOK(pin_sv)? SvPV_nolen(pin_sv) : NULL;
   PPCODE:
      cred_idx= cmk_fido2_assert_hmac_secret(dev, pin, rp_domain, credentials, challenge_buf, challenge_len, resp);
      if (cred_idx >= 0) {
         ST(0)= sv_2mortal(newSViv(cred_idx));
         ST(1)= resp_ref;
         XSRETURN(2);
      } else {
         /* -2 means timeout waiting for button press or button press failed in some way.
          * -1 means the key doesn't contain any of the credentials.
          * All other errors would have been thrown as exceptions. */
         errno= cred_idx == -2? EAGAIN : ENOENT;
         XSRETURN(0);
      }

