#ifndef CMK_FIDO2_H
#define CMK_FIDO2_H

/* Wrap a fido_dev_t with a blessed Crypt::MultiKey::FIDO2::Device object, which will then
 * own and control the lifespan of the fido_dev_t.  The info may be provided to populate
 * some attributes of the new object.
 */
extern SV *cmk_fido2_wrap_dev(fido_dev_t *dev);

/* Get the fido_dev_t from a Crypt::MultiKey::FIDO2::Device object */
extern fido_dev_t *cmk_fido2_dev_from_magic(SV *objref, int flags);

/* Set the fido_dev_t pointer into magic on the object */
extern void cmk_fido2_dev_set_magic(SV *objref, fido_dev_t *dev);

/* get error string for libfido2 error code */
extern const char *cmk_fido2_err_name(int err_code);

/* assign objref->{fido_err} to a dualvar of the error code */
extern void cmk_fido2_set_last_err(SV *objref, int err_code);

/* Return AV (which caller must free) of the available FIDO2 devices. */
extern AV *cmk_fido2_list_devices(void);

extern void cmk_fido2_dev_load_info_attrs(SV *dev_objref, const fido_dev_info_t *info);
extern HV* cmk_fido2_dev_load_cbor_attrs(SV *dev_objref);

extern SV* cmk_fido2_device_new(const char *path);

/* Request a FIDO2 device to create a new credential */
extern SV* cmk_fido2_make_credential(SV *dev_objref, const char *pin,
   bool discoverable, const char *rp_domain, const char *rp_name,
   const char *user_name, const char *user_display_name, const char *user_icon);

/* Perform challenge/response using hmac-secret API of the FIDO2 protocol.
 * This can supply multiple credentials and succeed if any of them are the correct credential
 *   for this hardware authenticator.
 */
extern int cmk_fido2_assert_hmac_secret(SV *dev_objref, const char *pin,
   const char *rp_domain, AV *credentials, const U8 *salt, size_t salt_len,
   secret_buffer *out);

#endif
