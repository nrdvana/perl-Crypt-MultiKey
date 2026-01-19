#ifndef CMK_H
#define CMK_H

#include <SecretBuffer.h>

/* cmk_pkey may be a struct in the future, but for now that struct would only have one field,
 * so just declare it as a pointer-to-pointer and then it doesn't need a second allocation
 * when stored in MAGIC.  The MAGIC's pointer *is* the "struct" */
typedef EVP_PKEY* cmk_pkey;

/* Coerce an SV to be a PV with length pre-set to 'size', ready for writing.
 * Return the SV's buffer.
 */
extern char * cmk_prepare_sv_buffer(SV *sv, size_t size);

/* Store a text-notation UUID / GUID into buf_sv, enlarging it as needed. */
extern SV * cmk_generate_uuid_v4(SV *buf_sv);

/* Return a pointer-to-pointer to EVP_PKEY (which is just a typecast of the
 * MAGIC's mg_ptr) adding the magic if 'autocreate' is true.
 */
#define CMK_MAGIC_AUTOCREATE 1
#define CMK_MAGIC_OR_DIE     2
#define CMK_MAGIC_UNDEF_OK   4
extern cmk_pkey* cmk_pkey_from_magic(SV *sv, int flags);

/* Handy get/set accessors for public and private key which check the type of key actually
 * present in MAGIc and croak with useful error messages. */
extern cmk_pkey* cmk_get_pubkey(SV *objref);
extern cmk_pkey* cmk_get_privkey(SV *objref);

/* Create a new public/private keypair, store it into MAGIC on the ::PKey object,
 */
extern void cmk_pkey_keygen(cmk_pkey *pk, const char *type_and_params);
extern void cmk_pkey_keygen_params(cmk_pkey *pk, const char *type, const char **params, int param_count);

extern bool cmk_pkey_has_public(cmk_pkey *pkey);
extern bool cmk_pkey_has_private(cmk_pkey *pkey);

extern void cmk_pkey_dup(cmk_pkey *pk, cmk_pkey *orig);

/* Load the public key from the buffer and store it into MAGIC on the ::PKey object.
 * The buffer should contain ASN.1 DER bytes of RFC5280's SubjectPublicKeyInfo structure.
 */
extern void cmk_pkey_import_pubkey(cmk_pkey *pk, const U8 *buf, STRLEN buf_len);

/* Save the public key from ::PKey MAGIC into the supplied buffer.
 * The buffer receives ASN.1 DER bytes of RFC5280's SubjectPublicKeyInfo structure.
 */
extern void cmk_pkey_export_pubkey(cmk_pkey *pk, SV *buf_out);

/* Load the private key from the buffer and store it into MAGIC on the ::PKey object.
 * The buffer should contain ASN.1 DER bytes of PKCS#8 which may be storing an encrypted private
 * key that requires a password to decrypt.  It also stores the PDK iterations and other
 * encryption parameters, so only the original password is required.
 */
extern void cmk_pkey_import_pkcs8(cmk_pkey *pk, const U8 *buf, STRLEN buf_len, const char *pw, STRLEN pw_len);

/* Save the private key from ::PKey MAGIC into the supplied buffer.
 * The pasword parameter is optional, and if supplied results in an encrypted private key.
 */
extern void cmk_pkey_export_pkcs8(cmk_pkey *pk, const char *pass, STRLEN pw_len, int kdf_iter, SV *buf_out);

/* Import a key from a PEM block by best-effort of autodetecting the format.
 * This should be able to handle most OpenSSH and OpenSSL key formats.
 */
extern void cmk_pkey_import_pem(cmk_pkey *pk, const U8 *buf, STRLEN buf_len, const char *pw, STRLEN pw_len);

/* Generate symmetric key material from the public key and store the public data in tumbler_out.
 * This appends bytes to skey_buf, so multiple keys can concatenate to the same buffer
 * before running it through HKDF.
 */
extern void cmk_pkey_generate_key_material(cmk_pkey *pubkey, HV *tumbler_out, secret_buffer *skey_buf);

/* Re-create the symmetric key material from the parameters in 'tumbler' using the private key.
 * This appends bytes to skey_buf, so multiple keys can concatenate to the same buffer
 * before running it through HKDF.
 */
extern void cmk_pkey_recreate_key_material(cmk_pkey *privkey, HV *tumbler, secret_buffer *skey_buf);

/* This runs HKDF on the key material to generate an AES key.
 * It reads the cipher from the encryption parameters to know how large to make the key.
 * It also creates a random salt and stores that into the encryption parameters.
 * It uses a default HKDF "info" that can be overridden in the encryption params.
 */
secret_buffer *cmk_hkdf(HV *params, secret_buffer *key_material);

/* Perform symmetric encryption using the supplied AES key, storing the ciphertext and parameters
 * into the hash `params`.
 */
extern void cmk_symmetric_encrypt(HV *params, secret_buffer *aes_key, const U8 *secret, size_t secret_len);

/* Perform symmetric decryption using the supplied AES key and ciphertext and parameters in
 * `params`, storing the original secret into secret_out.
 */
extern void cmk_symmetric_decrypt(HV *params, secret_buffer *aes_key, secret_buffer *secret_out);

#endif /* define CMK_H */
