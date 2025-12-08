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

/* Generate an AES key from the public key and store the public data in enc_out */
extern secret_buffer * cmk_pkey_create_aes_key(cmk_pkey *pubkey, HV *enc_out);

/* Produce an AES key from the private key and the parameters in 'enc' */
extern secret_buffer * cmk_pkey_recreate_aes_key(cmk_pkey *privkey, HV *enc);

/* Use the public half of a ::Key object to encrypt arbitrary data (usually an AES key)
 * and store the ciphertext and other details into `enc_out`.
 * This is a combination of cmk_key_create_aes_key and cmk_aes_encrypt.
 */
extern void cmk_pkey_encrypt(cmk_pkey *pubkey, const U8 *secret, size_t secret_len, HV *enc_out);

/* Use the private half of a ::Key object to decrypt the supplied hash of parameters
 * back to the original secret, stored into secret_out.
 * This is a combination of cmk_key_recreate_aes_key and cmk_aes_decrypt.
 */
extern void cmk_pkey_decrypt(cmk_pkey *privkey, HV *enc_in, secret_buffer *secret_out);

/* Perform symmetric encryption using the supplied AES key, storing the ciphertext and parameters
 * into the hash `enc_out`.
 */
extern void cmk_aes_encrypt(secret_buffer *aes_key, const U8 *secret, size_t secret_len, HV *enc_out);

/* Perform symmetric decryption using the supplied AES key and ciphertext and parameters in enc_in,
 * storing the original secret into secret_out.
 */
extern void cmk_aes_decrypt(secret_buffer *aes_key, HV *enc_in, secret_buffer *secret_out);

#endif /* define CMK_H */
