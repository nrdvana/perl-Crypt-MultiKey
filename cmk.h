#ifndef CMK_H
#define CMK_H

#include <SecretBuffer.h>

/* Coerce an SV to be a PV with length pre-set to 'size', ready for writing.
 * Return the SV's buffer.
 */
extern char* cmk_prepare_sv_buffer(SV *sv, size_t size);

/* Store a text-notation UUID / GUID into buf_sv, enlarging it as needed. */
extern SV* cmk_generate_uuid_v4(SV *buf_sv);

/* Return a pointer-to-pointer to EVP_PKEY (which is just a typecast of the
 * MAGIC's mg_ptr) adding the magic if 'autocreate' is true.
 */
extern EVP_PKEY ** cmk_EVP_PKEY_p_from_magic(SV *sv, bool autocreate);

/* Return the cached EVP_PKEY from the ::Key object, or deserialize it from ->{public}
 * Dies if ->{public} doesn't exist or can't be deserialized.
 */
extern EVP_PKEY *  cmk_key_get_pubkey(SV *objref);
/* Return the cached EVP_PKEY from $key->{private}, or deserialize it from ->{private}
 * Dies if ->{private} doesn't exist or can't be deserialized.
 */
extern EVP_PKEY *  cmk_key_get_privkey(SV *objref);

/* Create a new public/private keypair, store it into MAGIC on the ::Key object,
 * and serialize it into the object's ->{public} and ->{private} fields.
 */
extern EVP_PKEY *  cmk_key_keygen(SV *objref, const char *type_and_params);
/* Same as above, but with key parameters in an array instead of parsing them out of 'type' */
extern EVP_PKEY *  cmk_key_keygen_params(SV *objref, const char *type, const char **params, int param_count);

/* Create the 'private_encrypted' field of the Key object from the 'private' field
 * using AES with an aes_key derived from the supplied password.  The field 'pbkdf2_iter'
 * is consulted to determine whether to use pbkdf2, and pbk_salt field is generated if so.
 * The 'private' field is unmodified.
 * Dies on failure.
 */
extern void cmk_key_encrypt_private(SV *objref, const U8 *pw, size_t pw_len);

/* Create the 'private' field of the Key object from the 'private_encrypted' field
 * using AES with an aes_key reconstructed from the supplied password.
 * Dies on failure.
 */
extern void cmk_key_decrypt_private(SV *objref, const U8 *pw, size_t pw_len);

/* Use the public half of a ::Key object to encrypt arbitrary data (usually an AES key)
 * and store the ciphertext and other details into `enc_out`.
 */
extern void cmk_key_encrypt(EVP_PKEY *public_key, const U8 *secret, size_t secret_len, HV *enc_out);

/* Use the private half of a ::Key object to decrypt the supplied hash of parameters
 * back to the original secret, stored into secret_out.
 */
extern void cmk_key_decrypt(EVP_PKEY *private_key, HV *enc_in, secret_buffer *secret_out);

/* Perform symmetric encryption using the supplied AES key, storing the ciphertext and parameters
 * into the hash `enc_out`.
 */
extern void cmk_aes_encrypt(secret_buffer *aes_key, const U8 *secret, size_t secret_len, HV *enc_out);

/* Perform symmetric decryption using the supplied AES key and ciphertext and parameters in enc_in,
 * storing the original secret into secret_out.
 */
extern void cmk_aes_decrypt(secret_buffer *aes_key, HV *enc_in, secret_buffer *secret_out);

#endif /* define CMK_H */
