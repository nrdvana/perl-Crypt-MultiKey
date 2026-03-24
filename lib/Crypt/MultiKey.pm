package Crypt::MultiKey;
# VERSION
# ABSTRACT: Toolkit for encrypting data that can be unlocked by multiple key combinations

=head1 SYNOPSIS

  use Crypt::MultiKey qw( pkey coffer );
  use Crypt::SecretBuffer qw( secret );
  
  # Encrypt data with your public key
  my $pubkey= pkey(load => '~/.ssh/id_rsa.pub');
  my $encrypted= $pubkey->encrypt("secret data");
  
  # Load your private key
  my $privkey= pkey(load => '~/.ssh/is_rsa');
  
  # If your private key is itself encrypted, prompt for password
  if ($privkey->private_encrypted) {
    my $pasword= secret;
    $password->append_console_line(prompt => 'password: ')
      or die "require password";
    $privkey->decrypt_private($password);
  }
  
  # use private key to decrypt data
  my $secret= $privkey->decrypt($encrypted);

  # Store multiple data strings in a Coffer, locked with a variety of keys
  my $coffer= coffer(content_kv => {
    secret1 => "REDACTED",
    secret2 => "REDACTED",
  });
  $coffer->add_access($privkey);      # now $privkey can unlock
  my $key2= pkey(generate => 'x25519');
  my $key3= pkey(generate => 'secp256k1');
  $coffer->add_access($key2, $key3);  # now $key2+$key3 can unlock
  $coffer->save('coffer.pem');
  
  # Open a coffer
  $coffer= coffer(load => 'coffer.pem');
  $coffer->unlock($privkey);
  # or $coffer->unlock($key2, $key3);
  
  # content of a coffer is a SecretBuffer
  $coffer->content_kv->{secret1}->unmask_to(sub { say $_[0] });
  
=head1 DESCRIPTION

This module collection is an implementation of a "key wrapping scheme" (such as done by
L<age(1)> or libsodium) packaged as an object resembling a password safe
(L<Coffer|Crypt::MultiKey::Coffer>) and also as an object representing an encrypted block device
(L<Vault|Crypt::MultiKey::Vault>, similar to Linux LUKS) and comes with a handy
L<PKey|Crypt::MultiKey::PKey> object that can load a variety of existing public/private key
formats and use a variety of methods to decrypt them, such as
L<::PKey::FIDO2|Crypt::MultiKey::PKey::FIDO2> for using hardware authenticators as passwords.

Since there are so many "secrets" and "keys" involved in this system, I'm using the following
metaphor to help disambiguate them:

=over

=item PKey

The L<PKey|Crypt::MultiKey::PKey> objects are wrappers around a public/private key system,
currently implemented with OpenSSL's C<EVP_PKEY>.
A PKey can either be a full public/private key, a public key missing the private half, or a
public key with an encrypted private half.
Subclasses of C<Crypt::MultiKey::PKey> implement different ways of recovering the private half
of the key; for example the L<Crypt::MultiKey::PKey::SSHAgentSignature> can use a signature
from an SSH agent as a password to decrypt the private half of the PKey, and the
L<Crypt::MultiKey::PKey::FIDO2> uses a challenge/response from a FIDO2 hardware authenticator
(e.g. YubiKey) as a password to unlock the private half.

PKey objects can be loaded from OpenSSL public key PEM files, OpenSSL private key PEM files,
OpenSSH public keys, and OpenSSH private keys, and in limited cases even encrypted OpenSSH
private keys.  Newly-generated keys are saved as OpenSSL PEM format with additional headers to
hold the attributes of the object.

=item Coffer

A L<Coffer|Crypt::MultiKey::Coffer> object is a container that implements a key-wrapping scheme
where a master "file key" is encrypted with one or more "Locks" and each "Lock" can require one
or more PKeys to unlock it.  A symmetric AES key is derived from the file key and used to
encrypt the data payload.  Coffers are also stored in PEM format, with PEM headers that describe
which keys can unlock the Coffer, and a MAC to guard against tampering.

The coffer file may also contain any number of PKey PEM blocks if you wish to keep all the
coffer's keys (with private-half encrypted) bundled in the same file to ensure they don't get
lost.

Because a Coffer is always locked using public/private key pairs, the coffer can be re-encrypted
at any time without needing the private halves available.

=item Vault

A L<Vault|Crypt::MultiKey::Vault> object is a container just like a Coffer but designed for
compatibility with Linux's dm-crypt implementation.  The Vault can be unlocked and then an
offset can be bound to a loopback device, and then initialize dm-crypt so that the rest of the
file can be read/written directly by a Linux Device Mapper block device.  In this case,
Crypt::MultiKey is really just acting as a substitute for LUKS.

=back

=head2 Motivation

The use case this module was designed to solve was to allow encryped volumes on a server to be
unlocked with more than one method:

=over

=item * A key server, using SSL certs for authentication

=item * A SSH private key from the Agent of a logged-in user

=item * A Yubikey

=item * A very secure password stored offline

=back

Every time the server boots, it needs the encrypted volumes unlocked.  If it is online, it
contacts the central key server and the key server is able to send a response that allows the
activation of that key.   If the key server is offline or unavailable, an admin with a SSH key
can connect and forward their SSH agent to unlock the volumes.  If an admin can't connect
remotely or can't be reached, someone on-site with a physically secure Yubikey can retrieve and
plug in the key and then udev rules automatically trigger to unlock the encrypted volumes.
If all else fails, someone can go to the safe deposit box and get the sheet of paper where the
secret is written and read it to someone over the phone.  Further, any or all of these unlock
methods can be added or removed without needing to have all the secrets present.

This module collection facilitates all of that.

=cut

use strict;
use warnings;
use Carp;
use parent qw( DynaLoader Exporter );
use Crypt::SecretBuffer 0.020;
sub dl_load_flags {0x01} # Share extern symbols with other modules
__PACKAGE__->bootstrap;

our $openssl_version;
sub _openssl_version {
   $openssl_version ||= do {
      require version;
      version->parse('v'.join('.', Crypt::MultiKey::_openssl_version_components()));
   }
}

our @EXPORT_OK= qw(
   pkey coffer vault sha256 hkdf hmac_sha256 symmetric_encrypt symmetric_decrypt
   lazy_load lazy_loadable
);

=head1 FUNCTIONS

All functions can be exported, or called by the full package name.
They cannot be called as class methods.

=head2 pkey

Shortcut for C<< Crypt::MultiKey::PKey->new(@_) >>.

=head2 coffer

Shortcut for C<< Crypt::MultiKey::Coffer->new(@_) >>.

=head2 vault

Shortcut for C<< Crypt::MultiKey::Vault->new(@_) >>.

=cut

sub pkey {
   Crypt::MultiKey::PKey->new(@_);
}

sub coffer {
   require Crypt::MultiKey::Coffer;
   Crypt::MultiKey::Coffer->new(@_);
}

sub vault {
   require Crypt::MultiKey::Vault;
   Crypt::MultiKey::Vault->new(@_);
}

=head2 hkdf

  my %params;
  $secret_buffer= hkdf(\%params, $secret_key_material);
  # %params:
  #   size           - number of bytes to generate
  #   cipher         - substitute for 'size'; name of a cipher with known size requirement
  #   kdf_info       - namespace for key derivation
  #   kdf_salt       - salt bytes, will be generated if not provided

This runs OpenSSL's C<EVP_PKEY_HKDF> with C<EVP_sha256>, supplying 'info' and 'salt' and storing
the output into a new SecretBuffer object.

=head2 sha256

  $secret_buffer= sha256(@strings);

Feed one or more strings
(which may be L<SecretBuffers|Crypt::SecretBuffer> or L<Spans|Crypt::SecretBuffer::Span>)
into C<SHA256> and return the result as a L<Crypt::SecretBuffer>.
The buffer contains raw bytes, not hex or base64.

=head2 hmac_sha256

  $secret_buffer= hmac_sha256($mac_key, @strings);

Feed a key and one or more strings
(which may be L<SecretBuffers|Crypt::SecretBuffer> or L<Spans|Crypt::SecretBuffer::Span>)
into C<HMAC-SHA256> and return the result as a C<Crypt::SecretBuffer>.
The buffer contains raw bytes, not hex or base64.

=head2 symmetric_encrypt

  my %params;
  symmetric_encrypt(\%params, $aes_key, $secret);
  # %params:
  #   cipher     - Currently must be AES-256-GCM; will be assigned if unset
  #   pad        - optionally harden the secret with a prefix of random bytes
  #                and pad to specified length.
  #   auth_data  - optional Additional Authenticated Data (AAD) for AES-GCM
  #                to include in the validation tag of the ciphertext.
  #                In other words, cause decryption to fail if it isn't given
  #                identical 'auth_data'.  The failure will be indistinguishable
  #                from an incorrect $aes_key.
  #   ciphertext - set on output to the encrypted bytes of ciphertext

This performs encryption using a cipher (currently always C<AES-256-GCM>) and optional padding
to obscure the length of the secret.  The ciphertext is written into a field of C<%params>.
You must preserve the entire contents of C<%params> to be passed to C<symmetric_decrypt>.
The C<$aes_key> should be a L<SecretBuffer|Crypt::SecretBuffer> object and must be the correct
length for the cipher.  Use L</hkdf> to get a key the correct length.

If you use C<auth_data>, you should I<not> serialize that alongside the other parameters, and
instead reconstruct the C<auth_data> before decryption.

=head2 symmetric_decrypt

  my %params= ...;         # previous encryption result hashref
  $params{auth_data}= ...; # if you used auth_data during encryption
  my $secret= symmetric_decrypt(\%params, $aes_key);

This decrypts the previous result of C<symmetric_encrypt>.  If using C<AES-GCM>, it will also
verify whether the C<$aes_key> was the correct key, and croak on failure.

=head2 lazy_load

  $class= lazy_load($class);

Given a class name, perform 'require' on that class name if and only if it is in the permitted
set of L</lazy_loadable>.

=head2 lazy_loadable

Convenient accessor for C<< %Crypt::MultiKey::lazy_loadable >>.  Returns a global hashref of the
names of classes which are safe to load on demand; i.e. from tainted input requesting a class be
used to process that input.  This hashref is writeable so that other modules may add more names
to the list.

=cut

# For security, only permit loading packages which are known to be safe to construct from
# external configuration.
our %lazy_loadable= map +($_ => 1), qw(
   Crypt::MultiKey::PKey::Unencrypted
   Crypt::MultiKey::PKey::FIDO2
   Crypt::MultiKey::PKey::YKChalResp
   Crypt::MultiKey::PKey::SSHAgentSignature
);
sub lazy_loadable { \%lazy_loadable }

sub lazy_load {
   my ($class)= @_;
   croak "Class '$class' is not marked as safe for lazy-loading"
      unless $lazy_loadable{$class};
   (my $fname= $class . '.pm') =~ s,::,/,g;
   require $fname;
   return $class;
}

# Can't do anything useful without PKey, so load it automatically
require Crypt::MultiKey::PKey;

1;
__END__

=head1 SEE ALSO

=over

=item L<age|https://age-encryption.org>

"age is a simple, modern and secure file encryption tool, format, and Go library."

This tool can encrypt a secret using one or more public keys, to then be decrypted using any of
the corresponding private keys.

=item L<libsodium|https://github.com/jedisct1/libsodium>

"Sodium is an easy-to-use software library that provides a wide range of cryptographic
operations including encryption, decryption, digital signatures, and secure password hashing."

libsodium provides a "box" primitive that is a key-wrapping scheme similar to Coffer.

There are Perl bindings at L<Crypt::Sodium>.

=back
