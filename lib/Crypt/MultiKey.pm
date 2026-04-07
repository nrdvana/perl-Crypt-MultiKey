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
  my $privkey= pkey(load => '~/.ssh/id_rsa');
  
  # If your private key is itself encrypted, prompt for password
  if ($privkey->private_encrypted) {
    my $password= secret;
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
(L<Coffer|Crypt::MultiKey::Coffer>) and also as an object representing encrypted block storage
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

The use case this module was designed to solve was to allow encrypted volumes on a server to be
unlocked with more than one method:

=over

=item * A key server, using SSL certs for authentication

=item * An SSH private key from the Agent of a logged-in user

=item * A YubiKey

=item * A very secure password stored offline

=back

Every time the server boots, it needs the encrypted volumes unlocked.  If it is online, it
contacts the central key server and the key server is able to send a response that allows the
activation of that key.   If the key server is offline or unavailable, an admin with a SSH key
can connect and forward their SSH agent to unlock the volumes.  If an admin can't connect
remotely or can't be reached, someone on-site with a physically secure YubiKey can retrieve and
plug in the key and then udev rules automatically trigger to unlock the encrypted volumes.
If all else fails, someone can go to the safe deposit box and get the sheet of paper where the
secret is written and read it to someone over the phone.  Further, any or all of these unlock
methods can be added or removed without needing to have all the secrets present.

This module collection facilitates all of that.

=cut

use strict;
use warnings;
use Carp;
use Scalar::Util qw( blessed looks_like_number );
use parent qw( DynaLoader Exporter );
use MIME::Base64 qw/ encode_base64 decode_base64 /;
use Crypt::SecretBuffer 0.020;
use Crypt::SecretBuffer qw( secret span );
use Encode ();
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
  my $ciphertext= symmetric_encrypt(\%params, $aes_key, $secret);
  # or
  symmetric_encrypt(\%params, $aes_key, $secret, $ciphertext_out);
  # %params:
  #   cipher     - Currently must be AES-256-GCM; will be assigned if unset
  #   pad        - optionally harden the secret with a prefix of random bytes
  #                and pad to specified length.
  #   auth_data  - optional Additional Authenticated Data (AAD) for AES-GCM
  #                to include in the validation tag of the ciphertext.
  #                In other words, cause decryption to fail if it isn't given
  #                identical 'auth_data'.  The failure will be indistinguishable
  #                from an incorrect $aes_key.
This performs encryption using a cipher (currently always C<AES-256-GCM>) and optional padding
to obscure the length of the secret.
The ciphertext is returned, or written into C<$ciphertext_out> if supplied
(which may be a byte scalar or C<Crypt::SecretBuffer>).
You must preserve both C<%params> and the ciphertext to be passed to C<symmetric_decrypt>.
The C<$aes_key> should be a L<SecretBuffer|Crypt::SecretBuffer> object and must be the correct
length for the cipher.  Use L</hkdf> to get a key the correct length.

If you use C<auth_data>, you should I<not> serialize that alongside the other parameters, and
instead reconstruct the C<auth_data> before decryption.

=head2 symmetric_decrypt

  my %params= ...;         # previous encryption parameter hashref
  my $ciphertext= ...;     # previous ciphertext bytes
  $params{auth_data}= ...; # if you used auth_data during encryption
  my $secret= symmetric_decrypt(\%params, $aes_key, $ciphertext);

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
   Crypt::MultiKey::PKey::Password
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

# Helper function to get a list of PEM objects from whatever input the user gave us
sub _extract_pems_from_something {
   my ($something, $options)= @_;
   return ( $something )
      if blessed($something) && $something->isa('Crypt::SecretBuffer::PEM');
   return map _extract_pems_from_something($_), @$something
      if ref $something eq 'ARRAY';
   # is it a path name? could be an object that stringifies to a path.
   unless (ref $something eq 'SCALAR'
           or blessed($something) && (
              $something->isa('Crypt::SecretBuffer::Span')
              || $something->isa('Crypt::SecretBuffer')
           )
   ) {
      $options->{path} //= "$something" if defined $options;
      $something= secret(load_file => $something);
   }
   # Now load all PEM blocks from that buffer
   my @pems= Crypt::SecretBuffer::PEM->parse_all(span($something))
      or croak "No complete PEM records found";
   return @pems;
}

# Helper to flatten structured data into PEM header text.
# All keys and values are exported as UTF-8.  Keys and values must meet the restrictions of
# the PEM encoder, such as no leading or trailing whitespace, no control characters, etc.
# I debated adding an automatic escaping system for "problematic" values, but that just makes
# everything more complicated and there's a large degree of uncertainty about whether a perl
# scalar should be treated as text or bytes, which would introduce all sorts of edge cases.
# It's better to just require that the values be "clean" text.
# The downside is that the caller needs to base64-encode byte strings on a field-by-field basis.
sub _flatten_to_pem_header_kv {
   my @ret;
   while (@_) {
      my ($prefix, $node)= splice(@_, 0, 2);
      if (!ref $node) {
         push @ret, Encode::encode('UTF-8', $prefix, Encode::FB_CROAK),
                    Encode::encode('UTF-8', $node, Encode::FB_CROAK);
      }
      elsif (ref $node eq 'ARRAY') {
         for (0 .. $#$node) {
            push @ret, _flatten_to_pem_header_kv($prefix.'.'.$_ => $node->[$_]);
         }
      }
      elsif (ref $node eq 'HASH') {
         for (sort keys %$node) {
            /^[^\x00-\x1F\x7F .:0-9][^\x00-\x1F\x7F .:]*\z/
               or croak "Invalid hash key for export as PEM header: '$_' at $prefix";
            push @ret, _flatten_to_pem_header_kv($prefix.'.'.$_ => $node->{$_});
         }
      }
      else {
         croak "Can't flatten type ".ref($node)." into PEM headers";
      }
   }
   return @ret;
}

# This should only be processing PEM headers that we wrote from this module, so it should be
# safe to assume that we are decoding UTF-8.
sub _inflate_pem_header_kv {
   my %attrs;
   for (my $i= 0; $i < @_; $i += 2) {
      my ($k, $v)= @_[$i,$i+1];
      $k= Encode::decode('UTF-8', $k, Encode::FB_CROAK) if $k =~ /[\x80-\xFF]/;
      $v= Encode::decode('UTF-8', $v, Encode::FB_CROAK) if $v =~ /[\x80-\xFF]/;
      my $node_ref= \\%attrs;
      for (split /\./, $k) {
         # A pure decimal element becomes an array index
         if (looks_like_number($_) && /^[0-9]+\z/) {
            if (!defined $$node_ref) {
               $$node_ref ||= [];
            }
            elsif (ref $$node_ref ne 'ARRAY') {
               croak "Can't assign to $k, not an array ref";
            }
            # Array elements must be listed in sequential order
            exists $$node_ref->[$_] or $_ == @$$node_ref
               or croak "Can't assign to $k, $_ is not the next element in the array";
            $node_ref= \$$node_ref->[$_];
         }
         else {
            if (!defined $$node_ref) {
               $$node_ref ||= {};
            }
            elsif (ref $$node_ref ne 'HASH') {
               croak "Can't assign to $k, not a hash ref at '$_'";
            }
            $node_ref= \$$node_ref->{$_};
         }
      }
      croak "Attempt to overwrite $k" if defined $$node_ref;
      $$node_ref= $v;
   }
   return \%attrs;
}

1;
__END__

=head1 SEE ALSO

=over

=item L<age|https://age-encryption.org>

"age is a simple, modern and secure file encryption tool, format, and Go library."

This tool can encrypt a secret using one or more public keys such that it can then be decrypted
using any of the corresponding private keys.

=item L<libsodium|https://github.com/jedisct1/libsodium>

"Sodium is an easy-to-use software library that provides a wide range of cryptographic
operations including encryption, decryption, digital signatures, and secure password hashing."

libsodium provides a "box" primitive that is a key-wrapping scheme similar to Coffer.

There are Perl bindings at L<Crypt::Sodium>.

=back
