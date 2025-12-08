package Crypt::MultiKey::PKey;
use strict;
use warnings;
use Carp;
use Crypt::SecretBuffer qw/ HEX /;
use Crypt::SecretBuffer::INI;
use Crypt::MultiKey;

=head1 SYNOPSIS

  # Generate a public/private keypair
  my $key= Crypt::MultiKey::PKey->new(type => 'x25519');
  
  # encrypt the private half with a password
  my $pass= Crypt::SecretBuffer->new;
  $pass->append_console_line(STDIN) or die;
  $key->encrypt_private($pass);
  
  # Throw away the private half
  $key->clear_private;
  
  # encrypt some other data with the public half of the key
  my $enc= $key->encrypt("Example Plaintext");
  say JSON->new->encode($enc); # It's a hashref that you can serialize
  
  # restore the private key, using the password
  $key->decrypt_private($pass); # croaks on wrong pass
  
  # Decrypt the data
  say $key->decrypt($enc); # "Example Plaintext"

=head1 DESCRIPTION

C<Crypt::MultiKey::PKey> is a public/private keypair where the public half is always available,
but the private half can be encrypted or removed.  The PKey can always L</encrypt> data, but the
private half must be avalable to L</decrypt> that data again.

=attribute type

The type of public-key cryptography used.  The default is C<'x25519'>.

=attribute fingerprint

SSH-style C<< "sha256:base64..." >> used to help identify the key.

=attribute path

A disk path from which this key was loaded or to which it will be saved.

=attribute mechanism

The mechanism for decrypting/restoring the C<privkey>.  This is used as a class name suffix for
the Key object and affects the behavior of the Key object.  Any key with the L<private_pkcs8>
attribute can be decrypted using L</decrypt_private>, but this attribute indicates the I<source>
of the password, such as whether it is a human-typed text password, or a password generated from
a YubiKey's hash function, etc.  Keys with the mechanism 'Password' will interactively prompt the
user on the console, where keys with the mechanism 'SSHAgent' will silently query the SSH agent
for whether the required SSH key is available.

=attribute public

Export the public key in ASN.1 SubjectPublicKeyInfo structure defined in RFC5280, then encode
as Hex.

=cut

sub type { $_[0]{type} }
sub fingerprint { $_[0]{fingerprint} }
sub path { $_[0]{path} }
sub private_encrypted { $_[0]{private_encrypted} }
sub mechanism { undef; }
sub public {
   shift->_export_pubkey(my $buf);
   return unpack 'H*', $buf;
}

=constructor new

  $key= Crypt::MultiKey::PKey->new(%attributes);

This is the constructor for the base class.  It applies and verifies the attributes above, and
then tries to apply any remaining attribute as an instance method.  Subclasses need to override
this if attributes are not writeable via accessor.

If you do not specify attribute C<public>, a new public/private keypair of L</type> will be
generated.  If you do not specify C<uuid>, a new random UUID will be generated.

=cut

our %type_alias= (
   rsa1024   => 'RSA:bits=1024',
   rsa2048   => 'RSA:bits=2048',
   rsa4096   => 'RSA:bits=4096',
   secp256k1 => 'EC:group=secp256k1',
);

sub new {
   my $class= shift;
   return $class->new_from_file(@_) if @_ == 1;
   my %attrs= @_;
   my $self= bless {}, $class;
   my ($type, $public, $private)= delete @attrs{'type','public','private'};
   # If 'private' is present, it contains the whole unencrypted key.
   # 'public' may also be present but we ignore it.
   if (defined $private) {
      $self->_import_pkcs8(pack '(H2)*', $private);
   # If 'public' is present, it may be paired with 'private_encrypted' so that the user
   # can decrypt it later.
   } elsif (defined $public) {
      $self->_import_pubkey(pack '(H2)*', $public);
      $self->{private_encrypted}= delete $attrs{private_encrypted};
   # else generate a new key of the specified type, defaulting to x25519
   } else {
      $type= $type && $type_alias{lc $type} || $type || 'x25519';
      $self->_keygen($type);
   }
   # save the type regardless of how we loaded it.  It could become inconsistent with the actual
   # key type if someone tampered with private attributes or edited the file, but it would be a
   # lot of work to verify it or reconstruct it from the key.
   $self->{type}= $type;
   # Every remaining attribute must have a writable accessor
   $self->$_($attrs{$_}) for keys %attrs;
   return $self;
}

=constructor new_from_file

  $key= Crypt::MultiKey::PKey->new_from_file($filename);

Load a file into a SecretBuffer and pass it to L</deserialize>.

=constructor deserialize

  $key= Crypt::MultiKey::PKey->deserialize($scalar);
  $key= Crypt::MultiKey::PKey->deserialize(\$scalar);
  $key= Crypt::MultiKey::PKey->deserialize($Crypt_SecretBuffer);

This returns a key object from a serialized INI-format string or SecretBuffer.  The returned
object will be a I<subclass> of C<Crypt::MultiKey::PKey>.

=cut

sub new_from_file {
   my ($class, $fname)= @_;
   $class->deserialize(Crypt::SecretBuffer->new(load_file => $fname));
}

sub deserialize {
   my ($class, $text)= @_;
   my $ini= Crypt::SecretBuffer::INI->new(
      field_config => [
         public              => { encoding => HEX },
         private             => { encoding => HEX, secret => 1 },
         private_encrypted   => { encoding => HEX },
      ]
   );
   my $sections= $ini->parse($text);
   ref $sections eq 'ARRAY' && @$sections == 2
      or croak "Expected one INI-style header followed by attributes in Key file";
   my $subclass= $sections->[0];
   # Security check - class must already be loaded, or in the list of autoloads
   Crypt::MultiKey::_lazy_load_class($subclass)
      unless $subclass->can('new');
   $subclass->isa($class)
      or croak "Expected subclass of '$class' but got '$subclass'";
   $subclass->new(%{ $sections->[1] });
}

=method serialize

Export the attributes of the Key as a SecretBuffer object containing INI-format text.
This excludes the L</private> attribute unless L</mechanism> is C<'Unencrypted'>.

=method save

  $key->save;         # saves to $key->path
  $key->save($path);  # saves to $path and sets $key->path if not already set

This is a shortcut for C<< $key->serialize->save_file($key->path, "rename") >>.

=cut

sub serialize {
   my ($self, $buf)= @_;
   $buf ||= Crypt::SecretBuffer->new;
   $buf->append(join "\n",
      '['.ref($self).']',
      'type='.$self->type,
      '# ASN.1 SubjectPublicKeyInfo structure defined in RFC5280',
      'public='.$self->public,
      (defined $self->{private_encrypted}? (
         '# PKCS#8 Encrypted Private Key',
         'private_encrypted='.$self->{private_encrypted},
      ):()),
   );
   return $buf;
   # subclass needs to append additional attributes
}

sub save {
   my ($self, $path)= @_;
   $path //= $self->path;
   defined $path or croak "No 'path' specified for saving key";
   $self->serialize->save_file($path, "rename");
   $self->path($path) if !defined $self->path;
}

=method encrypt_private

  $key->encrypt_private($password, $kdf_iter=100_000);

Export the (private) key in PKCS#8 format, encrypted with a password, and stored into attribute
C<private_encrypted> to be saved out by a subsequent L</save> call.
You may customize the number of iterations for the key-derivation-function to resist brute-force
attempts.  If the password is known to be a string of hashed data with uniformly-distributed
bits, you may reduce the kdf_iterations to 1.  (but it cannot be zero, due to OpenSSL API).
Ideally, C<$password> is a C<SecretBuffer> object, but scalars are also accepted.
The password must be bytes, not wide characters.

=cut

sub encrypt_private {
   my $self= shift;
   defined $_[0] or die "Missing password";
   my $buf= '';
   $self->_export_pkcs8($buf, $_[0], $_[1] || 100_000);
   $self->{private_encrypted}= unpack 'H*', $buf;
   $self;
}

=method clear_private

Delete the private half of the public/private key pair.  You should only call this after
L<encrypting it|/encrypt_private>, or saving it by some other means.

=cut

sub clear_private {
   my $self= shift;
   $self->_export_pubkey(my $buf);
   $self->_import_pubkey($buf);
   $self;
}

=method decrypt_private

  $key->decrypt_private($password);

Using the supplied password, decrypt attribute C<private_encrypted> and import it.
Ideally, C<$password> is a C<SecretBuffer> object, but scalars are also accepted.
The password must be bytes, not wide characters.

=cut

sub decrypt_private {
   my $self= shift;
   defined $_[0] or die "Missing password";
   my $raw= pack 'H*', $self->{private_encrypted};
   $self->_import_pkcs8($raw, $_[0]);
   $self;
}

=method encrypt

  $fields= $key->encrypt($secret);
  $key->encrypt($secret, \%fields_out);

Encrypt a secret using the public half of this key.  The secret is ideally a C<SecretBuffer>
object, but may also be a scalar.  The return value is a hashref containing the ciphertext
and other fields that are required to decrypt it, and which depend on the type of key used.
You may supply a second argument of a pre-existing hashref to be filled.

=method decrypt

  $secret_buffer= $key->decrypt(\%fields);
  $key->decrypt(\%fields, $secret_buffer_out);

Decrypt a secret using the private half of this key.  (and dies if the private half of the key
is not currently available)  The hash of fields must include everything written by C<encrypt>.
The original secret is returned as a L<SecretBuffer object|Crypt::SecretBuffer>, and you may
supply a second argument of a pre-existing buffer to be filled instead of allocating a new one.

=cut

1;
