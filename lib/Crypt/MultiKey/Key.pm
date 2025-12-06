package Crypt::MultiKey::Key;
use strict;
use warnings;
use Carp;
use Crypt::SecretBuffer qw/ HEX /;
use Crypt::SecretBuffer::INI;
use Crypt::MultiKey;

=head1 SYNOPSIS

  # Generate a public/private keypair
  my $key= Crypt::MultiKey::Key->new(type => 'x25519');
  
  # encrypt the private half with a password
  my $pass= Crypt::SecretBuffer->new;
  $pass->append_console_line(STDIN) or die;
  $key->encrypt_private($pass);
  
  # encrypt some other data with the public half of the key
  my $enc= $key->encrypt("Example Plaintext");
  say JSON->new->encode($enc); # It's a hashref that you can serialize
  
  # restore the private key, using the password
  $key->decrypt_private($pass); # croaks on wrong pass
  
  # Decrypt the data
  say $key->decrypt($enc); # "Example Plaintext"

=head1 DESCRIPTION

C<Crypt::MultiKey::Key> is a public/private keypair where the public half is always available,
but the private half can be encrypted or removed.  The Key can always L</encrypt> data, but the
private half must be avalable to L</decrypt> that data again.

=attribute path

A disk path from which this key was loaded or to which it will be saved.

=attribute uuid

All keys have a UUID, used to quickly identify which Keys go to which KeySlots on Coffers.

=attribute type

The type of public-key cryptography used.  The default is C<'x25519'>.

=attribute mechanism

The mechanism for decrypting/restoring the C<privkey>.  This is used as a class name suffix for
the Key object and affects the behavior of the Key object.

=attribute public

The public key encoded as C<SubjectPublicKeyInfo> format of OpenSSL.

=attribute private

The private key stored in a SecretBuffer object, encoded as a per-algorithm format from OpenSSL's
C<i2d_PublicKey> function.  This is *not* encrypted, and this field will typically be cleared
using L</clear_private> after password-encrypting it to the L</private_pkcs8> field with the
L</encrypt_private> method.

=attribute private_pkcs8

The private key encrypted with a password and encoded in C<PCKS#8> format.
Call L</decrypt_private> to reconstruct the L</private> field from this field.

=cut

sub uuid { $_[0]{uuid} }
sub type { $_[0]{type} }
sub mechanism { die "needs overridden by subclass" }
sub public { $_[0]{public} }
sub private {
   my $self= shift;
   if (@_ > 1) {
      {
         local $self->{private}= $_[0];
         $self->_validate_private; # if it fails, we avoided setting ->{private}
      }
      $self->{private}= $_[0];
   }
   $self->{private}
}
sub private_pkcs8 { $_[0]{private_pkcs8} }

=constructor new

  $key= Crypt::MultiKey::Key->new(%attributes);

This is the constructor for the base class.  It applies and verifies the attributes above, and
then tries to apply any remaining attribute as an instance method.  Subclasses need to override
this if attributes are not writeable via accessor.

If you do not specify attribute C<public>, a new public/private keypair of L</type> will be
generated.  If you do not specify C<uuid>, a new random UUID will be generated.

=cut

sub new {
   my $class= shift;
   return $class->new_from_file(@_) if @_ == 1;
   my %attrs= @_;
   my $self= bless {}, $class;
   # Initialize UUID unless provided
   $self->{uuid}= uc(delete $attrs{uuid} // Crypt::MultiKey::generate_uuid_v4());
   $self->{uuid} =~ /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\z/i
      or croak "Invalid UUID: $self->{uuid}";
   # Create new random keypair, or validate existing public/private key vs. type
   $self->{type}= delete $attrs{type} // 'x25519';
   # consume other known attributes
   for (qw( public private private_pkcs8 )) {
      $self->{$_}= delete $attrs{$_} if defined $attrs{$_};
   }
   if (defined $self->{public}) {
      $self->_validate_public;
      $self->_validate_private if defined $self->{private};
   } else {
      croak "private key supplied, but 'public' is missing!"
         if defined $self->{private} or defined $self->{private_pkcs8};
      $self->_keygen($self->{type})
   }
   # Every remaining attribute must have a writable accessor
   $self->$_($attrs{$_}) for keys %attrs;
   return $self;
}

=constructor new_from_file

  $key= Crypt::MultiKey::Key->new_from_file($filename);

Load a file into a SecretBuffer and pass it to L</deserialize>.

=constructor deserialize

  $key= Crypt::MultiKey::Key->deserialize($scalar);
  $key= Crypt::MultiKey::Key->deserialize(\$scalar);
  $key= Crypt::MultiKey::Key->deserialize($Crypt_SecretBuffer);

This returns a key object from a serialized INI-format string or SecretBuffer.  The returned
object will be a I<subclass> of C<Crypt::MultiKey::Key>.

=cut

sub new_from_file {
   my ($class, $fname)= @_;
   $class->deserialize(Crypt::SecretBuffer->new(load_file => $fname));
}

sub deserialize {
   my ($class, $text)= @_;
   my $ini= Crypt::SecretBuffer::INI->new(
      field_config => [
         pubkey              => { encoding => HEX },
         privkey             => { encoding => HEX, secret => 1 },
         privkey_ciphertext  => { encoding => HEX },
         privkey_pbkdf2_salt => { encoding => HEX },
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
      'uuid='.$self->uuid,
      'type='.$self->type,
      'public='.unpack('H*',$self->public),
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

Using the supplied password and optional PBKDF2 iteration count, write an encrypted PKCS#8
DER-format string of bytes into attribute L</private_pkcs8>.    Ideally, C<$password> is a
C<SecretBuffer> object, but scalars are also accepted.  The password must be bytes, not wide
characters.

=method clear_private

Delete the private half of the public/private key pair.  You should only call this after
L<encrypting it|/encrypt_private>, or saving it by some other means.

=method decrypt_private

  $key->decrypt_private($password);

Using the supplied password, decrypt attribute C<private_pkcs8> and store it into attribute
L</private> as a L<SecretBuffer|Crypt::SecretBuffer>.  Ideally, C<$password> is a
C<SecretBuffer> object, but scalars are also accepted.  The password must be bytes, not wide
characters.

=cut

sub clear_private {
   # SecretBuffer destructor takes care of wiping the secret
   delete $_[0]{private};
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
