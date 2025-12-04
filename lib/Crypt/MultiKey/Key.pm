package Crypt::MultiKey::Key;
use strict;
use warnings;
use Carp;
use Crypt::SecretBuffer qw/ HEX /;
use Crypt::SecretBuffer::INI;

=head1 DESCRIPTION

A Crypt::MultiKey::Key is composed of the public half of a public key cryptography scheme, and
the means to either decrypt the private half stored locally, or re-combine with the private half
stored separately.  Once the private half is available, the Key object can be used to unlock
L<Coffers|Crypt::MultiKey::Coffer>.

A Key can be paired with an unlocked Coffer (generating a KeySlot on the Coffer) regardless of
whether the Key's private half is available.

=attribute uuid

All keys have a UUID, used to quickly identify which Keys go to which KeySlots on Coffers.

=attribute type

The type of public-key cryptography used.  The default is C<'x25519'>.

=attribute mechanism

The mechanism for decrypting/restoring the C<privkey>.  This is used as a class name suffix for
the Key object and affects the behavior of the Key object.

=attribute public

The raw bytes of the public key.  (not printable)

=attribute private

The raw bytes of the private key, stored in a L<Crypt::SecretBuffer> instance.
This field will normally not be stored anywhere, and needs reconstructed from some mechanism.

=attribute private_encrypted

The raw bytes of a ciphertext containing the private key.  This attribute is used by several
of the mechanisms, but not all.

=attribute private_encrypted_cipher

The cipher that created L</private_encrypted> from L</private>, currently always C<AES-256-ECB>.

=attribute pbkdf2_iter

If this attribute is defined, it is a count of PBKDF2 iterations that were applied to a password
to create the AES key for the C<private_encrypted_cipher>.

=attribute pbkdf2_salt

If C<privkey_pbkdf2> is nonzero, this attribute holds the bytes of salt that were applied to the
PBKDF2 algorithm.

=attribute ssh_agent_pubkey

If the C<privkey_ciphertext> was produced in combination with a user's SSH Agent, this is the
public key of the private key which was used.

=cut

sub uuid { $_[0]{uuid} }
sub type { $_[0]{type} }
sub mechanism { die "needs overridden by subclass" }
sub public { $_[0]{public} }
sub private { $_[0]{private} }
sub private_encrypted { $_[0]{private_encrypted} }
sub private_encrypted_cipher { $_[0]{private_encrypted_cipher} }
sub pbkdf2_iter { $_[0]{pbkdf2_iter} }
sub pbkdf2_salt { $_[0]{pbkdf2_salt} }

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
   $self->{uuid}= delete $attrs{uuid} // Crypt::MultiKey::_generate_uuid();
   $self->{uuid} =~ /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\z/
      or croak "Invalid UUID: $self->{uuid}";
   # Create new random keypair, or validate existing public/private key vs. type
   $self->{type}= delete $attrs{type} // 'x25519';
   $self->{public}= delete $attrs{public};
   $self->{private}= delete $attrs{private};
   $self->_validate_or_create_keypair;
   # consume other attributes
   for (qw( private_encrypted private_encrypted_cipher pbkdf2_iter pbkdf2_salt )) {
      $self->{$_}= delete $attrs{$_} if defined $attrs{$_};
   }
   # If encrypted with a cipher, validate we support the cipher
   $self->_validate_cipher;
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

=method clear_private

Delete the private half of the public/private key pair.  You should only call this after
encrypting it, or saving it by some other means.

=cut

sub clear_private {
   # SecretBuffer destructor takes care of wiping the secret
   delete $_[0]{private};
}

1;
