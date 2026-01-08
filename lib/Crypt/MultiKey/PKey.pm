package Crypt::MultiKey::PKey;
use strict;
use warnings;
use Carp;
use Scalar::Util qw/ blessed /;
use MIME::Base64;
use Crypt::SecretBuffer qw/ secret HEX BASE64 ISO8859_1 /;
use Crypt::SecretBuffer::INI;
use Crypt::SecretBuffer::PEM;
use Crypt::MultiKey;

=head1 SYNOPSIS

  # Generate a public/private keypair
  my $key= Crypt::MultiKey::PKey->generate('x25519');
  
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
the Key object and affects the behavior of the Key object.  Any key with the L</private_encrypted>
attribute can be decrypted using L</decrypt_private>, but this attribute indicates the I<source>
of the password, such as whether it is a human-typed text password, or a password generated from
a YubiKey's hash function, etc.  Keys with the mechanism 'Password' will interactively prompt the
user on the console, where keys with the mechanism 'SSHAgent' will silently query the SSH agent
for whether the required SSH key is available.

=attribute has_public

Boolean; whether this key currently has the public half loaded.  This will be true except when
loaded from a PEM file which only contained an encrypted private key, and the password hasn't yet
been supplied.

=attribute has_private

Boolean; whether this key currently has the private half loaded.  See L</clear_private> and
L</decrypt_private>.

=attribute public

Export the public key in ASN.1 SubjectPublicKeyInfo structure defined in RFC5280, then encode
as Base64.

=attribute private_encrypted

This attribute holds an encrypted PKCS#8 (in base64) or encrypted OpenSSL PEM format for later
when you call L</decrypt_private>.

=cut

sub type { $_[0]{type} }
sub fingerprint { $_[0]{fingerprint} }
sub path { $_[0]{path} }
sub mechanism { undef; }
sub public {
   shift->_export_pubkey(my $buf);
   return encode_base64($buf, '');
}
sub private_encrypted { $_[0]{private_encrypted} }

=constructor new

  $key= Crypt::MultiKey::PKey->new($filename);
  $key= Crypt::MultiKey::PKey->new($secretbuffer);
  $key= Crypt::MultiKey::PKey->new(%attributes);

This is the constructor for the base class.  It applies and verifies the attributes above, and
then tries to apply any remaining attribute as an instance method.  Subclasses need to override
this if attributes are not writeable via accessor.

If you do not specify attribute C<public>, a new public/private keypair of L</type> will be
generated.  If you do not specify C<uuid>, a new random UUID will be generated.

=cut

sub new {
   my $class= shift;
   my %attrs= @_ != 1? @_
            : blessed($_[0]) && $_[0]->can('scan')? ( data => $_[0] )
            : ref $_[0] eq 'SCALAR'? ( data => $_[0] )
            : ( path => $_[0] );
   my $self= bless {}, $class;
   my $path= $self->{path}= delete $attrs{path};
   my $data= delete $attrs{data};
   my ($pw, $generate, $public, $private, $private_encrypted)
      = delete @attrs{qw( password generate public private private_encrypted )};
   # If keygen is requested, that takes priority, and if path is also specified
   # it will just be the default for ->save.
   if ($generate) {
      $self->generate($generate);
      $self->encrypt_private($pw) if defined $pw;
   }
   # else if 'private' is specified, try to parse that
   elsif (length $private) {
      $self->import_autodetect($private, password => $pw);
      $self->encrypt_private($pw) if defined $pw && !defined $self->{encrypted_private};
   }
   # else if 'private_encrypted' is specified, save it for later unless the
   # password was also supplied.
   elsif (length $private_encrypted) {
      # no password, save for later, and (below) look for pubkey
      $self->{private_encrypted}= $private_encrypted;
      # decrypt immediately if password provided
      $self->decrypt_private($pw) if length $pw;
   }
   # else if 'path' is specified, it must exist and be parsable.
   elsif (length $path || defined $data) {
      $data= Crypt::SecretBuffer->new(load_file => $path)
         unless defined $data;
      $self->import_autodetect($data, password => $pw);
   }
   # else this will just be an empty key until the user calls ->keygen or ->import_x

   # If we have an encrypted private key and no public key, try loading the
   # public key either from the ->{public} param or from a paired public key file.
   if (!$self->has_public) {
      if ($public) {
         $self->import_autodetect($public);
      } elsif (length $path && -f "$path.pub") {
         my $buf= Crypt::SecretBuffer->new(load_file => "$path.pub");
         $self->import_autodetect($buf);
      }
   }
   # If 'save' is requested, do that after everything else
   my $save= delete $attrs{save};
   # Hook for subclasses to process attributes
   $self->_init(\%attrs) if $self->can('_init');
   # Every remaining attribute must have a writable accessor
   $self->$_($attrs{$_}) for keys %attrs;
   # Now apply the 'save'
   $self->save($save) if length $save;
   return $self;
}

=method import_autodetect

  $key->import_autodetect($buffer, %options);

This attempts to parse a variety of key formats and load either a private key,
public key, or encrypted private key.  If the key format is encrypted and the
C<%options> do not include C<'password'>, the encrypted key will be stored in
the L</private_encrypted> attribute to be used by L</decrypt_private>.

=cut

sub import_autodetect {
   my ($self, undef, %options)= @_;
   # Upgrade buffer to a SecretBuffer::Span.  This makes parsing harder, but some
   # files are secrets, so might as well use the same parsing for everything.
   my $span= blessed($_[1]) && $_[1]->can('subspan')? $_[1]
           : blessed($_[1]) && $_[1]->can('span')? $_[1]->span
           : Crypt::SecretBuffer->new($_[1])->span;
   my @attempts;
   # There may be some UTF-8 in various formats, but the starting headers are always ascii
   # Check if there is at least one text line of ASCII
   my $ascii= $span->clone->parse(qr/[\t\r\n\x20-\x7E]+/);
   if ($ascii && $ascii->len > 1 && $ascii->scan("\n")) {
      # Does it look like the Crypt::Multikey INI serialization format?
      if (my $ini_header= ($ascii->starts_with('[') || $ascii->scan("\n["))) {
         $ini_header->lim($ascii->lim);
         # class name must be 'A-Za-z0-9:'
         if ($ini_header->parse(qr/[A-Za-z0-9:]+/) && $ini_header->parse("]")) {
            return if eval { $self->import_ini($span, %options); 1 };
            push @attempts, [ 'INI', $@ ];
         }
      }
      # Does it contain PEM blocks?
      if ($span->scan("-----BEGIN ")) {
         return if eval { $self->import_pem($span, %options); 1 };
         push @attempts, [ 'PEM', $@ ];
      }
   }
   # Maybe raw bytes of PKCS#8?
   if ($span->starts_with("\x30")) {
      return if eval { $self->import_pkcs8($span, \%options); 1 };
      push @attempts, [ 'PKCS#8', $@ ];
   }
   # If the whole thing looks like base64, try that
   if ($ascii->len == $span->len && !$span->scan(qr{[^A-Za-z0-9+/=\r\n\t ]})) {
      my $b64= $span->clone(encoding => BASE64);
      if ($b64->starts_with("\x30")) { # First byte of ASN.1 DER
         # decode the base64 into a buffer
         my $bytes= $b64->copy(encoding => ISO8859_1);
         return if eval { $self->import_pkcs8($bytes, %options); 1 };
         push @attempts, [ 'PKCS#8-base64', $@ ];
      }
   }
   # If the whole thing is hex, try that
   if ($ascii->len == $span->len && !$span->scan(qr{[^A-Fa-f0-9\r\n\t ]})) {
      my $hex= $span->clone(encoding => HEX);
      if ($hex->starts_with("\x30")) { # First byte of ASN.1 DER
         # decode the hex into a buffer
         my $bytes= $hex->copy(encoding => ISO8859_1);
         return if eval { $self->import_pkcs8($bytes, \%options); 1 };
         push @attempts, [ 'PKCS#8-base16', $@ ];
      }
   }
   croak join "\n", 
      "Failed to autodetect Key format:",
      map "  $_->[0]: $_->[1]", @attempts;
}

=method import_pem

Import a key which is known to be in PEM format.

=cut

sub import_pem {
   my ($self, $span, %options)= @_;
   my $orig_span= $span->clone;
   my $password= $options{password};
   
   my (@private, @encrypted, @public);
   
   # Extract all PEM blocks
   for my $pem (Crypt::SecretBuffer::PEM->parse_all($span)) {
      if ($pem->label eq 'ENCRYPTED PRIVATE KEY') {
         push @encrypted, $pem;
      }
      elsif ($pem->label =~ /PRIVATE KEY$/) {
         # PRIVATE KEY, RSA PRIVATE KEY, EC PRIVATE KEY, etc.
         if ($pem->headers->{'Proc-Type'} && $pem->headers->{'Proc-Type'}->scan('ENCRYPTED')) {
            push @encrypted, $pem;
         } else {
            push @private, $pem;
         }
      }
      elsif ($pem->label eq 'PUBLIC KEY') {
         push @public, $pem;
      }
      elsif ($pem->label eq 'OPENSSH PRIVATE KEY') {
         push @private, $pem;  # May be encrypted
      }
   }

   # Try to load private keys first
   for my $pem (@private, @encrypted) {
      return 1
         if eval { $self->_import_pem($pem->buffer, $password); 1 };
   }
   
   # If we have encrypted blocks and no password, save them for later
   if (@encrypted && !defined $password) {
      # Store the first encrypted block for decrypt_private to use later.
      # Extract it into a non-secret buffer.
      $encrypted[0]->buffer->unmask_to(sub{ $self->{private_encrypted}= shift });
      # Fall through to try public keys
   }

   # Try public keys as fallback
   for my $pem (@public) {
      return 1
         if eval { $self->_import_pem($pem->buffer); 1 };
   }

   # If we stored an encrypted key, that's partial success
   return 1 if $self->private_encrypted;

   die "No valid PEM blocks found or all failed to parse";
}

=method generate

Replace any current key with a newly generated key of 'type'.  The attribute
private_encrypted is deleted, if present, since it no longer matches the public
key.

Supported types and aliases:

  EC:group=X
  secp256k1   => EC:group=secp256k1
  
  ed25519
  x25519
  
  RSA:bits=N
  RSA         => RSA:bits=4096
  rsa4096     => RSA:bits=4096
  rsa2048     => RSA:bits=2048
  rsa1024     => RSA:bits=1024

=cut

our %type_alias= (
   rsa1024   => 'RSA:bits=1024',
   rsa2048   => 'RSA:bits=2048',
   rsa4096   => 'RSA:bits=4096',
   secp256k1 => 'EC:group=secp256k1',
);
sub generate {
   my ($self, $type)= @_;
   $self= $self->new unless ref $self; # permit usage as a class method
   $type ||= 'x25519';
   $type= $type_alias{lc $type} || $type;
   $self->_keygen($type);
   $self->{type}= $type;
   delete $self->{fingerprint};
   delete $self->{private_encrypted};
   $self;
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
bits, you may reduce the KDF iterations to 1.  (but it cannot be zero, due to OpenSSL API).
Ideally, C<$password> is a C<SecretBuffer> object, but scalars are also accepted.
The password must be bytes, not wide characters.

=cut

sub encrypt_private {
   my $self= shift;
   defined $_[0] or die "Missing password";
   my $buf= '';
   $self->_export_pkcs8($buf, $_[0], $_[1] || 100_000);
   $self->{private_encrypted}= encode_base64($buf, '');
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
   defined $self->{private_encrypted} or die "Can't decrypt an empty private_encrypted attribute";
   # private_encrypted can either be pure base64 which is pkcs8, or it can be a
   # PEM block that needs format-detection.
   if ($self->{private_encrypted} =~ m|^[A-Za-z0-9+/]+=*\z|) {
      my $raw= decode_base64($self->{private_encrypted});
      $self->_import_pkcs8($raw, $_[0]);
   } elsif ($self->{private_encrypted} =~ m|^-----BEGIN |) {
      $self->_import_pem($self->{private_encrypted}, $_[0]);
   } else {
      croak "Unknown format in attribute 'private_encrypted'";
   }
   $self;
}

=method generate_key_material

  $skey= Crypt::SecretBuffer->new();
  my %tumbler;
  $key->generate_key_material(\%tumbler, $skey);

Generate reproducible cryptographic bytes using the public half of this key and append them to
a SecretBuffer.  The parameters needed to reproduce those bytes are stored into a "tumbler".
The key material should then be fed to L<Crypt::MultiKey/hkfd> to derive an AES key.

Calling this method on multiple key objects (with a fresh tumbler hashref for each, but with the
same buffer) allows you to build a compound secret which will then require all of the private
keys to recreate.

=method recreate_key_material

  $skey= Crypt::SecretBuffer->new();
  $key->generate_key_material(\%tumbler, $skey);

Reproduce the cryptographic bytes that were previously generated by L</generate_key_material>
using the private half of this key and the information in C<%tumbler>.

=method encrypt

  $fields= $key->encrypt($secret);

Encrypt a secret using the public half of this key.  The secret is ideally a C<SecretBuffer>
object, but may also be a scalar.  The return value is a hashref containing the ciphertext
and other fields that are required to decrypt it, and which depend on the type of key used.

=method decrypt

  $secret_buffer= $key->decrypt(\%fields);

Decrypt a secret using the private half of this key.  (and dies if the private half of the key
is not currently available)  The hash of fields must include everything written by C<encrypt>.
The original secret is returned as a L<SecretBuffer object|Crypt::SecretBuffer>.

=cut

1;
