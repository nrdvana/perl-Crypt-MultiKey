package Crypt::MultiKey::PKey;
# VERSION
# ABSTRACT: Object representing a Public/Private key pair (OpenSSL EVP_PKEY)

use v5.12;
use warnings;
use Carp;
use mro 'c3';
use Scalar::Util qw/ blessed /;
use MIME::Base64;
use Digest::SHA qw/ sha256_base64 /;
use Crypt::SecretBuffer qw/ secret span BASE64 ISO8859_1 /;
use Crypt::SecretBuffer::PEM;
use Crypt::MultiKey;

=head1 SYNOPSIS

  # Generate a public/private keypair
  my $pkey= Crypt::MultiKey::PKey->generate('x25519');
  
  # encrypt the private half with a password
  my $pass= Crypt::SecretBuffer->new;
  $pass->append_console_line() or die;
  $pkey->encrypt_private($pass);
  
  # Throw away the private half
  $pkey->clear_private;
  
  # encrypt some other data with the public half of the key
  my $cipherdata= $pkey->encrypt("Example Plaintext");
  say JSON->new->encode($cipherdata); # It's a hashref that you can serialize
  
  # restore the private key, using the password
  $pkey->decrypt_private($pass); # croaks on wrong password
  
  # Decrypt the data
  say $pkey->decrypt($cipherdata); # "Example Plaintext"

=head1 DESCRIPTION

C<Crypt::MultiKey::PKey> is a public/private key pair where the public half is always available,
but the private half can be encrypted or removed.  The PKey can always L</encrypt> data, but the
private half must be available to L</decrypt> that data again.

=attribute protection_scheme

The scheme used to protect and/or obtain the private half of the key.  This is used as a class
name suffix for the PKey object, such as C<'Password'> referring to
C<Crypt::MultiKey::PKey::Password>.
The class defines the L</obtain_private> and L</can_obtain_private> methods, and may override
the behavior of L</encrypt_private> or introduce an entirely new workflow for setting up the key.
Most schemes derive a password (or equivalent secret) for use with L</encrypt_private>, storing
the encrypted private key locally in attribute L</private_encrypted>.  However, they are not
limited to this; the implementation could do something entirely different like fetching the
private key from remote, or forwarding all encryption operations to a device that posesses the
private key.

Calling L</encrypt_private> on a PKey with no current protection scheme sets the scheme to
C<'Password'>, which protects the private key by encrypting it using OpenSSL's encrypted
PKCS#8 support, stores it in the L</private_encrypted> attribute, and obtains it by prompting
the console for the password.

=attribute algorithm

The type of public-key cryptography used.  This is selected during L</generate>, or implied if
you L</load> a pre-existing key.

=attribute fingerprint

OpenSSL-style C<< "SHA256:base64..." >> used to help identify the key.

=attribute path

A disk path from which this key was loaded or to which it will be saved.

=attribute has_public

Boolean; whether this key currently has the public half loaded.  This will be true except when
loaded from a PEM file which only contained an encrypted private key, and the password hasn't
yet been supplied.

=attribute has_private

Boolean; whether this key currently has the private half loaded.  See L</clear_private> and
L</decrypt_private>.

=attribute public

Accessor for the public half of the key, as raw SubjectPublicKeyInfo bytes.
It reads L</export_spki> and writes L</import_spki>.

=attribute public_b64

Like L</public>, but base64-encoded for use in text formats.

=attribute private

Accessor for the private half of the key, as raw PKCS#8 bytes.
It reads L</export_pkcs8_unencrypted> and writes L</import_pkcs8>.

=attribute private_encrypted

Encrypted PKCS#8 DER bytes as returned by L</export_pkcs8_encrypted>.  This attribute holds the
input for the L</decrypt_private> method.  This attribute gets exported by L</export>
and L</save>, and (when base64-encoded and wrapped with PEM) is the same format used by OpenSSL
for encrypted private keys.

=attribute private_encrypted_foreign

An encrypted private key in some other recognized input format (such as SSH encrypted private
key format), kept verbatim so it can be decrypted later by L</decrypt_private>.  This attribute
is accepted by L</decrypt_private>, but is not emitted by L</export> or L</save>.

=cut

sub fingerprint {
   $_[0]{fingerprint} ||= do {
      $_[0]->_export_spki(my $pub);
      'SHA256:'.sha256_base64($pub);
   };
}

sub path {
   @_ > 1? $_[0]->_set_path($_[1]) : $_[0]{path};
}
sub _set_path { $_[0]{path}= $_[1]; $_[0] }

sub protection_scheme {
   @_ > 1? $_[0]->_set_protection_scheme($_[1]) : undef;
}
# protection_scheme attribute is writable, but may only rebless into a subclass
sub _set_protection_scheme {
   my ($self_or_class, $protection_scheme)= @_;
   my $class= ref $self_or_class || $self_or_class;
   # Handle request for "no protection scheme" (undef or empty string)
   if (!length($protection_scheme // '')) {
      my $cur_prot= $self_or_class->protection_scheme;
      croak "Can't change protection_scheme to 'undef' after it has been set to '$cur_prot'"
         if defined $cur_prot;
      return undef;
   }
   my $subclass= Crypt::MultiKey::lazy_load(__PACKAGE__.'::'.$protection_scheme);
   $subclass eq $class or $subclass->isa($class)
      or croak "protection_scheme $subclass does not derive from $class";
   if (ref $self_or_class) {
      return bless $self_or_class, $subclass;
   } else {
      return $subclass;
   }
}

sub public { @_ > 1? shift->_set_public(@_) : shift->export_spki }
sub _set_public { shift->import_spki(@_) }

sub public_b64 {
   @_ > 1? shift->_set_public_b64(@_)
   : encode_base64(shift->export_spki, '');
}
sub _set_public_b64 {
   my ($self, $val)= @_;
   $self->import_spki(_decode_base64($val));
}

sub private { @_ > 1? shift->_set_private(@_) : shift->export_pkcs8_unencrypted }
sub _set_private {
   my ($self, $val)= @_;
   $self->import_pkcs8($val);
   delete $self->{private_encrypted};
   delete $self->{private_encrypted_foreign};
   return $self;
}

sub private_encrypted {
   @_ > 1? shift->_set_private_encrypted(@_)
   : $_[0]{private_encrypted}
}
sub _set_private_encrypted { $_[0]{private_encrypted}= $_[1]; $_[0] }

sub private_encrypted_foreign {
   @_ > 1? shift->_set_private_encrypted_foreign(@_)
   : $_[0]{private_encrypted_foreign}
}
sub _set_private_encrypted_foreign { $_[0]{private_encrypted_foreign}= $_[1]; $_[0] }

=constructor new

  $key= Crypt::MultiKey::PKey->new(%options);

Construct a new Public/Private Key.  Constructor options are limited to writable attributes,
plus C<generate> and C<password>.

=over

=item protection_scheme

If protection_scheme is a known subclass, this selects that subclass for the new object.

=item path

Specify the path attribute, which can be used as a default for L</save>.  Use L</load> to read a
key from a file.

=item generate

Immediately generate a new key of the specified type.  The C<private>, C<private_encrypted>,
and C<public> attributes are ignored.

=item private

A scalar or SecretBuffer containing a private key or encrypted private key.  The format is
auto-detected.  If the format is encrypted and you do not also specify a password,
this will become the L<private_encrypted> attribute to be decrypted later using
L</decrypt_private>.

=item private_encrypted

Encrypted PKCS#8 DER bytes to save for a later L</decrypt_private>.

=item private_encrypted_foreign

An encrypted private key in another format recognized by L</load>, to save for a later
L</decrypt_private>.

=item public

Loading a C<private> key always implies a public key, but if your private key is encrypted this
attribute can be used to provide the public half, enabling the PKey object to be able to encrypt
data even before the private half has been obtained.

=item password

If the private key is encrypted, this attempts a L</decrypt_private> before the constructor
returns and dies if the password is incorrect.  In the opposite case, if you are calling the
constructor with C<< { generate => $type } >>, specifying a password will make an automatic
call to L</encrypt_private>.

=back

=cut

our $_ctor_password;
sub new {
   my $class= shift;
   my %attrs= @_ == 1 && ref $_[0] eq 'HASH'? ( %{ $_[0] } ) : @_;
   my $self= bless {}, $class;
   # 'password' is not an attribute, but the ->import methods need access to it.
   # Rather than plumbing that up manually through the constructor and subclasses,
   # just localize a global and then use the methods normally.
   local $_ctor_password= delete $attrs{password}
      if defined $attrs{password};
   $self->_init(\%attrs);
   return $self;
}

# Make sure attributes (or methods) are applied in the following order:
our %_attr_pri= (
   protection_scheme => -100,
   path => -99,
   private => -5,
   private_encrypted => -4,
   private_encrypted_foreign => -4,
   public => -3,
   public_b64 => -3,
   generate => -1,
   # default = 0
);
sub _init {
   my ($self, $attrs)= @_;
   # Subclasses may handle specific attributes before calling this.
   # Every remaining attribute must have a writable setter, except 'generate'.
   for (sort { ($_attr_pri{$a}||0) <=> ($_attr_pri{$b}||0) } keys %$attrs) {
      if ($_ eq 'generate') {
         $self->generate($attrs->{$_});
      } else {
         my $setter= "_set_$_";
         $self->can($setter)
            or croak "Unknown PKey constructor option '$_'";
         $self->$setter($attrs->{$_});
      }
   }
}

=constructor load

  ->load($filename, %options);
  ->load(\$buffer, %options);
  ->load($Crypt_SecretBuffer, %options);
  ->load($Crypt_SecretBuffer_Span, %options);
  ->load($Crypt_SecretBuffer_PEM, %options);

This attempts to parse a variety of key formats and load either a private key, public key, or
encrypted private key.  If the key format is encrypted and the C<%options> do not include
C<'password'>, encrypted PKCS#8 DER will be stored in L</private_encrypted>, while other
encrypted input formats will be stored in L</private_encrypted_foreign>.  Either can be used by
L</decrypt_private> later when the password is available.

If the argument is a L<Crypt::SecretBuffer>, L<Crypt::SecretBuffer::Span>,
L<Crypt::SecretBuffer::PEM>, or scalar-ref, it will be parsed directly.  Anything else is
assumed to be a filename that must be opened/read first.  If given a filename, this also sets
the L</path> attribute.

This can be called as a class constructor or as a method of an existing object to replace the
contents of the object.

=over

=item password

Provide a password to decrypt an encrypted key

=item path

Specify the 'path' attribute for the new object.

=back

=cut

sub load {
   my ($class_or_self, $filename_or_buf, %options)= @_;
   my $self= ref $class_or_self? $class_or_self : bless {}, $class_or_self;
   my $data;
   if (blessed($filename_or_buf) && (
        $filename_or_buf->isa('Crypt::SecretBuffer')
        || $filename_or_buf->isa('Crypt::SecretBuffer::Span')
        || $filename_or_buf->isa('Crypt::SecretBuffer::PEM')
      )
   ) {
      $data= $filename_or_buf;
   }
   elsif (ref $filename_or_buf eq 'SCALAR') {
      $data= span($$filename_or_buf);
   }
   else { # else assume it's a filename
      $data= secret(load_file => $filename_or_buf);
      $options{path}= "$filename_or_buf";
   }
   $self->_import_key($data, %options)
      or croak "Unrecognized key format";
   $self->path($options{path})
      if !defined $self->path && defined $options{path};
   return $self;
}

sub _looks_like_base64 {
   my $span= span($_[0]);
   return $span->len >= 4 && !$span->scan(qr{[^A-Za-z0-9+/=\r\n\t ]})
}
sub _decode_base64 {
   return span($_[0], encoding => BASE64)->copy(encoding => ISO8859_1)->span;
}
# ASN.1 DER encoding starts with a type code and then a length and then the contents
# of that type.  The relevant type codes are:
#   0x02 INTEGER
#   0x03 BIT STRING
#   0x04 OCTET STRING
#   0x30 SEQUENCE
# This code looks for the patterns of:
#   SEQUENCE { SEQUENCE {...}, BIT STRING   => RFC 5280 SubjectPublicKeyInfo
#   SEQUENCE { SEQUENCE {...}, OCTET STRING => Encrypted PKCS#8
#   SEQUENCE { INTEGER                      => Unencrypted PKCS#8
sub _identify_asn1 {
   my $span= span($_[0]);
   if ($span->parse("\x30")) {
      my $len= $span->parse_asn1_der_length;
      if ($len && $len <= $span->len) {
         return 'PKCS#8-unencrypted' if $span->starts_with("\x02");
         if ($span->parse("\x30")) { # encrypted PKCS#8, or SubjectPublicKeyInfo
            my $len2= $span->parse_asn1_der_length;
            if ($len2 && $len2 <= $span->len) {
               my $next= $span->subspan($len2);
               return 'SPKI' if $next->starts_with("\x03");
               return 'PKCS#8-encrypted' if $next->starts_with("\x04");
            }
         }
      }
   }
   return '';
}

sub _import_key {
   my ($self, $input, %options)= @_;
   my $is_pem= $input->isa("Crypt::SecretBuffer::PEM");
   delete $self->{fingerprint}; # clear cache
   my $pass= $options{password} // $_ctor_password;
   # Does it look like PEM?
   if ($is_pem || span($input)->scan("-----BEGIN ")) {
      # This could be called on an existing object.  In case a key was already loaded, we need
      # to keep track of whether the routines below succeeded yet.  If so, this method has
      # succeeded, and if not, we need to die while preserving any previous loaded key.
      my $loaded_something= 0;
      # Find all PEM blocks.  There should probably only be one, unless someone added both the
      # public and private PEM to the same file.
      my @pems= $is_pem? ($input) : Crypt::SecretBuffer::PEM->parse_all(span($input))
         or croak "No complete PEM records found";
      for my $pem (@pems) {
         # OpenSSL encrypted key format
         if ($pem->label eq 'ENCRYPTED PRIVATE KEY') {
            if (defined $pass) {
               # password provided, so attempt to import, and die if it fails
               $self->import_pkcs8($pem->content->copy(encoding => ISO8859_1), $pass);
            } else {
               # password not provided, so save the decoded PKCS#8 DER for later
               $pem->content->copy_to($self->{private_encrypted}= '', encoding => ISO8859_1);
               # this method is now classified as succeeding, so remove any pre-existing key
               # unless the thing loaded was a public key from earlier in the file.
               $self->_clear_key unless $loaded_something;
            }
            $self->_import_pem_headers($pem);
            $self->protection_scheme('Password') unless defined $self->protection_scheme;
            $loaded_something= 1;
            # unless public key is defined, keep iterating in case the public key was provided
            # as another PEM record in the same file
            return 1 if $self->has_public;
         }
         # OpenSSL unencrypted key format
         elsif ($pem->label eq 'PRIVATE KEY') {
            $self->import_pkcs8($pem->content->copy(encoding => ISO8859_1));
            $self->_import_pem_headers($pem);
            return 1;
         }
         # OpenSSH key format, which always contains a public key and either an encrypted or
         # unencrypted private key.
         elsif ($pem->label eq 'OPENSSH PRIVATE KEY') {
            # decode base64 to get byte buffer
            my $bytes= $pem->content->copy(encoding => ISO8859_1);
            $self->_import_openssh_privkey($bytes, $pass);
            # loading SSH key may succeed with only public half if the key was encrypted and
            # '$pass' is undef.
            if (!defined $pass && !$self->has_private) {
               $pem->buffer->span->copy_to($self->{private_encrypted_foreign}= '');
               $self->protection_scheme('Password');
            }
            return 1;
         }
         elsif ($pem->label eq 'PUBLIC KEY') {
            $self->import_spki($pem->content->copy(encoding => ISO8859_1));
            $self->_import_pem_headers($pem);
            # keep iterating in case the private key is a second PEM record
            $loaded_something= 1;
         }
      }
      croak "No supported PEM record types were found"
         unless $loaded_something;
      return 1; # either just a public key, or private_encrypted, or both.
   }
   # Does it look like the SSH public key line?
   my $span= span($input);
   if ($span->parse("ssh-") && $span->parse(qr/[-a-z0-9]+/) && $span->parse(" ")
      && ($span=$span->parse(qr{[A-Za-z0-9+/=]+}))
   ) {
      $span->encoding(BASE64);
      $span= $span->copy(encoding => ISO8859_1)->span;
      $self->_import_openssh_pubkey($span);
      return 1;
   }
   $span= span($input);
   again: {
      # Maybe raw bytes of ASN.1?
      my $type;
      if ($span->starts_with("\x30") && ($type= _identify_asn1($span))) {
         if ($type eq 'SPKI') {
            $self->import_spki($span);
            return 1;
         }
         elsif ($type eq 'PKCS#8-encrypted') {
            if (defined $pass) {
               $self->import_pkcs8($span, $pass);
            } else {
               $self->_clear_key;
            }
            $span->copy_to($self->{private_encrypted}= '');
            $self->protection_scheme('Password');
            return 1;
         }
         elsif ($type eq 'PKCS#8-unencrypted') {
            $self->import_pkcs8($span);
            return 1;
         }
      }
      # If the whole thing looks like base64, decode it and try again
      if (_looks_like_base64($span)) {
         $span= _decode_base64($span);
         goto again;
      }
   }
   return 0;
}

sub _import_pem_headers {
   my ($self, $pem)= @_;
   # protection_scheme header can change the class, then might need re-dispatched
   my $prot= $pem->headers->{cmk_protection_scheme};
   if (defined $prot && $prot ne ($self->protection_scheme//'')) {
      my $this_sub= $self->can('_import_pem_headers');
      $self->protection_scheme($prot);
      # guard against infinite loop
      $self->protection_scheme eq $prot or croak "BUG";
      my $new_sub= $self->can('_import_pem_headers');
      goto $new_sub if $new_sub != $this_sub;
   }
   
   # check for a public_key header, which can be paired with encrypted PKCS#8
   unless ($self->has_public) {
      my $pub= $pem->headers->{public_key};
      if (defined $pub && _looks_like_base64($pub)) {
         $self->_import_spki(_decode_base64($pub));
      }
   }
}

=method generate

Replace any current key with a newly generated key of 'type'.  The attribute
private_encrypted is deleted, if present, since it no longer matches the public
key.

Supported types and aliases:

  EC:curve=X
  secp256k1   => EC:curve=secp256k1
  
  ed25519
  x25519
  
  RSA:bits=N
  RSA         => RSA:bits=4096
  rsa4096     => RSA:bits=4096
  rsa2048     => RSA:bits=2048
  rsa1024     => RSA:bits=1024

  (with OpenSSL >= 3.5)
  ML-KEM      => ML-KEM-768
  ML-KEM-512
  ML-KEM-768
  ML-KEM-2014

=cut

our %type_alias= (
   rsa1024   => 'RSA:bits=1024',
   rsa2048   => 'RSA:bits=2048',
   rsa4096   => 'RSA:bits=4096',
   secp256k1 => 'EC:curve=secp256k1',
   mlkem     => 'ML-KEM-768',
   'ml-kem'  => 'ML-KEM-768',
);
sub generate {
   my ($self, $type)= @_;
   $self= $self->new unless ref $self; # permit usage as a class method
   $type ||= 'x25519';
   $type= $type_alias{lc $type} || $type;
   $self->_keygen($type);
   delete $self->{fingerprint};
   delete $self->{private_encrypted};
   delete $self->{private_encrypted_foreign};
   # If run from the constructor with a { password => 'xxx' } and the protection_scheme
   # isn't defined, automatically encrypt_private.
   if (defined $_ctor_password && !defined $self->protection_scheme) {
      $self->encrypt_private($_ctor_password);
   }
   $self;
}

=method import_spki

  $pkey->import_spki($der_bytes);

Import a public key from DER-encoded ASN.1 SubjectPublicKeyInfo bytes.  SubjectPublicKeyInfo
is the public-key structure defined by RFC5280 and used by OpenSSL's C<BEGIN PUBLIC KEY> PEM
files.  DER is the deterministic binary encoding of ASN.1 data.

=method export_spki

  $der_bytes= $pkey->export_spki;

Export the public key as DER-encoded SubjectPublicKeyInfo bytes.

=method import_pkcs8

  $pkey->import_pkcs8($der_bytes);
  $pkey->import_pkcs8($encrypted_der_bytes, $password);

Import a private key from DER-encoded PKCS#8 bytes.  PKCS#8 is the standard private-key
container used by OpenSSL's C<BEGIN PRIVATE KEY> and C<BEGIN ENCRYPTED PRIVATE KEY> PEM files.
If the PKCS#8 structure is encrypted, C<$password> is required.

Dies on failure.  If the password is incorrect, the error will match C<< qr/^password/ >>.
Note that in many cases it is hard to distinguish an incorrect password from a corrupt file.

=method export_pkcs8_unencrypted

  $secret_buffer= $pkey->export_pkcs8_unencrypted;

Export the private key as unencrypted DER-encoded PKCS#8 bytes in a
L<SecretBuffer|Crypt::SecretBuffer>.

=method export_pkcs8_encrypted

  $der_bytes= $pkey->export_pkcs8_encrypted($password, $kdf_iter);

Export the private key as password-encrypted DER-encoded PKCS#8 bytes.  Both C<$password> and
C<$kdf_iter> are required.

=cut

sub import_spki {
   my ($self, $bytes)= @_;
   $self->_import_spki($bytes);
   delete $self->{fingerprint};
   return $self;
}

sub export_spki {
   my $self= shift;
   $self->_export_spki(my $buf);
   return $buf;
}

sub import_pkcs8 {
   my ($self, $bytes, $password)= @_;
   $self->_import_pkcs8($bytes, defined($password)? $password : ());
   delete $self->{fingerprint};
   return $self;
}

sub export_pkcs8_unencrypted {
   my $self= shift;
   my $buf= secret;
   $self->_export_pkcs8($buf);
   return $buf;
}

sub export_pkcs8_encrypted {
   my ($self, $password, $kdf_iter)= @_;
   defined $password or croak "Missing password";
   defined $kdf_iter or croak "Missing kdf_iter";
   my $buf= '';
   $self->_export_pkcs8($buf, $password, $kdf_iter);
   return $buf;
}

=method export

  $pkey->export->save_file($filename);

Export the PKey as a L<SecretBuffer|Crypt::SecretBuffer> object containing OpenSSL PEM text of
PKCS#8 format data, but also with PEM headers that preserve the value of object attributes.
If L</protection_scheme> is C<undef>, this will write out an B<unencrypted private key>.
If you called L</encrypt_private>, the C<protection_scheme> changed to C<'Password'> and this
will write out an encrypted private key in PKCS#8 format.  If a protection scheme is defined
but L</private_encrypted> is not available, this exports only the public key.

All exports from this method will include PEM headers as needed to store the PKey attributes.
OpenSSL cannot read PEM files if they have headers.

=method export_pem

Like L</export>, but return a L<PEM object|Crypt::SecretBuffer::PEM> prior to serializing.

=method export_pem_openssl_public_key

Export the PKey as a L<PEM object|Crypt::SecretBuffer::PEM> of C<SubjectPublicKeyInfo> data
(OpenSSL C<BEGIN PUBLIC KEY> format) B<without> any PEM headers so that L<openssl(1)> can read
it.

=method export_pem_openssl_private_key

Export the PKey as a L<PEM object|Crypt::SecretBuffer::PEM> of C<PKCS#8> data, B<unencrypted>,
and B<without> any PEM headers so that L<openssl(1)> can read it.

=method export_pem_openssl_encrypted_private_key

Export the PKey as a L<PEM object|Crypt::SecretBuffer::PEM> of password-encrypted C<PKCS#8>
data from the L</private_encrypted> attribute, B<without> any Crypt::MultiKey metadata headers
so that L<openssl(1)> can read it.

=method save

  $pkey->save;         # saves to $pkey->path
  $pkey->save($path);  # saves to $path and sets $pkey->path if not already set

This is a shortcut for C<< $pkey->export_pem->serialize->save_file($pkey->path, "rename") >>.

=cut

sub export {
   shift->export_pem->serialize;
}
sub export_pem {
   my ($self)= @_;
   # Serialize an encrypted private key only when we have PKCS#8 ciphertext.
   # Foreign encrypted formats are accepted for delayed decryption, but are not exported.
   my $pem;
   if (defined $self->{private_encrypted}) {
      $pem= $self->export_pem_openssl_encrypted_private_key;
   }
   # If a protection_scheme is defined, default to only exporting the public key
   elsif (defined $self->protection_scheme) {
      $pem= $self->export_pem_openssl_public_key;
   }
   # No protection scheme, export the whole key
   else {
      $pem= $self->export_pem_openssl_private_key;
   }
   $self->_export_pem_headers($pem);
   $pem;
}

sub export_pem_openssl_public_key {
   my $self= shift;
   return Crypt::SecretBuffer::PEM->new(label => 'PUBLIC KEY', content => $self->export_spki);
}

sub export_pem_openssl_private_key {
   my $self= shift;
   return Crypt::SecretBuffer::PEM->new(label => 'PRIVATE KEY', content => $self->export_pkcs8_unencrypted);
}

sub export_pem_openssl_encrypted_private_key {
   my $self= shift;
   my $content= span($self->{private_encrypted});
   croak "private_encrypted is not encrypted PKCS#8 DER (as would be created by ->encrypt_private)"
      unless _identify_asn1($content) eq 'PKCS#8-encrypted';
   return Crypt::SecretBuffer::PEM->new(label => 'ENCRYPTED PRIVATE KEY', content => $content);
}

sub _export_pem_headers {
   my ($self, $pem)= @_;
   $pem->header_kv([]) unless defined $pem->header_kv;
   # export the 'protection_scheme' (indicating subclass) if it is defined
   push @{$pem->header_kv}, cmk_protection_scheme => $self->protection_scheme
      if defined $self->protection_scheme;
   # Store the public key in a PEM header so that we can load the public key from an
   # "ENCRYPTED PRIVATE KEY" file even before we have the password.
   push @{$pem->header_kv}, public_key => $self->public_b64
      if $pem->label eq 'ENCRYPTED PRIVATE KEY' && $self->has_public;
   # subclasses override this to export additional headers
}

sub save {
   my ($self, $path)= @_;
   $path //= $self->path // croak "No 'path' specified for saving key";
   $self->export->save_file($path, "rename");
   $self->path($path) unless defined $self->path;
   $self;
}

=method encrypt_private

  $pkey->encrypt_private($password, $kdf_iter=100_000);

Export the (private) key in PKCS#8 format encrypted with a password, and store it into attribute
C<private_encrypted> to be saved out by a subsequent L</export> or L</save>.
You may customize the number of iterations for the key-derivation-function (KDF) to resist
brute-force attempts.  If the password is known to be a string of hashed data with
uniformly-distributed bits, you may reduce the KDF iterations to 1, but it cannot be zero due
to OpenSSL API.

The password must be bytes, not wide characters, so make sure to encode it first.
Ideally, C<$password> is a L<SecretBuffer|Crypt::SecretBuffer> object, but scalars are also
accepted.

If this PKey did not have a L</protection_scheme>, the C<protection_scheme> gets initialized to
C<'Password'>.

=cut

sub encrypt_private {
   my $self= shift;
   defined $_[0] or die "Missing password";
   $self->protection_scheme('Password')
      unless defined $self->protection_scheme;
   my $kdf_iter= $_[1] || 100_000;
   $self->{private_encrypted}= $self->export_pkcs8_encrypted($_[0], $kdf_iter);
   delete $self->{private_encrypted_foreign};
   $self;
}

=method clear_private

Delete the private half of the public/private key pair.  You should only call this after
L<encrypting it|/encrypt_private>, or saving it by some other means.

=cut

sub clear_private {
   my $self= shift;
   croak "Refusing to clear_private when protection_scheme is not defined"
      unless defined $self->protection_scheme;
   my $buf= $self->export_spki;
   $self->_clear_key;
   $self->import_spki($buf);
   $self;
}

=method decrypt_private

  $pkey->decrypt_private($password);

Using the supplied password, decrypt attribute C<private_encrypted> or
C<private_encrypted_foreign> and import it.

The password must be bytes, not wide characters.
Ideally, C<$password> is a C<SecretBuffer> object, but scalars are also accepted.

Dies on failure.  If the password is incorrect, the error will match C<< qr/^password/ >>.
Note that in many cases it is hard to distinguish an incorrect password from a corrupt file.

=cut

sub decrypt_private {
   my $self= shift;
   defined $_[0] or croak "Missing password";
   defined($self->{private_encrypted}) || defined($self->{private_encrypted_foreign})
      or croak "Can't decrypt an empty private_encrypted attribute";
   my $old_pub= $self->has_public? $self->export_spki : undef;
   if (defined $self->{private_encrypted}) {
      $self->import_pkcs8($self->{private_encrypted}, $_[0]);
   } else {
      $self->_import_key(span($self->{private_encrypted_foreign}), password => $_[0])
         or croak "Unknown key format in private_encrypted_foreign";
      delete $self->{fingerprint};
   }
   if (defined $old_pub && $old_pub ne $self->export_spki) {
      $self->_clear_key;
      $self->import_spki($old_pub);
      croak "Decrypted private key does not match the existing public key";
   }
   $self;
}

=method can_obtain_private

Returns true if the resources needed for obtaining the private half of the PKey are available,
or seem to be available.  (attempting may still fail)

This can return false even when the private key was already loaded; check L</has_private> first.

=method obtain_private

Attempt to gain access to the private half of the PKey, either by decrypting it and loading it
locally, or opening a connection to a device or service which is providing the private half.
This may block as it prompts the user for a password or other type of confirmation.
Dies on failure.

If the private half of the PKey is already available, this does nothing.

=cut

sub can_obtain_private { 0 }

sub obtain_private {
   return if $_[0]->has_private;
   croak "No protection_scheme defined for obtaining the private key";
}

=method generate_key_material

  $key_material= Crypt::SecretBuffer->new();
  my (%tumbler1, %tumbler2);
  $pkey1->generate_key_material(\%tumbler1, $key_material);
  $pkey2->generate_key_material(\%tumbler2, $key_material);
  ...
  $symmetric_key= Crypt::MultiKey::hkdf({ size => 32 }, $key_material);

Generate reproducible cryptographic bytes using the public half of this key and append them to
a SecretBuffer.  The parameters needed to reproduce those bytes are stored into a "tumbler".
The key material should then be fed to L<Crypt::MultiKey/hkdf> to derive an AES key.

Calling this method on multiple key objects (with a fresh tumbler hashref for each, but with the
same buffer) allows you to build a compound secret which will then require all of the private
keys to recreate.

=method recreate_key_material

  $key_material= Crypt::SecretBuffer->new();
  $pkey1->recreate_key_material(\%tumbler1, $key_material);
  $pkey2->recreate_key_material(\%tumbler2, $key_material);
  ...
  $symmetric_key= Crypt::MultiKey::hkdf({ size => 32 }, $key_material);

Reproduce the cryptographic bytes that were previously generated by L</generate_key_material>
using the private half of this key and the information in C<%tumbler>.

=method encrypt

  my $fields= $pkey->encrypt($secret);
  my $fields2= $pkey->encrypt($secret, $ciphertext_out);

Encrypt a secret using the public half of this key.  The secret is ideally a C<SecretBuffer>
object, but may also be a scalar.  The return value is a hashref containing the encryption
parameters and key-exchange data needed for decryption.  The ciphertext is stored as
C<< $fields->{ciphertext} >> unless you pass an explicit C<$ciphertext_out> scalar/buffer.

=method decrypt

  $secret_buffer= $pkey->decrypt(\%fields);
  $pkey->decrypt(\%fields, $secret_out);

Decrypt a secret using the private half of this key.  (and dies if the private half of the key
is not currently available).  It reads ciphertext from C<< $fields->{ciphertext} >>.
The original secret is returned as a L<SecretBuffer object|Crypt::SecretBuffer>, or written into
C<$secret_out> if supplied.  C<$secret_out> must be a C<Crypt::SecretBuffer>.

=cut

# Avoid depending on namespace::clean
delete @Crypt::MultiKey::PKey::{qw(
   blessed carp confess croak
   BASE64 ISO8859_1 secret span
   sha256_base64 decode_base64 encode_base64
)};
