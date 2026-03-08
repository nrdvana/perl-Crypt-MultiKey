package Crypt::MultiKey::Coffer;
our $VERSION= '0.001'; # VERSION
# ABSTRACT: Encrypted container that can be unlocked with various combinations of keys

use strict;
use warnings;
use Carp;
use version;
use Scalar::Util qw/ blessed looks_like_number /;
use MIME::Base64 qw/ encode_base64 decode_base64 /;
use Crypt::SecretBuffer qw/ secret HEX BASE64 ISO8859_1 /;
use Crypt::SecretBuffer::PEM 0.020;
use Crypt::MultiKey;
use constant { KV_CONTENT_TYPE => 'application/crypt-multikey-coffer-kv' };

sub _isa_pem_obj { blessed($_[0]) && $_[0]->isa('Crypt::SecretBuffer::PEM') }
sub _isa_secret { blessed($_[0]) && $_[0]->isa('Crypt::SecretBuffer') }
sub _isa_secret_span { blessed($_[0]) && $_[0]->isa('Crypt::SecretBuffer::Span') }
sub _coerce_secret {
   my $val= shift;
   return $val if _isa_secret($val) || _isa_secret_span($val);
   croak "Expected a Crypt::SecretBuffer, Crypt::SecretBuffer::Span, or something that can stringify to bytes"
      if ref $val && !blessed($val);
   return secret($val);
}

=head1 SYNOPSIS

  # Coffer is locked/unlocked using public/private keys
  my ($key1, $key2, $key3)= map Crypt::MultiKey::PKey->new(), 1..3;
  
  # initial state of coffer is unlocked, and unsaved
  my $coffer= Crypt::MultiKey::Coffer->new(
    path => './mydata.coffer'
    content => $secret_buffer,
  );
  $coffer->add_access($key1);        # now coffer can be unlocked by key1
  $coffer->add_access($key2, $key3); # now coffer can be unlocked by key2+key3
  $coffer->save;                     # write encrypted PEM to file 'mydata.coffer'
  $coffer->lock;                     # now coffer cannot be read until unlocked
  $coffer->unlock($key2,$key3);      # content decrypted from ciphertext
  $secret= $coffer->content;         # access secret data
  
  # Coffer can be used in key/value mode.
  # (multiple named secrets get concatenated and encrypted as one secret)
  my $coffer= Crypt::MultiKey::Coffer->new(
    path => './mydata.coffer'
  );
  $coffer->set("secret1", $secret1);
  $coffer->set("secret2", $secret2);
  $coffer->add_access($key2);
  $coffer->save;
  $coffer->lock;
  $coffer->unlock($key2);
  $secret2= $coffer->get("secret2");

=head1 DESCRIPTION

=head1 FILE FORMAT

A Coffer is encoded in PEM format, with headers that describe the contents of the coffer and
which keys can unlock it.

  -----BEGIN CRYPT MULTIKEY COFFER-----
  version: 0.001
  writer_version: 0.001
  user_meta.name: Example
  locks.0.cipher: AES-256-GCM
  locks.0.ciphertext: base64==
  locks.0.tumblers.0.ephemeral_pubkey: base64==
  locks.0.tumblers.0.key_fingerprint: SHA256:base64==
  locks.1.cipher: AES-256-GCM
  locks.1.ciphertext: base64==
  locks.1.tumblers.0.ephemeral_pubkey: base64==
  locks.1.tumblers.0.key_fingerprint: SHA256:base64==
  locks.1.tumblers.1.ephemeral_pubkey: base64==
  locks.1.tumblers.1.key_fingerprint: SHA256:base64==
  content_type: text/plain
  cipher_data.cipher: AES-256-GCM
  pem_header_authentication: HMAC-SHA256:base64==
  
  base64==
  -----END CRYPT MULTIKEY COFFER-----

The content is either binary data of your choice, or a key/value format written by this module
which is just a series of length-delimited strings.  The content is encrypted with AES-256 and
written as base64 as the body of the PEM file.  The AES key that encrypted the content is
encrypted in one or more "access" entries and the AES encryption key for each access is
derived from the combined key material from the "tumblers".  A "tumbler" is a set of parameters
that can be combined with the private half of a public/private key to generate AES-key material.

=attribute path

Filesystem path from which to load and save the Coffer.

=attribute user_meta

An arbitrary hashref of name/value strings that will be added to the PEM as
C<< u.$name = $value >>.  Because PEM has no escaping system, the names and values may not
contain control characters or begin or end with space characters.  The names also may not
contain '.' or be purely numeric, because these are used for encoding the structure of the data.

Warning: the authenticity of C<user_meta> does not get checked until you have L</unlock>ed the
coffer.  Never trust L<user_meta> on a locked Coffer unless the file was stored securely.

=attribute name

A shortcut for C<< ->user_meta->{name} >>.  This helps encourage you to at least provide a label
for the file indicating its purpose or contents.  This defaults to the basename of the L</path>.

=cut

sub path { @_ > 1? shift->_set_path(@_) : $_[0]{path} }
sub _set_path { $_[0]{path}= $_[1]; $_[0] }

sub user_meta { @_ > 1? shift->_set_user_meta(@_) : ($_[0]{user_meta} ||= {}) }
sub _set_user_meta { $_[0]{user_meta}= $_[1]; $_[0] }

sub name { @_ > 1? shift->_set_name(@_) : $_[0]->user_meta->{name} }
sub _set_name { $_[0]->user_meta->{name}= $_[1]; $_[0] }

=attribute file_key

A L<Crypt::SecretBuffer> holding the secret key used to derive the AES key for
encrypting/decrypting the content and derive the HMAC key for authenticating the PEM headers.
A Coffer is logically "unlocked" when the C<file_key> is defined, and "locked"
(or uninitialized) when it isn't.

=over

=item unlocked

Convenience accessor that returns true if C<file_key> is defined.

=back

=cut

sub file_key { @_ > 1? shift->_set_file_key(@_) : $_[0]{file_key} }

sub _cipher_key {
   my $file_key= $_[0]->file_key || croak "Coffer is locked";
   return Crypt::MultiKey::hkdf(
      { size => 32, kdf_info => 'Crypt::MultiKey::Coffer/cipher_key', kdf_salt => '' },
      $file_key
   );
}
sub _hmac_key {
   my $file_key= $_[0]->file_key || croak "Coffer is locked";
   return Crypt::MultiKey::hkdf(
      { size => 32, kdf_info => 'Crypt::MultiKey::Coffer/hmac_key', kdf_salt => '' },
      $file_key
   );
}

sub unlocked { defined $_[0]{file_key} }

sub _set_file_key {
   my ($self, $val)= @_;
   croak "Not a SecretBuffer"
      unless _isa_secret($val);
   $self->{file_key}= $val;
   $self;
}

=attribute cipher_data

If the coffer has been encrypted/locked, this attribute holds a hashref including the ciphertext
and other parameters describing how it was encrypted.  In a newly-initialized Coffer this will
be C<undef>.

=over

=item has_ciphertext

True if the cipher_data is defined and contains a ciphertext string

=back

=cut

sub cipher_data { @_ > 1? shift->_set_cipher_data(@_) : $_[0]{cipher_data} }
sub _set_cipher_data { $_[0]{cipher_data}= $_[1]; $_[0] }

sub has_ciphertext { defined $_[0]{cipher_data} && defined $_[0]{cipher_data}{ciphertext} }

=attribute content_type

Specify the MIME type of the L</content> attribute.  The special value
C<< application/crypt-multikey-coffer-kv >> enables the L</get> and L</set> methods to use the
C<content> as a key/value dictionary.

=attribute content

This attribute is an unencrypted L<Crypt::SecretBuffer> of the secret data of the Coffer.
If an encrypted copy exists (L</has_ciphertext> is true), reading this attribute will attempt
to decrypt it, and fail if the Coffer is still locked.  If there is no encrypted copy (such as
when a Coffer object is first created) or the, reading this attribute just returns C<undef>.

Writing this attribute will invalidate the C<cipher_data> attribute, forcing it to be
re-encrypted when you call L</save>.  Beware that if you make changes to the SecretBuffer object
directly, the Coffer object will not be aware of those changes and the changes may be lost if
the Coffer doesn't know they need re-encrypted.  Set C<< $coffer->content_changed(1) >> if you
need to flag the content as having changed.

If you are using the Coffer for name/value storage, use the L</content_kv> attribute or L</get>
and L</set> methods instead of accessing this attribute.  In name/value mode, every access of
this attribute will re-serialize your data.

=over

=item has_content

True if the content or content_kv attributes are defined, meaning that either the Coffer is
decrypted or has been initialized to a new value.  Maybe unintuitively, it returns false for an
unlocked coffer where the content hasn't been lazy-decrypted yet.

=back

=attribute content_kv

This attribute is used when the content type is C<< application/crypt-multikey-coffer-kv >>.
and allows you to work with a hash of name/value pairs where each value is a SecretBuffer
or SecretBuffer Span.  Changes to this hash will not be seen automatically; either use L</set>,
or write the whole attribute to properly indicate to the Coffer that it needs re-encrypted.

=attribute content_changed

True if you have used accessors to alter your C<content> or C<content_kv> attribute.  If you
modify the content SecretBuffer yourself, you should set this attribute to true so that the
Coffer knows it needs to re-encrypt the content.

=cut

sub content_type { @_ > 1? shift->_set_content_type(@_) : $_[0]{content_type} }
sub _set_content_type { $_[0]{content_type}= $_[1]; $_[0] }

sub content {
   my $self= shift;
   return $self->_set_content($_[0])
      if @_;
   $self->decrypt
      if !$self->has_content && $self->has_ciphertext;
   $self->_pack_content_kv
      if !defined $self->{content} && defined $self->{content_kv};
   $self->{content}
}

sub content_kv {
   my $self= shift;
   return $self->_set_content_kv($_[0])
      if @_;
   croak "content_type is not ".KV_CONTENT_TYPE
      unless $self->content_type eq KV_CONTENT_TYPE;
   $self->decrypt
      if !$self->has_content && $self->has_ciphertext;
   $self->_unpack_content_kv
      if !defined $self->{content_kv} && defined $self->{content};
   $self->{content_kv}
}

sub has_content { defined $_[0]{content} || defined $_[0]{content_kv} }
sub content_changed { $_[0]{content_changed}= $_[1] if @_ > 1; !!$_[0]{content_changed} }

sub _set_content {
   my ($self, $val)= @_;
   if (!defined $val) {
      $self->{content}= undef;
      $self->{content_kv}= undef;
   } else {
      $self->{content}= _coerce_secret($val);
   }
   # discard key/value map, if any
   delete $self->{content_kv};
   $self->content_changed(1);
   $self;
}

sub _set_content_kv {
   my ($self, $val)= @_;
   croak "Clear content with ->content(undef) rather than ->content_kv(undef)"
      unless defined $val;
   croak "Expected hashref"
      unless ref $val eq 'HASH';
   # Ensure that all values are SecretBuffer or SecretBuffer::Span
   $val= { %$val }; # clone before converting values
   $_= _coerce_secret($_)
      for values %$val;
   $self->{content_kv}= $val;
   # override content type
   $self->{content_type}= KV_CONTENT_TYPE;
   # discard plain scalar content, if any
   delete $self->{content};
   $self->content_changed(1);
   $self;
}

sub _unpack_content_kv {
   my $self= shift;
   my $span= span($self->content);
   # parse_lenprefixed(-1) attempts to consume all bytes of the span as a list of variable-int
   # length followed by that many bytes.  It fails and returns an empty list if the final
   # lenprefixed string does not end exactly at the end of the span.
   my @kv= $span->parse_lenprefixed(-1);
   croak "Failed to parse Key/Value pairs: ".$span->last_error
      if !@kv && $span->len; # empty content is not an error
   croak "Failed to parse Key/Value pairs: odd number of strings"
      if @kv & 1;
   # All strings are currently SecreetBuffer objects.  Unmask the keys.
   for (0 .. ($#kv-1)/2) {
      my $k;
      $kv[$_*2]->copy_to($k);
      $kv[$_*2]= $k;
   }
   my %kv= @kv;
   delete $self->{content}; # content_kv is the official value, now
   $self->{content_kv}= \%kv;
}

sub _pack_content_kv {
   my $self= shift;
   my $buf= secret;
   $buf->append_lenprefixed($_) for %{ $self->{content_kv} };
   delete $self->{content_kv};
   $self->{content}= $buf;
}

=attribute locks

An arrayref of lock definitions, B<each> of which is sufficient to open the Coffer.
This breaks the intuitiveness of the Coffer metaphor a bit, but imagine a coffer with multiple
access hatches and a lock (which may require multiple keys) on each.  Locks are created with
L</add_access> method to emphasize that each one I<adds> access to the secret rather than
restricting it.

A lock always operates on public/private keys.  The private half must be present to open a lock,
but only the public half is needed to create the lock.  This means the coffer can be encrypted
with a new C<file_key> even when the private half of the keys are not available.

Each lock is an encryption of the Coffer's C<file_key> using a symmetric key derived from the
public half of the keys.  See L<Crypt::MultiKey::PKey/generate_key_material>.

  [
    { cipher        => 'AES-256-GCM',
      ciphertext    => $encrypted_bytes,
      tumblers      => [
        { key_fingerprint    => $hashname_and_base64,
          ephemeral_pubkey   => $pubkey_bytes,
          rsa_key_ciphertext => $encrypted_bytes,
        },
        ...
      ],
    },
    ...
  ]

=cut

sub locks { @_ > 1? shift->_set_locks(@_) : $_[0]{locks} }
sub _set_locks {
   $_[0]->_validate_locks($_[1]);
   $_[0]{locks}= $_[1];
   $_[0];
}

=attribute authentication

When loaded from an external source (currently just PEM files), this attribute gets initialized
to an arrayref of the canonical message (PEM headers) and the HMAC-SHA256 of that text.
This will be verified during L</unlock> to ensure that the headers were not altered, throwing
an exception if they don't match.  Beware that until unlocked, you have no guarantee that the
headers weren't altered by an attacker.  For an example attack, consider what happens if you
load a Coffer file, assign new content without unlocking the old content, and then re-encrypt
using the same public keys from the previous locks.  An attacker could inject a bogus lock
using a key they control, and then your re-encrypted Coffer file would be readable by them!
Always L</unlock> a Coffer before trusting any attribute of the object.

This attribute will be C<undef> if the Coffer was not loaded from an external source.
The check during L</unlock> is only performed if this attribute is defined.

=cut

sub authentication { @_ > 1? shift->_set_authentication(@_) : $_[0]{authentication} }
sub _set_authentication {
   my ($self, $val)= @_;
   ref $val eq 'ARRAY' && @$val == 3
      or croak 'Expected arrayref of [$canonical_message_bytes, $algorithm, $mac]';
   $self->{authentication}= $val;
   $self;
}

=constructor new

  $coffer= Crypt::MultiKey::Coffer->new(%attributes);

Construct a new Coffer.  The attributes are applied to the object as method calls.

=constructor load

  $coffer= Crypt::MultiKey::Coffer->load($filename);

Load a Coffer from a file.  This does not decrypt the data.  See L</unlock>.

=cut

# Make sure attributes (or methods) are applied in the following order:
our %_attr_pri= (
   user_meta => -2,
   content_type => -1,
   save => 1,
   # everything else defaults to 0
);

sub new {
   my $class= shift;
   my %attrs= @_ == 1? %{$_[0]} : @_;
   my $self= bless { locks => [] }, $class;
   # Hook for subclasses to process attributes
   $self->_init(\%attrs) if $self->can('_init');
   # Every remaining attribute must have a writable accessor
   $self->$_($attrs{$_})
      for sort { ($_attr_pri{$a}||0) <=> ($_attr_pri{$b}||0) } keys %attrs;
   return $self;
}

sub load {
   my ($class_or_self, $path)= @_;
   $path= $class_or_self->path if ref $class_or_self && !defined $path;
   my $sbuf= secret(load_file => $path);
   my $span= $sbuf->span;
   my $pem;
   while (1) {
      $pem= Crypt::SecretBuffer::PEM->parse($span)
         or croak "No CRYPT MULTIKEY COFFER block found in file '$path'";
      last if $pem->label eq 'CRYPT MULTIKEY COFFER';
   }
   my $attrs= $class_or_self->_import_pem($pem, $path);
   $attrs->{path}= $path;
   # If called as a class method, return a new object
   return $class_or_self->new($attrs) unless ref $class_or_self;
   # Replace contents of object otherwise
   %$class_or_self= %$attrs;
   return $class_or_self;
}

=method generate_file_key

Generate a new AES key for the Coffer.  This gets called automatically when initially creating
a Coffer, but you can call it later to completely re-encrypt a Coffer, so long as

=over

=item *

any existing encrypted content has been decrypted into memory

=item *

all current L</locks> have all their public keys available

=back

=cut

# Try to find a PKey object for each key of each lock.  This can either decode the public
# key from BASE64, or find the key with matching fingerprint from a supplied collection.
# Returns true if all keys are present as PKey objects at the end.
sub _inflate_lock_keys {
   my ($self, $keys, $missing_out)= @_;
   # User can provide an arrayref or hashref of keys
   my %by_fingerprint= ref $keys eq 'ARRAY'? (map +($_->fingerprint => $_), @$keys)
                     : ref $keys eq 'HASH' ? (map +($_->fingerprint => $_), values %$keys)
                     : ();
   my $success= !!1;
   for (@{ $self->locks }) {
      for (@{ $_->{tumblers} }) {
         next if defined $_->{key}; # key object already loaded
         if (my $k= $by_fingerprint{$_->{key_fingerprint}}) {
            $_->{key}= $k;
         } elsif (defined $_->{pubkey}) {
            $_->{key}= Crypt::MultiKey::PKey->new(public => $_->{pubkey});
         } else {
            push @$missing_out, $_->{key_fingerprint}
               if $missing_out;
            $success= !!0;
         }
      }
   }
   return $success;
}

sub generate_file_key {
   my $self= shift;
   croak "Can't generate_file_key unless content has been decrypted or overwritten"
      if $self->has_ciphertext && !$self->has_content;
   my @old_locks= @{ $self->locks };
   croak "Generating a new Coffer file_key required all existing locks to have public keys present"
      if @old_locks && !$self->_inflate_lock_keys;
   my $new_file_key= secret(append_random => 64);
   my @new_locks;
   # If any keyslots exist, need to create new tumblers
   if (@old_locks) {
      local $self->{file_key}= $new_file_key;
      local $self->{locks}= \@new_locks;
      for (@old_locks) {
         $self->add_access(map $_->{key}, @{ $_->{tumblers} });
      }
   }
   # everything looks good.  Throw away any old ciphertext, and use new values.
   delete $self->{cipher_data}{ciphertext} if $self->{cipher_data};
   delete $self->{pem_header_mac};
   $self->{file_key}= $new_file_key;
   @{$self->{locks}}= @new_locks;
   $self;
}

=method add_access

  $coffer->add_access($key1, ... $keyN);

This creates a new L</locks> entry, which provides a new way to access the Coffer independent of
other locks.  The new lock can be opened when the private half of all N keys are passed to the
L</unlock> method.  The keys can be passed to L</unlock> in any order, so long as all of them
are present.

=cut

sub add_access {
   my ($self, @keys)= @_;
   @keys= @{$keys[0]} if @keys == 1 && ref $keys[0] eq 'ARRAY';
   croak "Require one or more PKey objects"
      unless @keys > 0;
   unless (defined $self->file_key) {
      croak "Coffer must be unlocked in order to ->add_access"
         if $self->has_ciphertext or @{ $self->locks };
      # No existing encrypted data, so create a new key
      $self->generate_file_key;
   }
   my @tumblers= map +{ key => $_, key_fingerprint => $_->fingerprint }, @keys;
   my $key_material= secret;
   $_->{key}->generate_key_material($_, $key_material) for @tumblers;
   # Salt isn't very useful when the tumbers are made from nonces and single-use ephemeral keys
   my %lock= ( tumblers => \@tumblers, kdf_info => 'cmk-coffer-lock', kdf_salt => '' );
   my $aes_key= Crypt::MultiKey::hkdf(\%lock, $key_material);
   delete @lock{'kdf_info','kdf_salt'}; # don't bulk up the file unnecessarily
   # Use the keyslot's aes key to encrypt the Coffer's aes key
   Crypt::MultiKey::symmetric_encrypt(\%lock, $aes_key, $self->file_key);
   push @{$self->locks}, \%lock;
   return \%lock;
}

=method lock

Delete the L</file_key> attribute and any attributes holding unencrypted secrets.

=cut

sub lock {
   my $self= shift;
   # Make sure there is a way to unlock it!
   croak "Can't lock Coffer when no locks are defined!  (you would lose your data)"
      unless @{ $self->locks };
   # No need to encrypt if the ciphertext exists and the content is not changed
   $self->encrypt if $self->content_changed || !$self->has_ciphertext;
   # Delete all secrets
   delete @{$self}{qw( content content_kv file_key content_changed )};
   $self;
}

=method unlock

  $coffer->unlock($key1, ... $keyN);

This attempts to find a lock which can be unlocked by this list of keys, or a subset of them.
If found, the L</file_key> attribute is set, after which decryption and encryption methods can
be used.

=cut

sub unlock {
   my ($self, @keys)= @_;
   @keys= @{$keys[0]} if @keys == 1 && ref $keys[0] eq 'ARRAY';
   my %by_fingerprint;
   for my $pkey (@keys) {
      croak "Expected PKey object"
         unless blessed($pkey) && $pkey->can('has_private');
      croak "key ".$pkey->fingerprint." does not have the private half loaded"
         unless $pkey->has_private;
      $by_fingerprint{$pkey->fingerprint}= $pkey;
   }
   # Look for a slot having these exact keys
   for my $lock (@{ $self->locks }) {
      my $tumblers= $lock->{tumblers};
      my @keys_in_order= map $by_fingerprint{$_->{key_fingerprint}}, @$tumblers;
      next if grep !defined, @keys_in_order;
      # All keys are present.  Reconstruct the shared secret key material from
      # the private key and the tumbler of each key in order.
      my $key_material= secret();
      $keys_in_order[$_]->recreate_key_material($tumblers->[$_], $key_material)
         for 0..$#keys_in_order;
      local $lock->{kdf_info}= 'cmk-coffer-lock' unless defined $lock->{kdf_info};
      local $lock->{kdf_salt}= '' unless defined $lock->{kdf_salt};
      my $aes_key= Crypt::MultiKey::hkdf($lock, $key_material);
      my $file_key= Crypt::MultiKey::symmetric_decrypt($lock, $aes_key);
      $self->file_key($file_key);
      # If 'authentication' is set, it means we need to validate the MAC of the
      # PEM file headers, which couldn't be done until we know the file_key.
      $self->authenticate if defined $self->authentication;
      return $self;
   }
   croak "No lock can be opened using the supplied keys";
}

=method authenticate

  $coffer->authenticate($bool_croak);

Validate the L<authentication> attribute using the current L</file_key>, returning boolean.
Pass a true value to croak on failure instead of returning false.

=cut

sub authenticate {
   my ($self, $croak)= @_;
   my $auth= $self->authentication;
   unless (defined $auth) {
      croak 'No authentication attribute available' if $croak;
      return 0;
   }
   unless ($self->unlocked) {
      croak 'No file_key available for authentication' if $croak;
      return 0;
   }
   unless ($auth->[1] eq 'HMAC-SHA256') {
      croak 'Expected HMAC-SHA256' if $croak;
      return 0;
   }
   my $mac= Crypt::MultiKey::hmac_sha256($self->_hmac_key, $auth->[0]);
   unless ($mac->memcmp($auth->[2]) == 0) {
      croak 'Header MAC failed; PEM headers have been modified since Coffer file was written.'
         if $croak;
      return 0;
   }
   return 1;
}

=method get

  $secret= $coffer->get($name);

When L<content_type> is C<< application/crypt-multikey-coffer-kv >>, this method can be used to
retrieve a secret by name.  If the content is not yet decrypted, it will try decrypting it and
fail if the L</file_key> is not loaded.

=cut

sub get {
   my ($self, $key)= @_;
   my $kv= $self->content_kv;
   croak "content is not initialized"
      unless $kv;
   $kv->{$key};
}

=method set

  $coffer->set($name, $secret);

When L<content_type> is C<< application/crypt-multikey-coffer-kv >>, this method can be used to
store a secret by name.  Using this method when the content is not yet decrypted triggers it
to be decrypted, and will fail if the L</file_key> is not loaded.  Using this method when no
content or ciphertext are defined will initialize the content_type to
C<< application/crypt-multikey-coffer-kv >> and the content_kv attribute to a hashref.

If the C<$secret> is not defined, it deletes C<$name> from the hashref.  There is no way to store
a state of "exists but undefined".

=cut

sub set {
   my ($self, $key, $val)= @_;
   if (!defined $self->content_type && !$self->has_ciphertext && !$self->has_content) {
      # initialize KV storage, which sets content_type.
      $self->content_kv({});
   }
   my $kv= $self->content_kv;
   if (defined $val) {
      $kv->{$key}= _coerce_secret($val);
      $self->content_changed(1);
   } elsif (exists $kv->{$key}) {
      delete $kv->{$key};
      $self->content_changed(1);
   }
}

=method save

  $coffer->save;         # saves to ->path
  $coffer->save($path);  # save to specific path, and initialize path attribute

Save changes to disk.  If you specify the C<$path> and the path attribute is not already set,
this initializes it.  This writes a new file and then renames it into place to ensure it doesn't
corrupt the existing file.

=cut

sub save {
   my ($self, $path)= @_;
   # Make sure there is a way to unlock it!
   croak "Can't save Coffer when no locks are defined!  (you would lose your data)"
      unless @{ $self->locks };
   $path //= $self->path or croak "No path set";
   $self->path($path) unless defined $self->path;
   # No need to encrypt if the ciphertext exists and the content is not changed
   $self->encrypt if $self->content_changed || !$self->has_ciphertext;
   # Build PEM object and serialize to file, renaming it into place
   $self->_export_pem->serialize->save_file($path, 'rename');
   $self;
}

=method encrypt

  $coffer->encrypt;

Regenerate the L</cipher_data> attribute, and use a fresh C<file_key> if possible.
The C<content> or C<content_kv> attributes must be initialized.

This is called automatically during L</save> if the Coffer is aware that the L<cipher_data>
is not current.

=cut

sub encrypt {
   my $self= shift;
   # preconditions: the content must be defined
   croak "Content is not ".($self->has_ciphertext? 'decrypted' : 'defined')
      unless $self->has_content;
   # If possible, use a fresh AES key.
   # This requires that all locks have the public key present.
   $self->generate_file_key if $self->_inflate_lock_keys;
   # Preserve some encryption parameters from the previous encryption.
   my %cipher_data;
   my $prev_cipher= $self->{cipher_data};
   @cipher_data{'cipher','pad'}= @{$prev_cipher}{'cipher','pad'}
      if defined $prev_cipher;
   # Main encryption routine
   Crypt::MultiKey::symmetric_encrypt(\%cipher_data, $self->_cipher_key, $self->content);
   $self->{cipher_data}= \%cipher_data;
}

=method decrypt

  $coffer->decrypt;

Regenerate the C<content> attribute from the C<cipher_data> attribute.  The L</cipher_data>
attribute must be initialized and the correct L</aes_key> must be loaded.

This is called automatically when accessing an uninitialized C<content> or C<content_kv> if the
Coffer is unlocked.

=cut

sub decrypt {
   my $self= shift;
   # preconditions: the cipher_data must have ciphertext and aes_key must be loaded
   croak "Coffer is locked"
      unless $self->unlocked;
   croak "No ciphertext defined"
      unless $self->has_ciphertext;
   $self->{content}= Crypt::MultiKey::symmetric_decrypt($self->cipher_data, $self->_cipher_key);
}

our %_importable_attributes= map +($_ => 1),
   qw( locks user_meta cipher_data content_type );
# Extract Coffer attributes from a Crypt::SecretBuffer::PEM object
sub _import_pem {
   my ($self, $pem, $path)= @_;
   $pem->headers->unicode_keys(1)->unicode_values(1);
   my %h= %{ $pem->headers };
   my %attrs;

   # Version check.
   if (my $min_version= delete $h{version}) {
      $min_version= version->parse($min_version);
      my $writer_version= version->parse(delete $h{writer_version} || 0);
      carp "'$path' requires version $min_version of Crypt::MultiKey::Coffer"
         ." but this is only version ".__PACKAGE__->VERSION
         if $min_version > __PACKAGE__->VERSION;
   } else {
      carp "No module version found in PEM headers";
   }
   # Even if version problems, try to proceed

   # The final header must be "pem_header_authentication".  We use that to ensure that nothing
   # has been altered since it was written.  All the headers before that get combined into the
   # canonical text that we compare to the MAC.
   my $header_kv= $pem->header_kv;
   croak "Headers must end with pem_header_mac"
      unless @$header_kv > 2 && $header_kv->[-2] eq 'pem_header_authentication';
   # The PEM parser removes any leading or trailing whitespace on attributes and values, but we
   # also ensured that no leading or trailing whitespace existed when we wrote the file.
   # Reconstructing the text negates any whitespace damage that may have occurred to the file.
   my $header_text= '';
   for (0..$#$header_kv-2) {
      $header_text .= $header_kv->[$_] . ($_ & 1? "\n" : ": ");
   }
   my ($mac_algo,$mac_base64)= split ':', $header_kv->[-1], 2;
   delete $h{pem_header_authentication};
   # ...but the MAC can't be validated until we decrypt the coffer.

   for my $key (keys %h) {
      my $node_ref= \\%attrs;
      for (split /\./, $key) {
         # A pure decimal element becomes an array index
         if (looks_like_number($_) && /^[0-9]+\z/) {
            # Prevent a malicious file from exhausting memory with an insane array index
            croak "Array index '$_' out of bounds" if $_ > keys %h;
            if (!defined $$node_ref) {
               $$node_ref ||= [];
            }
            elsif (ref $$node_ref ne 'ARRAY') {
               croak "Can't assign to $key, not an array ref at '$_'";
            }
            $node_ref= \$$node_ref->[$_];
         }
         else {
            if (!defined $$node_ref) {
               $$node_ref ||= {};
            }
            elsif (ref $$node_ref ne 'HASH') {
               croak "Can't assign to $key, not a hash ref at '$_'";
            }
            $node_ref= \$$node_ref->{$_};
         }
      }
      croak "Attempt to overwrite $key" if defined $$node_ref;
      $$node_ref= $h{$key};
   }

   # Ensure structure of locks is valid
   $self->_validate_locks($attrs{locks});
   # base64 decode the binary fields
   for my $lock (@{ $attrs{locks} }) {
      for my $tmbl (@{ $lock->{tumblers} }) {
         for (qw( pubkey ephemeral_pubkey rsa_key_ciphertext )) {
            $tmbl->{$_}= decode_base64($tmbl->{$_})
               if defined $tmbl->{$_};
         }
      }
      # base64 decode binary fields
      for (qw( kdf_salt ciphertext )) {
         $lock->{$_}= decode_base64($lock->{$_})
            if defined $lock->{$_};
      }
   }

   # PEM object provides a Span with encoding=BASE64.  Need to decode that to bytes.
   my $ciphertext= $pem->content;
   if (_isa_secret_span($ciphertext) && $ciphertext->encoding == BASE64) {
      my $buf= secret;
      $ciphertext->copy_to($buf, encoding => ISO8859_1);
      $ciphertext= $buf;
   }
   $attrs{cipher_data}{ciphertext}= $ciphertext;

   # validate all attributes to make sure constructor doesn't call methods
   if (my @unauth= grep !$_importable_attributes{$_}, keys %attrs) {
      carp "The following PEM headers cannot be imported: ".join(', ', sort @unauth);
      delete @attrs{@unauth};
   }

   $attrs{authentication}= [ $header_text, $mac_algo, decode_base64($mac_base64) ];
   \%attrs;
}

# Utility to flatten Perl structured data into plain key/value appropriate for PEM headers
sub _struct_to_kv {
   my ($prefix, $node)= @_;
   if (!ref $node) {
      # The value may not start or end with whitespace or contain any control characters.
      # It may contain unicode, in which case we helpfully encode that.
      croak "Value at $prefix may not contain control characters" if $node =~ /[\x00-\x1F\x7F]/;
      croak "Value at $prefix may not begin or end with whitespace" if $node =~ /(^\s|\s\z)/;
      return ( $prefix => $node );
   }
   elsif (ref $node eq 'ARRAY') {
      return map _struct_to_kv($prefix.'.'.$_ => $node->[$_]), 0 .. $#$node;
   }
   elsif (ref $node eq 'HASH') {
      my @ret;
      for (sort keys %$node) {
         /^[^\x00-\x1F\x7F .:0-9][^\x00-\x1F\x7F .:]*\z/
            or croak "Invalid hash key for export as PEM header: '$_'";
         push @ret, _struct_to_kv($prefix.'.'.$_ => $node->{$_});
      }
      return @ret;
   }
   else {
      croak "Can't flatten type ".ref($node)." into PEM headers";
   }
}

sub _export_pem {
   my $self= shift;
   my @locks_export;
   for (@{ $self->locks }) {
      my %lock= %$_;
      for (@{ delete $lock{tumblers} }) {
         my %tumbler= %$_;
         # Need to remove the key objects from the locks definition before serializing.
         delete $tumbler{key};
         # base64 encode binary fields
         for (qw( ephemeral_pubkey rsa_key_ciphertext )) {
            $tumbler{$_}= encode_base64($tumbler{$_}, '')
               if defined $tumbler{$_};
         }
         push @{ $lock{tumblers} }, \%tumbler;
      }
      # base64 encode binary fields
      for (qw( kdf_salt ciphertext )) {
         $lock{$_}= encode_base64($lock{$_}, '')
            if defined $lock{$_};
      }
      push @locks_export, \%lock;
   }
   my %cipher_data_export= %{ $self->cipher_data };
   my $ciphertext= delete $cipher_data_export{ciphertext};
   delete $cipher_data_export{header_mac};  # old value not relevant
   delete $cipher_data_export{header_text};
   my @header_kv= (
      version => '0.001',
      writer_version => __PACKAGE__->VERSION,
      _struct_to_kv(user_meta => $self->user_meta),
      _struct_to_kv(locks     => \@locks_export),
      content_type => $self->content_type,
      _struct_to_kv(cipher_data => \%cipher_data_export),
   );
   # PEM doesn't define a character encoding for headers, but for this use of PEM, UTF-8 seems
   # to be the most sensible encoding.  Try to coerce things to UTF-8 so that it "just works".
   for (grep defined && /[^\x00-\x7F]/, @header_kv) {
      utf8::decode($_); # in case the string was already encoded
      utf8::encode($_);
   }
   # Build the canonical PEM header text so we can validate it with a MAC.
   my $header_text= '';
   for (0..$#header_kv) {
      $header_text .= $header_kv[$_] . ($_ & 1? "\n" : ": ");
   }
   my $header_mac= 'HMAC-SHA256:';
   Crypt::MultiKey::hmac_sha256($self->_hmac_key, $header_text)
      ->span->append_to($header_mac, encoding => BASE64);
   push @header_kv, 'pem_header_authentication' => $header_mac;
   return Crypt::SecretBuffer::PEM->new(
      label     => 'CRYPT MULTIKEY COFFER',
      header_kv => \@header_kv,
      content   => $ciphertext,
   );
}

our %_known_lock_fields= map +($_ => 1),
   qw( cipher kdf_salt ciphertext tumblers );
our %_known_tumbler_fields= map +($_ => 1),
   qw( key key_fingerprint pubkey ephemeral_pubkey rsa_key_ciphertext );
sub _validate_locks {
   my ($self, $locks)= @_;
   croak "locks must be an arrayref"
      unless ref $locks eq 'ARRAY';
   my @unknown;
   for my $lock_i (0..$#$locks) {
      my $lock= $locks->[$lock_i];
      for (qw( cipher ciphertext )) {
         croak "Missing '$_' in lock $lock_i"
            unless defined $lock->{$_};
      }
      croak "lock[$lock_i]{tumblers} must be an arrayref"
         unless ref $lock->{tumblers} eq 'ARRAY';
      for my $tmbl_i (0..$#{$lock->{tumblers}}) {
         my $tmbl= $lock->{tumblers}[$tmbl_i];
         # Need to be able to identify the key
         croak "No key details for tumbler $tmbl_i"
            unless defined $tmbl->{key} || defined $tmbl->{key_fingerprint} || defined $tmbl->{pubkey};
         # Need either ephemeral_pubkey or rsa_key_ciphertext
         croak "tumbler $tmbl_i must have rsa_key_ciphertext or ephemeral_pubkey"
            unless defined $tmbl->{rsa_key_ciphertext} xor defined $tmbl->{ephemeral_pubkey};
         @unknown= grep !$_known_tumbler_fields{$_}, keys %$tmbl;
         carp "Unknown tumbler[$tmbl_i] attributes: ".join(', ', @unknown)
            if @unknown;
      }
      @unknown= grep !$_known_lock_fields{$_}, keys %$lock;
      carp "Unknown lock[$lock_i] attributes: ".join(', ', @unknown)
         if @unknown;
   }
   return 1;
}

1;
