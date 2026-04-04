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
use Crypt::MultiKey::LockMechanism;
use constant { DICT_CONTENT_TYPE => 'application/crypt-multikey-coffer-dict' };

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

=attribute bundled_keys

  $coffer->bundled_keys(1);        # $coffer->save will also export referenced PKeys
  $coffer->bundled_keys('public'); # coffer PEM will have OpenSSL 'PUBLIC KEY' PEM appended

The L</locks> attribute references the keys that can unlock it by the key fingerprint.  The keys
can be saved separately to be loaded by the application and added with L</insert_keys>, or they
can be appended to the Coffer to be loaded automatically when loading the Coffer, to keep
everything together in one place.  When this option is set to a true value, the L</export>
method will write out the Coffer PEM block followed by the PEM serializations of each of the
L<PKey objects|Crypt::SecretBuffer::PKey/export>.  (They serialize as either public-only or
encrypted-private PEM blocks with PKey metadata included.  Obviously it would defeat the purpose
of the Coffer to serialize unencrypted private keys to the same file)

You can set this option to C<'public'> to write only the public key in the standard OpenSSL
format without any of the PKey metadata.  Having the full public key present allows a new Coffer
to be written that is decryptable by all the same PKeys as the current one, while not giving any
advantage to an attacker by showing them the PKey metadata.

=cut

sub path { @_ > 1? shift->_set_path(@_) : $_[0]{path} }
sub _set_path { $_[0]{path}= $_[1]; $_[0] }

sub bundled_keys { @_ > 1? shift->_set_bundled_keys(@_) : $_[0]{bundled_keys} }
sub _set_bundled_keys {
   my ($self, $val)= @_;
   # coerce to either 1, 0, or 'public'
   $val= !$val? 0
       : $val eq 'public'? 'public'
       : 1;
   $_[0]{bundled_keys}= $val;
}

=attribute lock_mechanism

This object handles the details of locking and unlocking, and lets Coffer and Vault share code.
The implementation could be configurable in the future, but currently only the default of
L<Crypt::MultiKey::LockMechanism> is supported.

Several methods are directly delegated to this object:

=over

=item L<locks|Crypt::MultiKey::LockMechanism/locks>

=item L<add_access|Crypt::MultiKey::LockMechanism/add_access>

=item L<insert_keys|Crypt::MultiKey::LockMechanism/insert_keys>

=item L<unlock|Crypt::MultiKey::LockMechanism/unlock>

=back

=attribute unlocked

True if the Coffer is in an unlocked state, meaning content can be read and written.

=cut

sub lock_mechanism { $_[0]{lock_mechanism} //= Crypt::MultiKey::LockMechanism->new }
sub _set_primary_skey { shift->lock_mechanism->_set_primary_skey(@_) }
sub locks { shift->lock_mechanism->locks(@_) }
sub _set_locks { shift->lock_mechanism->_set_locks(@_) }
sub add_access { shift->lock_mechanism->add_access(@_) }
sub insert_keys { shift->lock_mechanism->insert_keys(@_) }
sub unlock {
   my $self= shift;
   $self->lock_mechanism->unlock(@_);
   # If 'authentication' is set, it means we need to validate the MAC of the
   # PEM file headers, which couldn't be done until we know the primary_skey.
   $self->authenticate if defined $self->authentication;
   $self;
}

sub unlocked {
   my $self= shift;
   !$self->lock_mechanism->initialized || $self->lock_mechanism->unlocked;
}

=attribute user_meta

An arbitrary hashref of name/value strings that will be added to the exported PEM as headers
of the form C<< user_meta.$name = $value >>.  Note that headers are B<plaintext>.
If you wish to store secret user metadata it needs to be part of L</content>, which can be
accomplished conveniently using L</content_dict>.

Because PEM has no escaping system, the names and values may not contain control characters or
begin or end with space characters.  The names also may not contain '.' or be purely numeric,
because these are used for encoding the structure of the data.

Warning: the authenticity of C<user_meta> does not get checked until you have
L<unlocked|/unlock> the coffer.  Never trust C<user_meta> on a locked Coffer unless the file
was stored securely.

=attribute name

A shortcut for C<< ->user_meta->{name} >>.  This helps encourage you to at least provide a label
for the file indicating its purpose or contents.  This defaults to the basename of the L</path>.

=cut

sub user_meta { @_ > 1? shift->_set_user_meta(@_) : ($_[0]{user_meta} ||= {}) }
sub _set_user_meta { $_[0]{user_meta}= $_[1]; $_[0] }

sub name { @_ > 1? shift->_set_name(@_) : $_[0]->user_meta->{name} }
sub _set_name { $_[0]->user_meta->{name}= $_[1]; $_[0] }

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
C<< application/crypt-multikey-coffer-dict >> enables the L</get> and L</set> methods to use the
C<content> as a key/value dictionary.

=over

=item is_dict

Accessor to test whether the content_type indicates a dictionary encoding.

=back

=attribute content

This attribute is an unencrypted L<Crypt::SecretBuffer> of the secret data of the Coffer.
If it isn't initialized and an encrypted copy exists (L</has_ciphertext> is true), reading this
attribute will attempt to decrypt it, and fail if the Coffer is still locked.  If there is no
encrypted copy (such as when a Coffer object is first created) reading this attribute just
returns C<undef>.

Writing this attribute will invalidate the C<cipher_data> attribute, forcing it to be
re-encrypted when you call L</save>.  Beware that if you make changes to the SecretBuffer object
directly, the Coffer object will not be aware of those changes and the changes may be lost if
the Coffer doesn't know they need re-encrypted.  Set C<< $coffer->content_changed(1) >> if you
need to flag the content as having changed.

If you are using the Coffer for name/value dictionary storage, use the L</get> and L</set>
methods instead of accessing this attribute.  In dictionary mode, accessing this attribute will
trigger a serialization of the data.

=over

=item has_content

True if the C<content> or C<content_dict> attributes are defined, meaning that either the Coffer
is decrypted or has been initialized to a new value.  Maybe unintuitively, it returns false for
an unlocked coffer where the content hasn't been lazy-decrypted yet.

=back

=attribute content_dict

This attribute is used when the content type is C<< application/crypt-multikey-coffer-dict >>.
and allows you to work with a hash of name/value pairs where each value is a SecretBuffer
or L<Span|Crypt::SecretBuffer::Span>.  Changes to this hash will not be seen automatically;
either use L</set>, or write the whole attribute to properly indicate to the Coffer that it
needs re-encrypted.

=attribute content_changed

True if you have used accessors to alter your C<content> or C<content_dict> attribute.  If you
modify the content SecretBuffer yourself, you should set this attribute to true so that the
Coffer knows it needs to re-encrypt the content.

=cut

sub content_type { @_ > 1? shift->_set_content_type(@_) : $_[0]{content_type} }
sub _set_content_type { $_[0]{content_type}= $_[1]; $_[0] }
sub is_dict { (shift->content_type // '') eq DICT_CONTENT_TYPE }

sub content {
   my $self= shift;
   return $self->_set_content($_[0])
      if @_;
   $self->decrypt
      if !$self->has_content && $self->has_ciphertext;
   $self->_pack_content_dict
      if !defined $self->{content} && defined $self->{content_dict};
   $self->{content}
}

sub content_dict {
   my $self= shift;
   return $self->_set_content_dict($_[0])
      if @_;
   croak "content_type is not ".DICT_CONTENT_TYPE
      unless $self->is_dict;
   $self->decrypt
      if !$self->has_content && $self->has_ciphertext;
   $self->_unpack_content_dict
      if !defined $self->{content_dict} && defined $self->{content};
   $self->{content_dict} //= {};
}

sub has_content { defined $_[0]{content} || defined $_[0]{content_dict} }
sub initialized { $_[0]->has_content || $_[0]->has_ciphertext }
sub content_changed { $_[0]{content_changed}= $_[1] if @_ > 1; !!$_[0]{content_changed} }

sub _set_content {
   my ($self, $val)= @_;
   if (!defined $val) {
      $self->{content}= undef;
      $self->{content_dict}= undef;
   } else {
      $self->{content}= _coerce_secret($val);
   }
   # discard key/value map, if any
   delete $self->{content_dict};
   $self->content_changed(1);
   $self;
}

sub _set_content_dict {
   my ($self, $val)= @_;
   croak "Clear content with ->content(undef) rather than ->content_dict(undef)"
      unless defined $val;
   croak "Expected hashref"
      unless ref $val eq 'HASH';
   # Ensure that all values are SecretBuffer or SecretBuffer::Span
   $val= { %$val }; # clone before converting values
   $_= _coerce_secret($_)
      for values %$val;
   $self->{content_dict}= $val;
   # override content type
   $self->{content_type}= DICT_CONTENT_TYPE;
   # discard plain scalar content, if any
   delete $self->{content};
   $self->content_changed(1);
   $self;
}

sub _unpack_content_dict {
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
   # All strings are currently SecretBuffer objects.  Unmask the keys.
   for (0 .. ($#kv-1)/2) {
      my $k;
      $kv[$_*2]->copy_to($k);
      $kv[$_*2]= $k;
   }
   my %kv= @kv;
   delete $self->{content}; # content_dict is the official value, now
   $self->{content_dict}= \%kv;
}

sub _pack_content_dict {
   my $self= shift;
   my $buf= secret;
   $buf->append_lenprefixed($_) for %{ $self->{content_dict} };
   delete $self->{content_dict};
   $self->{content}= $buf;
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

  # as a constructor
  $coffer= Crypt::MultiKey::Coffer->load($source, %options);
  # as a method
  $coffer->load($source, %options);
  # $source may be:
  #   $file_path
  #   \$buffer
  #   Crypt::SecretBuffer
  #   Crypt::SecretBuffer::Span
  #   Crypt::SecretBuffer::PEM
  # options:
  #   path         => $file_path   # value for 'path' attribute when using a buffer
  #   bundled_keys => $bool        # whether to process PKey PEM blocks found in buffer

Load a Coffer from a file or buffer or L<PEM object|Crypt::SecretBuffer::PEM>.  This does not
decrypt the data.  See L</unlock>.

When loading from a file or buffer, the PEM encoding of the Coffer may be followed by PEM
encodings of the PKey objects.  If you request C<bundled_keys>, they will be inflated to
L<PKey objects|Crypt::SecretBuffer::PKey> and passed to L</insert_keys>.  This will also
initialize the L</bundled_keys> attribute of the created object.

Neither 'path' nor 'bundled_keys' attributes are serialized in the Coffer PEM, for security
reasons.  They must be specified / requested by the caller.

=cut

# Make sure attributes (or methods) are applied in the following order:
our %_attr_pri= (
   user_meta => -2,
   content_type => -1,
   # everything else defaults to 0
);

sub new {
   my $class= shift;
   my %attrs= @_ == 1? %{$_[0]} : @_;
   my $self= bless {}, $class;
   # Hook for subclasses to process attributes
   $self->_init(\%attrs) if $self->can('_init');
   # Every remaining attribute must have a writable accessor
   for (sort { ($_attr_pri{$a}||0) <=> ($_attr_pri{$b}||0) } keys %attrs) {
      my $setter= "_set_$_";
      $self->$setter($attrs{$_});
   }
   return $self;
}

sub load {
   my ($class_or_self, $path_or_data_or_pem, %options)= @_;
   # If called as a method on an object, default to loading the ->path attribute
   $path_or_data_or_pem //= $class_or_self->path
      if ref $class_or_self;
   
   # There should be exactly one COFFER pem block and any number of ENCRYPTED PRIVATE KEY or
   # PUBLIC KEY blocks.
   my ($coffer_pem, @pkey_pem);
   for (Crypt::MultiKey::_extract_pems_from_something($path_or_data_or_pem, \%options)) {
      if ($_->label eq 'CRYPT MULTIKEY COFFER') {
         croak "More than one CRYPT MULTIKEY COFFER pem block in file"
            if defined $coffer_pem;
         $coffer_pem= $_;
      }
      elsif ($options{bundled_keys} and (
         $_->label eq 'ENCRYPTED PRIVATE KEY'
         || $_->label eq 'PUBLIC KEY'
      )) {
         push @pkey_pem, $_;
      }
      else {
         carp "Ignoring PEM block ".$_->label;
      }
   }
   croak "No CRYPT MULTIKEY COFFER pem block in file"
      unless defined $coffer_pem;
   my $attrs= $class_or_self->_attrs_from_pem($coffer_pem, $options{path});
   $attrs->{path}= $options{path};
   $attrs->{bundled_keys}= $options{bundled_keys};
   my $self;
   if (ref $class_or_self) {
      # Called on existing object. Replace attributes.
      $self= $class_or_self;
      %$self= ();
      # Hook for subclasses to process attributes
      $self->_init($attrs) if $self->can('_init');
      # Every remaining attribute must have a writable accessor
      $self->$_($attrs->{$_})
         for sort { ($_attr_pri{$a}||0) <=> ($_attr_pri{$b}||0) } keys %$attrs;
   } else {
      # If called as a class method, return a new object
      $self= $class_or_self->new($attrs);
   }
   my @pkeys;
   for my $pk_pem (@pkey_pem) {
      # If a key can't be loaded, it shouldn't be a fatal error, because the coffer could
      # still be unlockable by other keys, or copies of the keys saved elsewhere.
      # But, it's a big enough problem to warrant writing stderr.
      eval { push @pkeys, Crypt::MultiKey::PKey->load($pk_pem) }
         or carp "Warning: failed to load PKey found alongside Coffer: $@";
   }
   $self->insert_keys(@pkeys) if @pkeys;
   return $self;
}

=method get

  $secret= $coffer->get($name);

When L<content_type> is C<< application/crypt-multikey-coffer-dict >>, this method can be used to
retrieve a secret by name.  If the content is not yet decrypted, it will try decrypting it and
fail unless the Coffer is L</unlocked>.

=cut

sub get {
   my ($self, $key)= @_;
   my $dict= $self->content_dict;
   croak "content is not initialized"
      unless $dict;
   $dict->{$key};
}

=method set

  $coffer->set($name, $secret);

When L<content_type> is C<< application/crypt-multikey-coffer-dict >>, this method can be used
to store a secret by name.  If the content is not yet decrypted, it will try decrypting it and
fail unless the Coffer is L</unlocked>.  Using this method when no content or ciphertext are
defined will initialize the content_type to C<< application/crypt-multikey-coffer-dict >> and
the C<content_dict> attribute to a hashref.

If the C<$secret> is not defined, it deletes C<$name> from the hashref.  There is no way to
store a state of "exists but undefined".

=cut

sub set {
   my ($self, $key, $val)= @_;
   if (!defined $self->content_type && !$self->has_ciphertext && !$self->has_content) {
      # initialize KV storage, which sets content_type.
      $self->content_dict({});
   }
   my $dict= $self->content_dict;
   if (defined $val) {
      $dict->{$key}= _coerce_secret($val);
      $self->content_changed(1);
   } elsif (exists $dict->{$key}) {
      delete $dict->{$key};
      $self->content_changed(1);
   }
   $self;
}

=method export

  $buf= $coffer->export;

Serialize the Coffer to a buffer, in PEM format.

=method save

  $coffer->save;           # saves to ->path
  $coffer->save($path);    # save to specific path, and initialize path attribute

Save changes to disk.  If you specify the C<$path> and the path attribute is not already set,
this initializes it.  This writes a new file and then renames it into place to ensure it doesn't
corrupt the existing file.

=cut

sub export {
   my ($self)= @_;
   # Make sure there is a way to unlock it!
   croak "Can't save Coffer when no locks are defined!  (you would lose your data)"
      unless @{ $self->locks };
   # No need to encrypt if the ciphertext exists and the content is not changed
   $self->encrypt if $self->content_changed || !$self->has_ciphertext;
   # Build PEM object and serialize to buffer
   my $buf= $self->_export_pem->serialize;
   if ($self->bundled_keys) {
      my $method= $self->bundled_keys eq 'public'? 'export_pem_openssl_public_key' : 'export_pem';
      my %keys;
      my $n_missing= 0;
      for (@{ $self->locks }) {
         for (@{ $_->{tumblers} }) {
            if (defined $_->{key}) {
               $keys{$_->{key}->fingerprint}= $_->{key};
            } else {
               ++$n_missing;
            }
         }
      }
      carp "Exporting 'bundled_keys' but $n_missing tumblers lack a PKey object"
         if $n_missing;
      for my $k (map $keys{$_}, sort keys %keys) { # export in a stable order
         # Make sure we aren't bundling an unprotected private key
         if (!defined $_->protection_scheme) {
            $buf->append($_->export_pem_openssl_public_key->serialize);
         } else {
            $buf->append($_->$method->serialize);
         }
      }
   }
   return $buf;
}

sub save {
   my ($self, $path)= @_;
   $path //= $self->path // croak "No path set";
   $self->export->save_file($path, "rename");
   $self->path($path) unless defined $self->path;
   $self;
}

=method authenticate

  $bool= $coffer->authenticate;
  $coffer->authenticate(1); # automatic croak

Validate the L</authentication> attribute, returning boolean.  This can only be called after
L<unlocking|/unlock> the Coffer.  Pass a true value to have it croak on failure instead of
returning false.

=cut

sub authenticate {
   my ($self, $croak)= @_;
   my $auth= $self->authentication;
   unless (defined $auth) {
      croak 'No authentication attribute available' if $croak;
      return 0;
   }
   unless (defined $self->lock_mechanism->primary_skey) {
      croak 'No primary_skey available for authentication' if $croak;
      return 0;
   }
   unless ($auth->[1] eq 'HMAC-SHA256') {
      croak 'Only HMAC-SHA256 is supported' if $croak;
      return 0;
   }
   my $mac= Crypt::MultiKey::hmac_sha256($self->lock_mechanism->hmac_skey, $auth->[0]);
   unless ($mac->memcmp($auth->[2]) == 0) {
      croak 'Header MAC failed; PEM headers have been modified since Coffer file was written.'
         if $croak;
      return 0;
   }
   return 1;
}

=method lock

Delete the L</primary_skey> attribute and any attributes holding unencrypted secrets.

=cut

sub lock {
   my $self= shift;
   # No need to encrypt if the ciphertext exists and the content is not changed
   $self->encrypt if $self->content_changed || !$self->has_ciphertext;
   # deletes primary_skey
   $self->lock_mechanism->lock;
   # Delete all secrets
   delete @{$self}{qw( content content_dict content_changed )};
   $self;
}

=method encrypt

  $coffer->encrypt;

Regenerate the L</cipher_data> attribute from L</content> (or C<content_dict>) attribute.
The C<content> or C<content_dict> attributes must be initialized.
This will use a fresh AES key if all lock tublers have public keys present.

This is called automatically during L</save> if the Coffer is aware that the L</cipher_data>
is not current.

=cut

sub encrypt {
   my $self= shift;
   # preconditions: the content must be defined
   croak "Content is not ".($self->has_ciphertext? 'decrypted' : 'defined')
      unless $self->has_content;
   # If possible, use a fresh AES key.  We can only replace it when all locks have
   # public keys inserted.
   my ($complete, $incomplete)= $self->lock_mechanism->insert_keys;
   unless (@$incomplete) {
      $self->lock_mechanism->generate_primary_skey;
      # Throw away any old ciphertext
      delete $self->{cipher_data}{ciphertext} if $self->{cipher_data};
      # Any authentication field is invalid now.
      delete $self->{authentication};
   }
   # Preserve some encryption parameters from the previous encryption.
   my %cipher_data;
   my $prev_cipher= $self->{cipher_data};
   @cipher_data{'cipher','pad'}= @{$prev_cipher}{'cipher','pad'}
      if defined $prev_cipher;
   # Main encryption routine
   Crypt::MultiKey::symmetric_encrypt(\%cipher_data, $self->lock_mechanism->cipher_skey, $self->content);
   $self->{cipher_data}= \%cipher_data;
   $self->content_changed(0);
   $self;
}

=method decrypt

  $coffer->decrypt;

Regenerate the C<content> attribute from the C<cipher_data> attribute.  Returns C<$coffer> for
chaining.  The L</cipher_data> attribute must be initialized and the correct L</primary_skey>
must be loaded.

This is called automatically when accessing an uninitialized C<content> or C<content_dict> if the
Coffer is unlocked.

=cut

sub decrypt {
   my $self= shift;
   # preconditions: the cipher_data must have ciphertext and aes_key must be loaded
   croak "Coffer is locked"
      unless $self->unlocked;
   croak "No ciphertext defined"
      unless $self->has_ciphertext;
   $self->{content}= Crypt::MultiKey::symmetric_decrypt($self->cipher_data, $self->lock_mechanism->cipher_skey);
   $self;
}

our %_importable_attributes= map +($_ => 1),
   qw( locks user_meta cipher_data content_type );
# Extract Coffer attributes from a Crypt::SecretBuffer::PEM object
sub _attrs_from_pem {
   my ($self, $pem, $path)= @_;
   my $header_kv= $pem->header_kv;

   # The first two headers must be version and writer_version.
   croak "Headers must start with version and writer_version"
      unless @$header_kv > 4 && $header_kv->[0] eq 'version' && $header_kv->[2] eq 'writer_version';
   my $min_version= version->parse($header_kv->[1]);
   carp "'$path' requires version $min_version of Crypt::MultiKey::Coffer"
      ." but this is only version ".__PACKAGE__->VERSION
      if $min_version > __PACKAGE__->VERSION;
   # Even if version problems, try to proceed

   # The final header must be "pem_header_authentication".  We use that to ensure that nothing
   # has been altered since it was written.  All the headers before that get combined into the
   # canonical text that we compare to the MAC.
   croak "Headers must end with pem_header_authentication"
      unless @$header_kv > 2 && $header_kv->[-2] eq 'pem_header_authentication';
   # The PEM parser removes any leading or trailing whitespace on attributes and values, but we
   # also ensured that no leading or trailing whitespace existed when we wrote the file.
   # Reconstructing the text negates any whitespace damage that may have occurred to the file.
   my $header_text= '';
   for (0..$#$header_kv-2) {
      $header_text .= $header_kv->[$_] . ($_ & 1? "\n" : ": ");
   }
   my ($mac_algo,$mac_base64)= split ':', $header_kv->[-1], 2;
   # ...but the MAC can't be validated until we decrypt the coffer.

   my $attrs= Crypt::MultiKey::_inflate_pem_header_kv(@{$header_kv}[4..($#$header_kv-2)]);
   # Ensure structure of locks is valid
   Crypt::MultiKey::LockMechanism->_validate_locks($attrs->{locks});
   # base64-decode the byte strings
   for my $lock (@{ $attrs->{locks} }) {
      for my $tmbl (@{ $lock->{tumblers} }) {
         for (qw( ephemeral_pubkey rsa_key_ciphertext kem_ciphertext )) {
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
   $attrs->{cipher_data}{ciphertext}= $ciphertext;

   # validate all attributes to make sure constructor doesn't call methods
   if (my @unauth= grep !$_importable_attributes{$_}, keys %$attrs) {
      carp "The following PEM headers cannot be imported: ".join(', ', sort @unauth);
      delete @$attrs{@unauth};
   }

   $attrs->{authentication}= [ $header_text, $mac_algo, decode_base64($mac_base64) ];
   return $attrs;
}

sub _export_pem {
   my $self= shift;
   my @locks_export= @{ $self->locks };
   for my $lock (@locks_export) {
      $lock= { %$lock };
      for (qw( kdf_salt ciphertext )) {
         $lock->{$_}= encode_base64($lock->{$_}, '')
            if defined $lock->{$_};
      }
      for my $tmbl (@{ $lock->{tumblers}= [ @{$lock->{tumblers}} ] }) {
         $tmbl= { %$tmbl };
         # Need to remove the key objects from the locks definition before serializing.
         delete $tmbl->{key};
         for (qw( ephemeral_pubkey rsa_key_ciphertext kem_ciphertext )) {
            $tmbl->{$_}= encode_base64($tmbl->{$_}, '')
               if defined $tmbl->{$_};
         }
      }
   }
   my %cipher_data_export= %{ $self->cipher_data };
   my $ciphertext= delete $cipher_data_export{ciphertext};
   my @header_kv= Crypt::MultiKey::_flatten_to_pem_header_kv(
      version        => '0.001',
      writer_version => __PACKAGE__->VERSION,
      user_meta      => $self->user_meta,
      locks          => \@locks_export,
      content_type   => $self->content_type,
      cipher_data    => \%cipher_data_export,
   );
   # Build the canonical PEM header text so we can validate it with a MAC.
   my $header_text= '';
   for (0..$#header_kv) {
      $header_text .= $header_kv[$_] . ($_ & 1? "\n" : ": ");
   }
   my $header_mac= 'HMAC-SHA256:';
   Crypt::MultiKey::hmac_sha256($self->lock_mechanism->hmac_skey, $header_text)
      ->span->append_to($header_mac, encoding => BASE64);
   push @header_kv, 'pem_header_authentication' => $header_mac;
   return Crypt::SecretBuffer::PEM->new(
      label     => 'CRYPT MULTIKEY COFFER',
      header_kv => \@header_kv,
      content   => $ciphertext,
   );
}

1;
