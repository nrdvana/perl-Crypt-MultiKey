package Crypt::MultiKey::Coffer;
use strict;
use warnings;
use Carp;
use Scalar::Util qw( blessed );
use MIME::Base64 ();
use Crypt::SecretBuffer qw/ secret HEX BASE64 ISO8859_1 /;
use Crypt::SecretBuffer::PEM;
use Crypt::MultiKey;
use constant { KV_CONTENT_TYPE => 'application/crypt-multikey-coffer-kv' };

sub _isa_pem_obj { blessed($_[0]) && $_[0]->can('headers') && $_[0]->can('content') }
sub _isa_pow2 { $_[0] == _round_up_to_pow2($_[0]) }
sub _isa_secret { blessed($_[0]) && $_[0]->can('unmask_to') }
sub _isa_secret_span { blessed($_[0]) && $_[0]->can('subspan') }
sub _coerce_secret {
   my $val= shift;
   return $val if _isa_secret($val) || _isa_secret_span($val);
   croak "Expected a Crypt::SecretBuffer, Crypt::SecretBuffer::Span, or something that can stringify to bytes"
      if ref $val && !blessed($val);
   return secret($val);
}
sub _round_up_to_pow2 {
   my $n= $_[0] - 1;
   $n |= $n >> 1;
   $n |= $n >> 2;
   $n |= $n >> 4;
   $n |= $n >> 8;
   $n |= $n >> 16;
   $n |= $n >> 32;
   return $n+1;
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

A Coffer is encoded in PEM, with leading attributes that describe the contents of the coffer
and which keys can unlock it.

  -----BEGIN CRYPT MULTIKEY COFFER-----
  version: 0.001
  writer_version: 0.001
  user_meta.name: User-supplied Name of This Coffer For Convenience
  user_meta.xyz: Arbitrary user-supplied metadata
  content_type: application/binary
  locks.0.tumbler.0.key_fingerprint: KeyFingerprint
  locks.0.tumbler.0.ephemeral_pubkey: base64==
  locks.0.kdf_salt: base64==
  locks.0.ciphertext: base64==
  locks.1.tumbler.0.key_fingerprint: Key0Fingerprint
  locks.1.tumbler.0.ephemeral_pubkey: base64==
  locks.1.tumbler.1.key_fingerprint: Key1Fingerprint
  locks.1.tumbler.1.ephemeral_pubkey: base64==
  locks.1.kdf_salt: base64==
  locks.1.ciphertext: base64==
  
  Base64Base64Base64Base64.....==
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
contain '.' or be purely numeric, because these are sued for encoding the structure of the data.

=attribute name

A shortcut for C<< ->user_meta->{name} >>.  This helps encourage you to at least provide a label
for the file indicating its purpose or contents.  This defaults to the basename of the L</path>.

=cut

sub path { $_[0]{path}= $_[1] if @_ > 1; $_[0]{path} }

sub user_meta { $_[0]{user_meta}= $_[1] if @_ > 1; $_[0]{user_meta} ||= {} }

sub name {
   my $meta= $_[0]->user_meta;
   $meta->{name}= $_[1] if @_ > 1;
   $meta->{name};
}

=attribute aes_key

A L<Crypt::SecretBuffer> holding the AES key used to encrypt/decrypt the content.
A Coffer is logically "unlocked" when the C<aes_key> is defined, and "locked" (or uninitialized)
when it isn't.

=over

=item unlocked

Convenience accessor that returns true if C<aes_key> is defined.

=back

=cut

sub aes_key {
   $_[0]->_set_aes_key($_[1]) if @_ > 1;
   $_[0]{aes_key}
}

sub unlocked { defined $_[0]{aes_key} }

sub _set_aes_key {
   my ($self, $val)= @_;
   croak "Not a SecretBuffer"
      unless _isa_secret($val);
   $self->{aes_key}= $val;
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

sub cipher_data { $_[0]{cipher_data} }
sub has_ciphertext { defined $_[0]{cipher_data} && defined $_[0]{cipher_data}{ciphertext} }

=attribute content_type

Specify the MIME type of the L</content> attribute.  The special value
C<< application/crypt-multikey-coffer-kv >> enables the L</get> and L</set> methods to use the
C<content> as a key/value dictionary.

=attribute content

This attribute is an unencrypted L<Crypt::SecretBuffer> of the secret data of the Coffer.
If L</cipher_data> is defined and the coffer is unlocked, reading this attribute will
lazy-decrypt it.  If there is no L</cipher_data> (such as a new unsaved Coffer object) or the
coffer is still locked, reading this attribute just returns C<undef>.

Writing this attribute will invalidate the C<cipher_data> attribute, forcing it to be
re-encrypted when you call L</save>.  Beware that if you make changes to the SecretBuffer object
directly, the Coffer object will not be aware of those changes and the changes may be lost if
the Coffer doesn't know they need re-encrypted.  Use L</invalidate_ciphertext> if you make
changes directly.

If you are using the Coffer for name/value storage, use the L</get> and L</set> methods instead
of accessing this attribute.  In name/value mode, every access of this attribute will
re-serialize your data.

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

True if you have used accessors to alter your C<content> attribute.  If you modify the content
SecretBuffer yourself, you should set this attribute to true so that the Coffer knows it needs
to re-encrypt the content.

=cut

sub content_type { $_[0]{content_type}= $_[1] if @_ > 1; $_[0]{content_type} }

sub content {
   my $self= shift;
   $self->_set_content($_[0])
      if @_;
   $self->decrypt
      if !$self->_have_content && $self->_have_ciphertext && $self->unlocked;
   $self->_pack_content_kv
      if !defined $self->{content} && defined $self->{content_kv};
   $self->{content}
}

sub content_kv {
   my $self= shift;
   $self->_set_content_kv($_[0]) 
      if @_;
   $self->decrypt
      if !$self->_have_content && $self->_have_ciphertext && $self->unlocked;
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
      # Set default content type
      $self->{content_type} ||= 'application/binary';
   }
   # discard key/value map, if any
   delete $self->{content_kv};
   $self->content_changed(1);
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
}

=attribute locks

An arrayref of lock definitions, B<each> of which is sufficient to open the Coffer.
This breaks the intuitiveness of the Coffer metaphor a bit, but imagine a coffer with multiple
access hatches and a lock (which may require multiple keys) on each.  Locks are created with
L</add_access> method to emphasize that each one I<adds> access to the secret rather than
restricting it.

A lock always operates on public/private keys.  The private half must be present to open a lock,
but only the public half is needed to create the lock.  This means the coffer can be encrypted
with a new C<aes_key> even when the private half of the keys are not available.

Each lock is an encryption of the Coffer's C<aes_key> using a symmetric key derived from the
public half of the keys.  See L<Crypt::MultiKey::PKey/generate_key_material>.

  [
    { cipher        => 'AES-256-GCM',
      ciphertext    => $encrypted_bytes,
      kdf_salt      => $salt_bytes,
      tumblers      => [
        { key_fingerprint    => $hex_colon_notation,
          pubkey             => $pubkey_bytes,
          ephemeral_pubkey   => $pubkey_bytes,
          rsa_key_ciphertext => $encrypted_bytes,
        },
        ...
      ],
    },
    ...
  ]

=cut

sub locks {
   if (@_ > 1) {
      $_[0]->_validate_locks($_[1]);
      $_[0]{locks}= $_[1];
   }
   $_[0]{locks}
}

=constructor new

  $coffer= Crypt::MultiKey::Coffer->new(%attributes);

Construct a new Coffer.  The attributes are applied to the object as method calls.

=constructor load

  $coffer= Crypt::MultiKey::Coffer->load($filename);

Load a Coffer from a file.  This does not decrypt the data.  See L</unlock>.

=cut

sub new {
   my $class= shift;
   my %attrs= @_ == 1? %{$_[0]} : @_;
   my $self= bless { locks => [] }, $class;
   # If 'save' is requested, do that after everything else
   my $save= delete $attrs{save};
   # Hook for subclasses to process attributes
   $self->_init(\%attrs) if $self->can('_init');
   # Every remaining attribute must have a writable accessor
   $self->$_($attrs{$_}) for keys %attrs;
   # Now apply the 'save', if requested
   $self->save($save) if length $save;
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
   my $attrs= $class_or_self->_import_pem($pem);
   $attrs->{path}= $path;
   # If called as a class method, return a new object
   return $class_or_self->new($attrs) unless ref $class_or_self;
   # Replace contents of object otherwise
   %$class_or_self= %$attrs;
   return $class_or_self;
}

=method generate_aes_key

Generate a new AES key for the Coffer.  This gets called automatically when initially creating
a Coffer, but you can call it later to completely re-encrypt a Coffer, so long as

=over

=item *

any existing encrypted content has been decrypted into memory

=item *

all current L</access> items have the full public key available

=back

=cut

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

sub generate_aes_key {
   my $self= shift;
   my @old_locks= @{ $self->locks };
   croak "Generating a new Coffer aes_key required all existing locks to have public keys present";
      if @old_locks && !$self->_inflate_lock_keys;
   # Future compatibility; use same cipher as before.  Currently only AES-256-GCM is supported.
   my $cipher= $self->{cipher_data} && $self->{cipher_data}{cipher} || 'AES-256-GCM';
   my $size= $self->cipher eq 'AES-256-XTS'? 64
           : $self->cipher eq 'AES-256-GCM'? 32
           : croak "Unsupported cipher $cipher";
   my $new_aes_key= secret(append_random => $size);
   my @new_locks;
   # If any keyslots exist, need to create new tumblers
   if (@old_locks) {
      local $self->{aes_key}= $new_aes_key;
      local $self->{locks}= \@new_locks;
      for (@old_locks) {
         $self->add_access(map $_->{key}, @{ $_->{tumblers} });
      }
   }
   # everything looks good.  Throw away any old ciphertext, and use new values.
   delete $self->{cipher_data}{ciphertext} if $self->{cipher_data};
   $self->{aes_key}= $new_aes_key;
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
   unless (defined $self->aes_key) {
      croak "Coffer must be unlocked in order to ->add_access"
         if $self->has_ciphertext or @{ $self->locks };
      # No existing encrypted data, so create a new AES key
      $self->generate_aes_key;
   }
   my @tumblers= map +{ key => $_, key_fingerprint => $_->fingerprint }, @keys;
   my $key_material= secret;
   $_->{key}->generate_key_material($_, $key_material) for @tumblers;
   my %lock= ( tumblers => \@tumblers );
   my $aes_key= Crypt::MultiKey::hkdf(\%lock, $key_material);
   # Use the keyslot's aes key to encrypt the Coffer's aes key
   Crypt::MultiKey::aes_encrypt(\%lock, $aes_key, $self->aes_key);
   push @{$self->locks}, \%lock;
   return \%lock;
}

=method unlock

  $coffer->unlock($key1, ... $keyN);

This attempts to find a slot which can be unlocked by these keys, or a subset of them.
If found, the L</aes_key> attribute is set, after which decryption and encryption methods can
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
      my $aes_key= Crypt::MultiKey::hkdf($lock, $key_material);
      my $coffer_aes_key= Crypt::MultiKey::aes_decrypt($lock, $aes_key);
      $self->aes_key($coffer_aes_key);
      return $self;
   }
   croak "No lock can be opened using the supplied keys";
}

=method lock

Delete the L</aes_key> attribute and any attributes holding unencrypted secrets.

=cut

sub lock {
   my $self= shift;
   # Make sure there is a way to unlock it!
   croak "Can't lock Coffer when no locks are defined!  (you would lose your data)"
      unless @{ $self->locks };
   # No need to encrypt if the ciphertext exists and the content is not changed
   $self->encrypt if $self->content_changed || !$self->has_ciphertext;
   # Delete all secrets
   delete @{$self}{qw( content content_kv aes_key content_changed )};
   $self;
}

=method get

  $secret= $coffer->get($name);

When L<content_type> is C<< application/crypt-multikey-coffer-kv >>, this method can be used to
retrieve a secret by name.  If the content is not yet decrypted, it will try decrypting it and
fail if the L</aes_key> is not loaded.

=cut

sub get {
   my ($self, $key)= @_;
   $self->content_kv->{$key};
}

=method set

  $coffer->set($name, $secret);

When L<content_type> is C<< application/crypt-multikey-coffer-kv >>, this method can be used to
retrieve a secret by name.  Using this method when the content is not yet decrypted triggers it
to be decrypted and will fail if the L</aes_key> is not loaded.  Using this method when no
content or ciphertext are defined will initialize the content_type to
C<< application/crypt-multikey-coffer-kv >> and the content_kv attribute to a hashref.

If the C<$secret> is not defined, it deletes C<$name> from the hashref.  There is no way to store
a state of "exists but undefined".

=cut

sub set {
   my ($self, $key, $val)= @_;
   if (!$self->_needs_encrypted && !$self->_has_ciphertext && !defined $self->{content_type}) {
      $self->{content_type}= KV_CONTENT_TYPE;
      $self->{content_kv}= {};
   }
   if (defined $val) {
      $self->content_kv->{$key}= _coerce_secret($val);
   } else {
      delete $self->content_kv->{$key};
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
   # No need to encrypt if the ciphertext exists and the content is not changed
   $self->encrypt if $self->content_changed || !$self->has_ciphertext;
   # Build PEM object and serialize to file, renaming it into place
   $self->_export_pem->serialize->save_file($path, 'rename');
   $self;
}

sub encrypt {
   my $self= shift;
   # preconditions: the content must be defined
   croak "Content is not ".($self->has_ciphertext? 'decrypted' : 'defined')
      unless $self->has_content;
   # If possible, use a fresh AES key.
   # This requires that all locks have the public key present.
   $self->generate_aes_key if $self->_inflate_lock_keys;
   # Fill the encryption parameters
   my %cipher_data;
   my $secret= $self->content;
   Crypt::MultiKey::aes_encrypt(\%cipher_data, $self->aes_key, $secret);
   $self->{cipher_data}= \%cipher_data;
}

sub decrypt {
   ...
}

# Extract Coffer attributes from a Crypt::SecretBuffer::PEM object
sub _import_pem {
   my ($self, $pem)= @_;
   my %h= %{ $pem->headers };
   my %attrs;

   # Version check.  
   if (my $min_version= delete $h->{min_version}) {
      $min_version= version->parse($min_version);
      my $writer_version= version->parse(delete $h->{writer_version} || 0);
      carp "'$path' requires version $version of Crypt::MultiKey::Coffer"
         ." but this is only version ".__PACKAGE__->VERSION
         if $version > __PACKAGE__->VERSION;
   } else {
      carp "No module version found in PEM headers";
   }
   # Even if version problems, try to proceed

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
            $tmbl->{$_}= base64_decode($tmbl->{$_})
               if defined $tmbl->{$_};
         }
         push @{ $lock{tumblers} }, \%tumbler;
      }
      # base64 decode binary fields
      for (qw( kdf_salt ciphertext )) {
         $lock->{$_}= base64_decode($lock->{$_})
            if defined $lock->{$_};
      }
   }

   $attrs{cipher_data}{ciphertext}= $pem->content;
   # TODO: validate all attributes to make sure constructor doesn't call methods
   ...
   \%attrs;
}

sub _struct_to_kv {
   my $prefix= shift;
   return ( $prefix => $_[0] ) unless ref $_[0];
   my $node= shift;
   if (ref $_[0] eq 'ARRAY') {
      return map _struct_to_kv($prefix.'.'.$_ => $node->[$_]), 0 .. $#$node;
   }
   elsif (ref $_[0] eq 'HASH') {
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
   my $export_pubkey= 1;
   # Need to remove the key objects from the locks definition before serializing.
   # Also the user might choose to only export the fingerprint and not the pubkey.
   my @locks_export;
   for (@{ $self->locks }) {
      my %lock= %$_;
      for (@{ delete $lock{tumblers} }) {
         my %tumbler= %$_;
         delete $tumbler{key};
         delete $tumbler{pubkey} unless $export_pubkey;
         # base64 encode binary fields
         for (qw( pubkey ephemeral_pubkey rsa_key_ciphertext )) {
            $tumbler{$_}= base64_encode($tumbler{$_}, '')
               if defined $tumbler{$_};
         }
         push @{ $lock{tumblers} }, \%tumbler;
      }
      # base64 encode binary fields
      for (qw( kdf_salt ciphertext )) {
         $lock{$_}= base64_encode($lock{$_}, '')
            if defined $lock{$_};
      }
      push @locks_export, \%lock;
   }
   my %cipher_data_export= %{ $self->cipher_data };
   my $ciphertext= delete $cipher_data_export{ciphertext};
   return Crypt::SecretBuffer::PEM->new(
      label     => 'CRYPT SECRETBUFFER COFFER',
      header_kv => [
         version => '0.001',
         writer_version => __PACKAGE__->VERSION,
         _struct_to_kv(user_meta => $self->user_meta),
         _struct_to_kv(locks     => \@locks_export),
         content_type => $self->content_type,
         _struct_to_kv(cipher_data => \%cipher_data_export),
      ],
      content   => $ciphertext,
   );
}

sub _unpack_content_kv {
   my ($self, $span)= @_;
   # Break the content buffer into a list of length-delimited spans
   my ($len, @kv);
   while ($span->len) {
      croak "Incomplete string in coffer key/value list"
         unless $span->len >= 4;
      $span->subspan(0, 4)->copy_to($len);
      $len= unpack 'N', $len;
      croak "Incomplete string in coffer key/value list"
         unless $span->len >= 4 + $len;
      push @kv, $span->subspan(4, $len);
      $span->pos($span->pos + 4 + $len);
   }
   croak "Odd number of key/value elements in coffer" if @kv & 1;
   # Now copy out all the keys (non-secret) into perl scalars
   for (my $i= 0; $i < @kv; $i += 2) {
      my $k;
      $kv[$i]->copy_to($k);
      $kv[$i]= $k;
   }
   return { @kv };
}

sub _pack_content_kv {
   my ($self, $hash)= @_;
   my $buf= secret();
   my $size= 0;
   $size += 4 + (_is_secret($_) || _is_Secret_span($_)? $_->length : length $_)
      for %$hash;
   $buf->capacity($size, 'AT_LEAST');
   for (%$hash) {
      # In case SecretBuffer does something "interesting" during append (like flattening UTF-8,
      # or dereferencing some new kind of buffer object), append first and then patch up the
      # length after.
      my $before= $buf->length;
      $buf->append("1234")->append($_);
      my $len= $buf->length - 4 - $before;
      croak "Secret exceeds 2^31 length" if $len > 0x7FFFFFFF;
      $buf->substr($before, 4, pack('N', $len));
   }
   return $buf;
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

# Applies universally to scalars, secret buffers, or secret buffer spans
sub _decode_base64_nonsecret {
   _isa_secret($_[0])? $_[0]->span(encoding => BASE64)->copy_to($_[1], encoding => ISO8859_1)
   : _isa_secret_span($_[0])? $_[0]->clone(encoding => BASE64)->copy_to($_[1], encoding => ISO8859_1)
   : $_[1]= decode_base64($_[0]);
}
sub _encode_base64 {
   return _isa_secret($_[0])? $_[0]->span->copy(encoding => BASE64)
        : _isa_secret_span($_[0])? $_[0]->copy(encoding => BASE64)
        : MIME::Base64::encode_base64($_[0], '');
}


1;
