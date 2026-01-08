package Crypt::MultiKey::Coffer;
use strict;
use warnings;
use Carp;
use Scalar::Util qw( blessed );
use Crypt::SecretBuffer qw/ secret HEX BASE64 ISO8859_1 /;
use Crypt::SecretBuffer::PEM;
use Crypt::MultiKey;
use constant { KV_CONTENT_TYPE => 'application/crypt-multikey-coffer-kv' };

sub _isa_pem_obj { blessed($_[0]) && $_[0]->can('headers') && $_[0]->can('content') }
sub _isa_secret { blessed($_[0]) && $_[0]->can('unmask_to') }
sub _isa_secret_span { blessed($_[0]) && $_[0]->can('subspan') }
sub _coerce_secret {
   my $val= shift;
   return $val if _isa_secret($val) || _isa_secret_span($val);
   croak "Expected a Crypt::SecretBuffer, Crypt::SecretBuffer::Span, or something that can stringify to bytes"
      if ref $val && !blessed($val);
   return secret($val);
}

=head1 SYNOPSIS

  my $key1= Crypt::MultiKey::PKey->new();
  # initial state of coffer is unlocked, and unsaved
  my $coffer= Crypt::MultiKey::Coffer->new(path => './mydata.coffer');
  $coffer->create_keyslot($key1);   # now coffer can be unlocked by $key1
  $coffer->set($name, $secret);     # manage set of name/value pairs
  $coffer->save;                    # write encrypted data to file 'mydata.coffer'
  $coffer->lock;                    # now coffer cannot be read until opened
  $coffer->unlock($key);            # coffer open again (decrypted from file)
  $secret= $coffer->get($name);     # access secrets by name
  
  my $key2= Crypt::MultiKey::PKey->new();
  my $key3= Crypt::MultiKey::PKey->new();
  # There can be more than one keyslot, and Keyslots can require more than one key
  $coffer->create_keyslot($key2, $key3);
  $coffer->save;
  # Now, coffer can be unlocked with $key1, or with ($key2 + $key3)

=head1 DESCRIPTION

=head1 FILE FORMAT

A Coffer is encoded in PEM, with leading attributes that describe the contents of the coffer
and which keys can unlock it.

  -----BEGIN CRYPT MULTIKEY COFFER-----
  name: Name of This Coffer
  content_type: application/binary
  slot.0.key: KeyFingerprint OptionalKeyFilename
  slot.0....:
  slot.1.0.key: Key0Fingerprint OptionalKey0Filename
  slot.1.1.key: Key1Fingerprint OptionalKey1Filename
  
  Base64Base64Base64Base64.....==
  -----END CRYPT MULTIKEY COFFER-----

The payload is either binary data of your choice, or a key/value format written by this module
which is just a series of length-delimited strings where the length is a 32-bit big-endian
integer.  The payload is encrypted with AES and written as base64 as the body of the PEM file.

=attribute path

Filesystem path from which to load and save the Coffer.

=attribute name

Arbitrary user-assigned name for the Coffer.  Defaults to the basename of the L</path>.
The name may not contain control characters or start or end with whitespace.

=cut

sub path { $_[0]{path}= $_[1] if @_ > 1; $_[0]{path} }

sub name {
   my $self= shift;
   if (@_ > 1) {
      $self->{name}= $_[0];
      $self->{name} =~ s/^\s+//;
      $self->{name} =~ s/\s+\z//;
      $self->{name} =~ s/[\0-\x1F]+//g;
   }
   elsif (!defined $self->{name} && defined $self->{path}) {
      ($self->{name})= ($self->{path} =~ m{ ( [^\\/]+\z ) }x);
   }
   $self->{name}
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
        : encode_base64($_[0], '');
}

=attribute aes_key

A L<Crypt::SecretBuffer> holding the AES key used to encrypt/decrypt the content.
A Coffer is logically "unlocked" when the C<aes_key> is defined, and "locked" when it isn't.

=attribute cipher

Either C<AES-256-GCM> or C<AES-256-XTS>.  XTS allows random block access for large secrets.

=cut

sub aes_key {
   if (@_ > 1) {
      croak "Not a SecretBuffer" unless _isa_secret($_[1]);
      $_[0]{aes_key}= $_[1]
   }
   $_[0]{aes_key}
}

our %supported_ciphers= ( 'AES-256-GCM' => 1, 'AES-256-XTS' => 1 );
sub cipher {
   if (@_ > 1) {
      croak "Unsupported cipher $_[1]"
         unless $supported_ciphers{$_[1]};
      $_[0]{cipher}= $_[1];
   }
   $_[0]{cipher}
}

=method generate_aes_key

Generate a new AES key for the Coffer.  This gets called automatically when initially creating
a Coffer, but you can call it later to completely re-encrypt a Coffer, so long as

=over

=item *

Any existing encrypted content has been decrypted into memory

=item *

All current C<keyslot>s have the full public key available

=back

=cut

sub generate_aes_key {
   my $self= shift;
   croak "Can't generate new AES key when content is still encrypted"
      unless $self->_content_fully_decrypted;
   my @old_keyslots= @{ $self->keyslots };
   for (@old_keyslots) {
      for (@{ $_->{tumblers} }) {
         # The public keys must be present, in order to regenerate the tumblers
         defined $_->{key} or defined $_->{pubkey}
            or croak "Generating a new Coffer aes_key required all existing keyslots to have public keys present";
         $_->{key} ||= Crypt::MultiKey::PKey->new(public => $_->{pubkey});
      }
   }
   my $size= $self->cipher eq 'AES-256-XTS'? 64
           : $self->cipher eq 'AES-256-GCM'? 32
           : croak "Unsupported cipher ".$self->cipher;
   my $new_aes_key= secret(append_random => $size);
   my @new_keyslots;
   # If any keyslots exist, need to create new tumblers
   if (@old_keyslots) {
      local $self->{aes_key}= $new_aes_key;
      local $self->{keyslots}= \@new_keyslots;
      for (@old_keyslots) {
         $self->add_keyslot(map $_->{key}, @{ $_->{tumblers} });
      }
   }
   # everything looks good.  Throw away any old ciphertext, and use new values.
   delete $self->{cipher_data};
   $self->{aes_key}= $new_aes_key;
   @{$self->{keyslots}}= @new_keyslots;
   $self;
}

=attribute cipher_data

This attribute holds various parameters representing the encrypted secret.
If the C<content> attribute is modified, this is set to C<undef> to indicate that it needs
re-encrypted.  Likewise, setting this attribute clears the C<content> attribute.
The possible keys are:

=over

=item ciphertext

The raw bytes of ciphertext loaded into a scalar.  Might not be used for large secrets.

=item ciphertext_fh

A file handle from which ciphertext can be read.  Might not be used if C<ciphertext> is populated.

=item ciphertext_file_offset

A file offset within C<handle> where the ciphertext begins.  If used, must be a multiple of 4K.
This is I<not> used when the ciphertext comes from the PEM base64 string.

=item aes_gcm_nonce

Random salt regenerated each time C<encrypt> is called.

=item aes_gcm_tag

Used by GCM decryption to validate the aes_key.  C<XTS> lacks this sort of validation.

=item aes_xts_block_size

The block size used by AES-XTS cipher, which performs block-based encryption.

=back

=cut

sub cipher_data {
   if (@_ > 1) {
      $_[0]{cipher_data}= $_[1];
      delete $_[0]{content};
   }
   $_[0]{cipher_data}
}

=attribute content_type

Specify the MIME type of the L</content> attribute.  The special value
C<< application/crypt-multikey-coffer-kv >> is used when the L</content> attribute holds a
hashref, and lets you use the Coffer as key/value storage.

=attribute content

This attribute is an unencrypted L<Crypt::SecretBuffer> of the secret data of the Coffer.
It can be initialized / assigned directly, or lazy-decrypted from L<cipher_data>.
If you trigger a lazy-build and the L</aes_key> is not available (such as by L</unlock>) it will
throw an exception.

If you are using the key/value C<content_type>, use the L</get> and L</set> methods instead of
accessing this attribute.

=over

=item has_content

True if the content attribute is set (lazy-built or assigned directly)

=back

=cut

sub content_type { $_[0]{content_type}= $_[1] if @_ > 1; $_[0]{content_type} }

sub has_content { defined $_[0]{content} }

sub content {
   my $self= shift;
   if (@_) {
      my $val= $_[0];
      if (!defined $val) {
         delete $self->{content};
      } else {
         $self->{content}= _coerce_secret($val);
         # Set default content type
         $self->{content_type}= 'application/binary'
            if !$self->{content_type} || $self->{content_type} eq KV_CONTENT_TYPE;
      }
   } elsif (!defined $self->{content}) {
      $self->{content}= $self->_build_content
         if $self->cipher_data;
   }
   $self->{content}
}

sub _build_content {
   my $self= shift;
   croak "Attribute '->cipher_data->{ciphertext}' is not defined"
      unless defined $self->cipher_data->{ciphertext};
   croak "Coffer must be unlocked in order to decrypt ciphertext"
      unless defined $self->aes_key;
   Crypt::MultiKey::aes_decrypt($self->cipher_data, $self->aes_key);
}

=attribute content_kv

This attribute is used when the content type is C<< application/crypt-multikey-coffer-kv >>.
and allows you to work with a hash of name/value pairs (where each value is a SecretBuffer
or SecretBuffer Span.

=over

=item has_content_kv

True if the content_kv attribute is set (lazy-built or assigned directly)

=back

=cut

sub has_content_kv { defined $_[0]{content_kv} }

sub content_kv {
   my $self= shift;
   if (@_) {
      my $val= $_[0];
      if (!defined $val) {
         delete $self->{content_kv};
      }
      else {
         croak "Expected hashref"
            unless ref $val eq 'HASH';
         $val= { %$val }; # clone before converting values
         # Ensure that all values are SecretBuffer or SecretBuuffer::Span
         $_= _coerce_secret($_)
            for values %$val;
      }
   } elsif (!defined $self->{content_kv}) {
      $self->{content_kv}= $self->_build_content_kv
         if $self->cipher_data;
   }
   $self->{content_kv}
}

sub _build_content_kv {
   my $self= shift;
   croak "Attribute '->cipher_data->{ciphertext}' is not defined"
      unless defined $self->cipher_data->{ciphertext};
   croak "Coffer must be unlocked in order to decrypt ciphertext"
      unless defined $self->aes_key;
   my $content= Crypt::MultiKey::aes_decrypt($self->cipher_data, $self->aes_key);
   $self->_unpack_content_kv($content->span);
}

=attribute keyslots

An arrayref of "key slots", each of which is sufficient to unlock the Coffer if you have the
matching private keys.  Each key slot (created using L</create_keyslot>) requires one or more
private keys to compute an AES key that becomes the L</aes_key> attribute.

  [
    { cipher        => 'AES-256-GCM',
      aes_gcm_nonce => $bytes,
      aes_gcm_tag   => $bytes,
      ciphertext    => $bytes,
      tumblers      => [
        { key_fingerprint    => $fingerprint, # used to locate matching key
          ephemeral_pubkey   => $bytes,
          rsa_key_ciphertext => $bytes,
        },
        ...
      ],
    },
    ...
  ]

=cut

sub keyslots {
   if (@_ > 1) {
      $_[0]->_validate_keyslots($_[1]);
      $_[0]{keyslots}= $_[1];
   }
   $_[0]{keyslots}
}

=method get

  $secret= $coffer->get($name);

When L<content_type> is C<< application/crypt-multikey-coffer-kv >>, this method can be used to
retrieve a secret by name.  If the content is not yet decrypted, it will call L</decrypt> and
fail if the L</aes_key> is not loaded.

=cut

sub get {
   my ($self, $key)= @_;
   unless (ref $self->content eq 'HASH') {
      if (!defined $self->content) {
         croak "content is not initialized"
            unless defined $self->ciphertext;
         $self->decrypt; # throws its own exceptions if things are wrong
      }
      croak "content_type is not ".KV_CONTENT_TYPE
         unless $self->content_type eq KV_CONTENT_TYPE;
      croak "content is not a hashref"
         unless ref $self->content eq 'HASH';
   }
   $self->content->{$key};
}

=method set

  $coffer->set($name, $secret);

When L<content_type> is C<< application/crypt-multikey-coffer-kv >>, this method can be used to
retrieve a secret by name.  Using this method when the content is not yet decrypted triggers a
call L</decrypt> and will fail if the L</aes_key> is not loaded.  Using this method when neither
C<content> nor C<content_encrypted> are defined will initialize the content to a hashref and the
content_type to C<< application/crypt-multikey-coffer-kv >>.

If the C<$secret> is not defined, it deletes C<$name> from the hashref.  There is no way to store
a state of "exists but undefined".

=cut

sub set {
   my ($self, $key, $val)= @_;
   unless (ref $self->content eq 'HASH') {
      if (!defined $self->content) {
         if (defined $self->content_encrypted) {
            $self->decrypt; # throws its own exceptions if things are wrong
         } else {
            # auto-vivify it to a hashref and corresponding content type
            $self->content({});
         }
      }
      croak "content_type is not ".KV_CONTENT_TYPE
         unless $self->content_type eq KV_CONTENT_TYPE;
      croak "content is not a hashref"
         unless ref $self->content eq 'HASH';
   }
   if (!defined $val) {
      delete $self->content->{$key};
   } else {
      $self->content->{$key}= _is_secret($val)? $val : secret($val);
   }
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
   my $self= bless {}, $class;
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
   # Expect the entire PEM block to be in the first 400K of the file.
   # Large files can have raw encrypted bytes following the PEM block.
   # ...but also, nothing stops the PEM from being multiple MB,
   #  so load the rest of the file if the end of the PEM block isn't seen.
   open my $fh, '<', $path or croak "open($path): $!";
   my $file_buf= secret;
   $file_buf->append_sysread($fh, 409600)
      or die "sysread($path): $!";
   my $start= $file_buf->index('-----BEGIN CRYPT MULTIKEY COFFER-----');
   croak "File lacks 'BEGIN CRYPT MULTIKEY COFFER'"
      unless $start >= 0;
   if ($file_buf->index("\n-----END CRYPT MULTIKEY COFFER-----") < 0) {
      # load the whole rest of the file on the assumption that PEM goes to the end
      my $blocksize= ( -s $fh ) - $file_buf->length;
      while (1) {
         my $got= $file_buf->append_sysread($fh, $blocksize);
         defined $got or croak "sysread($path): $!";
         last if $got == 0;
         # should have read the whole thing first try, but file could be changing
         # (a pipe or something), so keep going at 16K intervals until EOF.
         $blocksize= 16*1024 if $blocksize > 16*1024;
      }
      $file_buf->index("\n-----END CRYPT MULTIKEY COFFER-----") >= 0
         or croak "File lacks 'END CRYPT MULTIKEY COFFER'";
   }
   my $pem= Crypt::SecretBuffer::PEM->parse($file_buf->span($start))
      or croak "Unable to parse PEM from $path";

   my $h= $pem->headers;
   my %attrs= ( path => $path );
   my @attributes= qw( name content_type cipher );
   my @cipher_data_attributes= qw( aes_xts_block_size ciphertext_file_offset );
   my @cipher_data_base64_attributes= qw( aes_gcm_nonce aes_gcm_tag kdf_salt );
   for (@attributes) {
      $h->{$_}->copy_to($attrs{$_})
         if defined $h->{$_};
   }
   for (@cipher_data_attributes) {
      $h->{$_}->copy_to($attrs{cipher_data}{$_})
         if defined $h->{$_};
   }
   for (@cipher_data_base64_attributes) {
      _decode_base64_nonsecret($h->{$_} => $attrs{cipher_data}{$_})
         if defined $h->{$_};
   }
   $attrs{keyslots}= $class_or_self->_pem_headers_to_keyslots($h);

   # If the file is a PEM block followed by raw encrypted bytes, store the file
   # handle for later random access.
   if (my $ofs= $h->{ciphertext_file_offset}) {
      $attrs{handle}= $fh;
      $ofs->copy_to($attrs{cipher_data}{ciphertext_file_offset});
   } else {
      _decode_base64_nonsecret($pem->content => $attrs{cipher_data}{ciphertext});
   }
   
   # If called as a class method, return a new object
   return $class_or_self->new(\%attrs) unless ref $class_or_self;
   # Replace contents of object otherwise
   %$class_or_self= %attrs;
   return $class_or_self;
}

=method create_keyslot

  $coffer->create_keyslot($key1, ... $keyN);

This creates a new "slot" on the Coffer which can open the coffer when all of these keys
(with private half loaded) are passed to the L</unlock> method.  The keys can be passed
to L</unlock> in any order, so long as all of them are present.

=cut

sub create_keyslot {
   my ($self, @keys)= @_;
   @keys= @{$keys[0]} if @keys == 1 && ref $keys[0] eq 'ARRAY';
   unless (defined $self->aes_key) {
      croak "Coffer must be unlocked in order to ->create_keyslot"
         if $self->_has_ciphertext or @{ $self->keyslots };
      # No existing encrypted data, so create a new AES key
      $self->generate_aes_key;
   }
   my @tumblers= map +{ key => $_, key_fingerprint => $_->fingerprint }, @keys;
   my $key_material= secret;
   $_->{key}->generate_key_material($_, $key_material) for @tumblers;
   my %slot= ( tumblers => \@tumblers );
   my $aes_key= Crypt::MultiKey::hkdf(\%slot, $key_material);
   # Use the keyslot's aes key to encrypt the Coffer's aes key
   Crypt::MultiKey::aes_encrypt(\%slot, $aes_key, $self->aes_key);
   push @{$self->keyslots}, \%slot;
   return \%slot;
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
   my %by_fp;
   for my $pkey (@keys) {
      croak "Expected PKey object"
         unless blessed($pkey) && $pkey->can('has_private');
      croak "key ".$pkey->fingerprint." does not have the private half loaded"
         unless $pkey->has_private;
      $by_fp{$pkey->fingerprint}= $pkey;
   }
   # Look for a slot having these exact keys
   for my $slot (@{ $self->keyslots }) {
      my $tumblers= $slot->{tumblers};
      my @keys_in_order= map $by_fp{$_->{key_fingerprint}}, @$tumblers;
      next if grep !defined, @keys_in_order;
      # All keys are present.  Reconstruct the shared secret key material from
      # the private key and the tumbler of each key in order.
      my $key_material= secret();
      $keys_in_order[$_]->recreate_key_material($tumblers->[$_], $key_material)
         for 0..$#keys_in_order;
      my $aes_key= Crypt::MultiKey::hkdf($slot, $key_material);
      my $coffer_aes_key= Crypt::MultiKey::aes_decrypt($slot, $aes_key);
      $self->aes_key($coffer_aes_key);
      return $self;
   }
   croak "No slot matches supplied keys";
}

=method lock

Delete the L</aes_key> attribute and any attributes holding unencrypted secrets.

=cut

sub lock {
   my $self= shift;
   croak "Can't close coffer until it has been saved"
      unless defined $self->ciphertext;
   delete @{$self}{qw( content content_kv aes_key )};
}

=method save

  $coffer->save;         # saves to ->path
  $coffer->save($path);  # save to specific path, and initialize path attribute

Encrypt the content and write it to disk.  If you specify the C<$path> and the path attribute is
not already set, this initializes it.  This writes a new file and then renames it into place to
ensure it doesn't corrupt the existing file.

=cut

sub save {
   my ($self, $path)= @_;
   my $has_ciphertext= $self->_has_ciphertext;
   my $needs_encrypted= $self->_needs_encrypted;
   # If the aes_key is not loaded, this either means it was never unlocked, or that a fresh
   # coffer has never been encrypted and also not had ->create_keyslot called yet.
   croak "Can't save a Coffer without keyslots"
      unless @{$self->{keyslots}};
   croak "Can't save changes to a locked Coffer"
      if $needs_encrypted && !defined $self->{aes_key};
   # Caller can re-save a locked Coffer if they only made metadata changes, like changing the
   # 'name' field.  We can also re-use the encryption if they unlocked it and only added a
   # keyslot without any action that would change the content.
   croak "Can't save; no content defined"
      unless $has_ciphertext || $needs_encrypted;
   my $cipher_data;
   if ($needs_encrypted) {
      my $secret;
      # It can be a plain SecretBuffer that needs encrypted, or a hash of name/value that needs
      # packed and then encrypted
      if ($self->content_type eq KV_CONTENT_TYPE) {
         ref $self->{content_kv} eq 'HASH'
            or croak "BUG: expected hashref at ->{content_kv}";
         $secret= $self->_pack_content_kv($self->{content_kv});
      }
      else {
         $secret= $self->{content};
      }
      $cipher_data= { cipher => $self->cipher || 'AES-256-GCM' };
      Crypt::MultiKey::aes_encrypt($cipher_data, $self->aes_key, $secret);
      $self->{cipher_data}= $cipher_data;
      # Delete user-writable attributes to indicate that the encrypted content is the official
      # copy.  The user can still access them to lazy-decrypt.
      delete $self->{content};
      delete $self->{content_kv};
   } else {
      $cipher_data= { %{$self->{cipher_data}} };
   }
   # For XTS, the ciphertext needs appended after the end of the PEM and aligned to a block size.
   # For GCM, the ciphertext becomes the content of the PEM block.
   my $ciphertext= delete $cipher_data->{ciphertext};
   my @pem_header_kv= (
      name         => $self->name,
      content_type => $self->content_type,
      %$cipher_data,
      @{ $self->_keyslots_to_pem_headers($self->keyslots) }
   );
   if ($cipher_data->{cipher} =~ /-GCM\z/) {
      my $pem= Crypt::SecretBuffer::PEM->new(
         label     => 'CRYPT SECRETBUFFER COFFER',
         header_kv => \@pem_header_kv,
         content   => $ciphertext
      );
      # Save to a temp file and rename into place
      $pem->serialize->save_file($path, 'rename');
   } elsif ($cipher_data->{cipher} =~ /-XTS\z/) {
      my $pem= Crypt::SecretBuffer::PEM->new(
         label     => 'CRYPT SECRETBUFFER COFFER',
         header_kv => [
            @pem_header_kv,
            ciphertext_file_offset => '00000',
         ],
         content   => "\0", # not used, but must be present for PEM format
      );
      my $header= $pem->serialize;
      # round up to a multiple of page size or block_size
      my $align= $cipher_data->{aes_xts_block_size};
      $align= 4096 if $align < 4096;
      # round up the size of the header to include at least 200 "\n" characters
      my $offset= ($header->length + 200 + $align - 1) & ~$align;
      $pem->header_kv->[-1]= $offset;
      $header= $pem->serialize;
      $header->append("\n" x ($offset - $header->length));
      # Append ciphertext to this header, and save it.
      # (could be more efficient to open the file and write both parts to it, but that's a lot
      #  more code to write)
      # Handle edge case if ciphertext happens to be a span that was previously base64-encoded
      _is_secret_span($ciphertext)? $ciphertext->copy_to($header, encoding => ISO8859_1)
         : $header->append($ciphertext);
      $header->save_file($path, 'rename');
   }
   $self;
}

sub _has_ciphertext {
   my $self= shift;
   $self->{cipher_data} && (
         # AES-GCM holds ciphertext in {cipher_data}{ciphertext}.
         ($self->{cipher} =~ /-GCM\z/ && $self->{cipher_data}{ciphertext})
         # AES-XTS could also be loaded on demand from the file
      || ($self->{cipher} =~ /-XTS\z/ && $self->{cipher_data}{ciphertext_file_offset}
          && -s $self->{path} > $self->{cipher_data}{ciphertext_file_offset})
   );
}

# Return true if all content is currently in memory in a non-encrypted state.
# i.e. the ciphertext could be thrown away and replaced with a fresh encryption.
sub _content_fully_decrypted {
   my $self= shift;
   defined $self->{content} || defined $self->{content_kv};
}

# Any content decrypted to a SecretBuffer may have been modified by the user, and will need
# re-encrypted regardless of whether the {cipher_data} attribute is populated.
sub _needs_encrypted {
   my $self= shift;
   defined $self->{content} || defined $self->{content_kv};
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

our %_known_keyslot_keys= map +($_ => 1),
   qw( cipher | aes_gcm_nonce | aes_gcm_tag | ciphertext | tumblers );
our %_known_tumbler_keys= map +($_ => 1),
   qw( key key_fingerprint key_name );
sub _validate_keyslots {
   my ($self, $slots)= @_;
   croak "keyslots must be an arrayref"
      unless ref $slots eq 'ARRAY';
   my @unknown;
   for my $slot_i (0..$#$slots) {
      my $slot= $slots->[$slot_i];
      for (qw( cipher aes_gcm_nonce aes_gcm_tag ciphertext )) {
         croak "Missing '$_' in slot $slot_i"
            unless defined $slot->{$_};
      }
      croak "slot[$slot_i]{tumblers} must be an arrayref"
         unless ref $slot->{tumblers} eq 'ARRAY';
      for my $tmbl_i (0..$#{$slot->{tumblers}}) {
         my $tmbl= $slot->{tumblers}[$tmbl_i];
         # Need to be able to identify the key
         croak "No key details for tumbler $tmbl_i"
            unless defined $tmbl->{key} || defined $tmbl->{key_fingerprint} || defined $tmbl->{key_name};
         # Need either ephemeral_pubkey and kdf_salt, or rsa_key_ciphertext
         croak "tumbler $tmbl_i must have (rsa_key_ciphertext) or (ephemeral_pubkey, kdf_salt)"
            unless defined $tmbl->{rsa_key_ciphertext}
               xor (defined $tmbl->{ephemeral_pubkey} && defined $tmbl->{kdf_salt});
         @unknown= grep !$_known_tumbler_keys{$_}, keys %$tmbl;
         carp "Unknown tumbler[$tmbl_i] attributes: ".join(', ', @unknown)
            if @unknown;
      }
      @unknown= grep !$_known_keyslot_keys{$_}, keys %$slot;
      carp "Unknown keyslot[$slot_i] attributes: ".join(', ', @unknown)
         if @unknown;
   }
}

sub _keyslots_to_pem_headers {
   my ($self, $slots, %opts)= @_;
   my @header_kv;
   for my $slot_i (0..$#$slots) {
      my $slot= $slots->[$slot_i];
      for my $tmbl_i (0..$#{$slot->{tumblers}}) {
         my $tmbl= $slot->{tumblers}[$tmbl_i];
         push @header_kv, "slot$slot_i.tumbler$tmbl_i.key_name",
                          $tmbl->{key}->name
            if $opts{export_key_names};
         push @header_kv, "slot$slot_i.tumbler$tmbl_i.key_fingerprint",
                          $tmbl->{key}->fingerprint;
         push @header_kv, "slot$slot_i.tumbler$tmbl_i.key",
                          $tmbl->{key}->public
            if $opts{export_public_keys};
         for (qw( ephemeral_pubkey rsa_key_ciphertext )) {
            push @header_kv,
               "slot$slot_i.tumbler$tmbl_i.$_",
               encode_base64($tmbl->{$_}, '')
               if defined $tmbl->{$_};
         }
      }
      push @header_kv, "slot$slot_i.cipher" => $slot->{cipher};
      for (qw( kdf_salt aes_gcm_nonce aes_gcm_tag ciphertext )) {
         push @header_kv, "slot$slot_i.$_", encode_base64($slot->{$_}, '')
            if defined $slot->{$_};
      }
   }
   return \@header_kv;
}

sub _pem_headers_to_keyslots {
   my ($self, $headers)= @_;
   my %slots;
   for (keys %$headers) {
      if (my ($slot_id, $tumbler_id, $subkey)= /^slot(\d+)\.(?:tumbler(\d+)\.)?(.*)/) {
         my $dst= $slots{$slot_id} ||= {};
         $dst= $dst->{tumblers}{$tumbler_id} ||= {} if defined $tumbler_id;
         _decode_base64_nonsecret($headers->{$_} => $dst->{$subkey});
      } else {
         carp "Unknown PEM attribute '$_'";
      }
   }
   # collapse each tumbler hashref to an arrayref
   for (values %slots) {
      $_->{tumblers}= [ @{$_->{tumblers}}{ sort { $a <=> $b } keys %{$_->{tumblers}} } ]
         if defined $_->{tumblers};
   }
   # collapse the slots to an array
   return [ @slots{ sort { $a <=> $b } keys %slots } ];
}

1;
