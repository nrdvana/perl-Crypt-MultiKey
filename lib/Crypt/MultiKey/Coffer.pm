package Crypt::MultiKey::Coffer;
use strict;
use warnings;
use Carp;
use Crypt::SecretBuffer qw/ secret HEX BASE64 ISO8859_1 /;
use Crypt::SecretBuffer::PEM;
use Crypt::MultiKey;

sub _isa_pem_obj { blessed($_[0]) && $_[0]->can('headers') && $_[0]->can('content') }
sub _isa_secret { blessed($_[0]) && $_[0]->can('unmask_to') }
sub _isa_secret_span { blessed($_[0]) && $_[0]->can('subspan') }

=head1 SYNOPSIS

  my $key1= Crypt::MultiKey::PKey->new();
  # initial state of coffer is unlocked, and unsaved
  my $coffer= Crypt::MultiKey::Coffer->new(path => './mydata.coffer');
  $coffer->create_keyslot($key1);   # now coffer can be unlocked by $key1
  $coffer->set($name, $secret);     # manage set of name/value pairs
  $coffer->save;                    # write encrypted data to file 'mydata.coffer'
  $coffer->close;                   # now coffer cannot be read until opened
  $coffer->open($key);              # coffer open again (decrypted from file)
  $secret= $coffer->get($name);     # access secrets by name
  
  my $key2= Crypt::MultiKey::PKey->new();
  my $key3= Crypt::MultiKey::PKey->new();
  # There can be more than one keyslot, and Keyslots can require more than one key
  $coffer->create_keyslot($key2, $key3);
  $coffer->save;
  # Now, coffer can be opened with $key1, or with ($key2 + $key3)

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

=cut

sub name { $_[0]{name} }
sub content_type { $_[0]{content_type} }
sub content_encrypted { $_[0]{content_encrypted} }
sub content { $_[0]{content} }
sub content_kv { $_[0]{content_kv} ||= $_[0]->_build_content_kv }
sub keyslots { $_[0]{keyslots} }

# Applies universally to scalars, secret buffers, or secret buffer spans
sub _decode_base64_nonsecret {
   my $span= _isa_secret($_[0])? $_[0]->span
           : _isa_secret_span($_[0])? $_[0]
           : undef;
   return decode_base64($_[0]) unless defined $span;
   my $v;
   $span->copy_to($v, encoding => BASE64);
   return $v;
}

# If the content-type is 'cmk-coffer-kv' then we can decode it into a hashref.
# Also if it is not set yet, we can initialize it to be cmk-coffer-kv.
sub _build_content_kv {
   my $self= shift;
   croak "Coffer is locked"
      if $self->content_encrypted && !$self->content;
   $self->{content_type} ||= 'application/cmk-coffer-kv';
   croak "Coffer does not contain key/value data"
      unless $self->content_type eq 'application/cmk-coffer-kv';
   # Break the content buffer into a list of spans
   my ($len, @kv);
   my $span= $self->content->span;
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
         push @header_kv, "slot$slot_i.tumbler$tmbl_i.key_SubjectPublicKeyInfo",
                          $tmbl->{key}->public
            if $opts{export_public_keys};
         for (qw( ephemeral_pubkey kdf_salt rsa_key_ciphertext )) {
            push @header_kv,
               "slot$slot_i.tumbler$tmbl_i.$_",
               encode_base64($tmbl->{$_}, '')
               if defined $tmbl->{$_};
         }
      }
      for (qw( cipher aes_gcm_nonce aes_gcm_tag ciphertext )) {
         push @header_kv, "slot$slot_i.$_", encode_base64($slot->{$_}, '');
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
         $dst->{$subkey}= _decode_base64_nonsecret($headers->{$_});
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

=constructor new

  $coffer= Crypt::MultiKey::Coffer->new($filename);
  $coffer= Crypt::MultiKey::Coffer->new(%attributes);

=cut

sub new {
   my $class= shift;
   my %attrs= @_ != 1      ? @_
      : _isa_pem_obj($_[0])? ( pem => $_[0] )
      # Else assume its a filename or object that stringifies to a filename
      :                      ( path => $_[0] );

   if ($attrs{path} && !$attrs{pem}) {
      my $pem= Crypt::SecretBuffer::PEM->parse(secret(load_file => $attrs{path}))
         or croak "Unable to parse PEM from $attrs{path}";
      $attrs{pem}= $pem;
   }
   if ($attrs{pem}) {
      my $h= $pem->headers;
      $h->{name}->copy_to($attrs{name})
         if defined $h->{name};
      $h->{content_type}->copy_to($attrs{content_type})
         if defined $h->{content_type}
      $h->{content_encrypted}->copy_to($attrs{content_encrypted}, encoding => ISO8859_1)
         if defined $h->{content_encrypted};
      $attrs{keyslots}= $class->_pem_headers_to_keyslots($h);
   } else {
      $attrs{keyslots} ||= [];
   }
   # Validate attributes
   _validate_keyslots($attrs{keyslots});
   my $self= bless {}, $class;
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

sub create_keyslot {
   my ($self, @keys)= @_;
   croak "Coffer must be unlocked in order to ->create_keyslot"
      unless defined $self->aes_key;
   ...
}

sub open {
   my ($self, @keys)= @_;
   ...
}

sub save {
   my ($self, $path)= @_;
   unless ($self->content_encrypted) {
      croak "Can't save without defined 'content'"
         unless defined $self->content;
      croak "Can't save without defined keyslots"
         unless @{$self->keyslots};
      croak "Can't encrypt new content without attribute 'aes_key'"
         unless defined $self->aes_key;
      # encrypt content with aes_key
      ...
   }
   $path= $self->path unless defined $path;
   my $pem= Crypt::SecretBuffer::PEM->new(
      label => 'CRYPT SECRETBUFFER COFFER',
      header_kv => $self->_keyslots_to_pem_headers($self->keyslots),
   );
   $pem->serialize->save_file($path, 'rename');
}

sub close {
   my $self= shift;
   croak "can't close coffer until it has been saved"
      unless defined $self->content_encrypted;
   delete $self->content;
   delete $self->aes_key;
}

1;
