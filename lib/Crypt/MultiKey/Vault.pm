package Crypt::MultiKey::Vault;
our $VERSION= '0.001'; # VERSION
# ABSTRACT: Encrypted block storage that can be unlocked with various combinations of keys

=head1 DESCRIPTION

This is like Coffer, but instead of managing a single secret in memory, it reads and writes
blocks of the source file.  The initial few blocks of the file are plain text and store the
details of the key-wrapping implementation, followed by blocks of binary data.  The block
encryption algorithm is compatible with Linux crypt-dm, allowing the kernel to directly operate
on the Vault file.

=head1 FILE FORMAT

A Vault is defined in terms of a C<sector_size>.  The header occupies an integer number of blocks
such that the data starts on a 4KiB boundary.  The header is a variable-length PEM text followed
by "\n" characters and one NUL byte that pad it to the beginning of the data.  You may actually
put your own Unix "#!" interpreter directive at the start of the file if you wish, so long as
the PEM text begins within the first 4KiB of the file.

The purpose of this format is so you can see what is inside it using a text editor, easily parse
it if you need to, and have all the binary data pushed off the bottom of the screen by the run
of "\n" characters to reduce the chance that you corrupt your terminal.  The run of "\n"
characters also provide padding so that the header can usually be rewritten without needing to
replace the entire file.

  \0
  -----BEGIN CRYPT MULTIKEY VAULT-----
  version: 0.001
  writer_version: 0.001
  cipher: AES-256-XTS
  sector_size: 4096
  data_start_block: 2
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
  header_authentication: HMAC-SHA256:base64==
  
  -----END CRYPT MULTIKEY VAULT-----
  \n
  \n
  \n
  ....
  \n\0
  [binary data begins at a 4K and sector_size boundary]

=cut

use v5.10;
use warnings;
use version;
use Carp;
use Fcntl ();
use MIME::Base64 qw/ encode_base64 decode_base64 /;
use File::Basename qw/ basename /;
use Crypt::MultiKey;
use Crypt::MultiKey::LockMechanism;
use Scalar::Util qw/ blessed looks_like_number /;
use Crypt::SecretBuffer qw/ secret span HEX BASE64 ISO8859_1 /;
use Crypt::SecretBuffer::PEM 0.020;
use constant {
   STAGING_BUFFER_SIZE => 0x100000,
   STAGING_BUFFER_MASK => 0x0FFFFF,
   STAGING_BUFFER_SHIFT => 20,
   DEFAULT_SECTOR_SIZE => 512,
   DEFAULT_DATA_OFFSET => 65536,
};

=attribute path

The path to the Vault file.  This can only be changed by a call to L</save>.

=attribute handle

An open seekable file handle to the Vault's file.  This will be C<undef> if and only if the Vault
has not yet been saved.

=attribute cipher

Currently only C<AES-256-XTS> is supported.
This can be changed during L</save> if you are saving to a new file.

=attribute sector_size

The block size used for encrypting the file.  It must be a power of 2, ideally between 512 and
4096 (for compatibility with Linux dm-crypt).
This can be changed during L</save> if you are saving to a new file.

=attribute data_offset

The byte offset at which data blocks begin.  This must be a multiple of the block size, and by
default will not be smaller than 64KiB to leave room for the header to grow without needing to
rewrite the file.
This can be changed during L</save> if you are saving to a new file.

=attribute data_size

The length in bytes of the data area.  e.g. file size minus L<data_offset>.
This can be changed at any time via L</resize>.  The attribute is read-only for safety.

=attribute lock_mechanism

A reference to L<Crypt::SecretBuffer::LockMechanism>.  This may be a pluggable object in the
future, but is currently tied to the default implementation.

=cut

sub path   { $_[0]{path} }
sub _set_path { $_[0]{path}= $_[1]; $_[0] }
sub handle { $_[0]{handle} }
sub _set_handle { $_[0]{handle}= $_[1]; $_[0] }
sub cipher { $_[0]{cipher} }
sub _set_cipher { $_[0]{cipher}= $_[1]; $_[0] }
sub sector_size { $_[0]{sector_size} }
sub _set_sector_size {
   my ($self, $val)= @_;
   $val += 0;
   croak "sector_size must be an integer >= 512"
      if $val < 512 || int($val) != $val;
   croak "sector_size must be a power of 2"
      if $val & ($val-1);
   $self->{sector_size}= $val;
   $self;
}
sub data_offset { $_[0]{data_offset} }
sub _set_data_offset {
   my ($self, $val)= @_;
   $val += 0;
   croak "data_offset must be a non-negative integer"
      if $val < 0 || int($val) != $val;
   croak "data_offset must be a multiple of sector_size"
      if $self->sector_size && $val % $self->sector_size;
   $self->{data_offset}= $val;
   $self;
}
sub data_size {
   @_ > 1? croak("use ->resize to change data_size")
   : $_[0]{handle}? $_[0]->_get_data_size_from_handle
   : $_[0]{data_size}
}

sub _get_data_size_from_handle {
   my $self= shift;
   my $pos= sysseek($self->handle, 0, Fcntl::SEEK_END())
      // croak "seek failed: $!";
   croak "file has been truncated"
      if $pos < $self->data_offset;
   return $pos - $self->data_offset;
}

sub authentication { $_[0]{authentication} }
sub _cipher_skey {
   my $self= shift;
   my $skey= $self->lock_mechanism->primary_skey
      or croak "Vault is locked";
   Crypt::MultiKey::hkdf(
      { size => 64, kdf_info => 'Crypt::MultiKey/Vault/cipher_skey', kdf_salt => '' },
      $skey
   );
}

our %_attr_pri= (
   path => -2,
   handle => -2,
   sector_size => -1,
);

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
sub _set_lock_mechanism {
   my ($self, $val)= @_;
   blessed($val) && $val->can('primary_skey')
      or croak "Expected instance of Crypt::MultiKey::LockMechanism";
   $_[0]{lock_mechanism}= $_[1]
}
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

=constructor new

  $vault= Crypt::MultiKey::Vault->new(%attributes);

This creates a new uninitialized Vault.  Any configuration, read, or write
on this object will be cached in memory until you call L</save>.

=constructor open

  $vault= Crypt::MultiKey::Vault->open(path => $x);
  $vault= Crypt::MultiKey::Vault->open(handle => $x);

This opens an existing Vault file and unpacks its metadata.  The data canot be
read until you call L</unlock>.

=cut

sub new {
   my $class= shift;
   my %attrs= @_ == 1? %{$_[0]} : @_;
   my $self= bless {}, $class;
   $self->{cipher}= 'AES-256-XTS';
   $self->{sector_size}= DEFAULT_SECTOR_SIZE;
   $self->{data_offset}= DEFAULT_DATA_OFFSET;
   $self->{data_size}= 0;
   $self->_init(\%attrs) if $self->can('_init');
   for (sort { ($_attr_pri{$a}||0) <=> ($_attr_pri{$b}||0) } keys %attrs) {
      my $setter= "_set_$_";
      $self->$setter($attrs{$_});
   }
   $self->name($self->{path}? basename($self->{path}) : 'Vault')
      unless defined $self->name;
   return $self;
}

sub open {
   my ($class_or_self, %opts)= @_;
   my $self= ref($class_or_self)? $class_or_self : $class_or_self->new;
   my $fh= delete $opts{handle};
   my $path= delete $opts{path};
   my $bundled_keys= delete $opts{bundled_keys};
   croak "Specify exactly one of 'path' or 'handle'"
      if (!$fh && !$path) || ($fh && $path);
   croak "Unknown options: ".join(', ', sort keys %opts)
      if keys %opts;
   if (!$fh) {
      CORE::open $fh, '+<:raw', $path
         or croak "open($path): $!";
   }
   $self->{path}= $path if defined $path;
   $self->{handle}= $fh;
   $self->{bundled_keys}= $bundled_keys if defined $bundled_keys;
   $self->_load;
   return $self;
}

sub _load {
   my $self= shift;
   my $fh= $self->handle or croak "No handle";
   my $at= sysseek($fh, 0, Fcntl::SEEK_SET())
      // croak "seek: $!";
   $at == 0 or croak "seek returned wrong address";
   # Start with the first 64KiB, then keep reading until we have at least one
   # complete VAULT PEM stanza.
   my $header_buf= secret;
   my $end_marker= "-----END CRYPT MULTIKEY VAULT-----";
   my $tmp= '';
   while (index($tmp, $end_marker) < 0) {
      my $want= $header_buf->length? 16384 : 65536;
      my $n= sysread($fh, my $chunk= '', $want);
      defined $n or croak "read: $!";
      last unless $n;
      $header_buf->append(substr($chunk, 0, $n));
      $tmp .= substr($chunk, 0, $n);
      croak "Vault header appears unreasonably large"
         if $header_buf->length > 0x400000;
   }
   my ($vault_pem)= do {
      my ($pem_text)= $tmp =~ /(-----BEGIN CRYPT MULTIKEY VAULT-----.*?-----END CRYPT MULTIKEY VAULT-----\s*)/s;
      defined $pem_text
         ? grep $_->label eq 'CRYPT MULTIKEY VAULT', Crypt::SecretBuffer::PEM->parse_all(span($pem_text))
         : ();
   };
   croak "No CRYPT MULTIKEY VAULT pem block in file"
      unless defined $vault_pem;
   my $attrs= $self->_attrs_from_pem($vault_pem, $self->path // 'handle');
   my $data_offset= $attrs->{data_start_block} * $attrs->{sector_size};
   my $tail= '';
   my $tail_at= sysseek($fh, $data_offset - 2, Fcntl::SEEK_SET())
      // croak "seek: $!";
   $tail_at == ($data_offset - 2)
      or croak "seek returned wrong address";
   my $n= sysread($fh, $tail, 2);
   croak "read: unexpected EOF"
      unless defined($n) && $n == 2;
   croak "Bytes before data_start are not \"\\n\\0\""
      unless $tail eq "\n\0";
   $self->_set_cipher($attrs->{cipher});
   $self->_set_sector_size($attrs->{sector_size});
   $self->_set_data_offset($data_offset);
   $self->_set_lock_mechanism($attrs->{lock_mechanism});
   $self->_set_user_meta($attrs->{user_meta} || {});
   $self->{authentication}= $attrs->{authentication};
   if ($self->bundled_keys) {
      if ($header_buf->length < $data_offset) {
         my $at= sysseek($fh, $header_buf->length, Fcntl::SEEK_SET())
            // croak "seek: $!";
         $at == $header_buf->length
            or croak "seek returned wrong address";
         while ($header_buf->length < $data_offset) {
            $header_buf->append_sysread($fh, $data_offset - $header_buf->length)
               or croak "read: ".($! || "unexpected EOF");
         }
      }
      my @pkey_pem= grep {
         $_->label eq 'ENCRYPTED PRIVATE KEY' || $_->label eq 'PUBLIC KEY'
      } Crypt::SecretBuffer::PEM->parse_all($header_buf->span(pos => 0, len => $data_offset-1));
      my @pkeys;
      for my $pk_pem (@pkey_pem) {
         eval { push @pkeys, Crypt::MultiKey::PKey->load($pk_pem) }
            or carp "Warning: failed to load bundled PKey: $@";
      }
      $self->insert_keys(@pkeys) if @pkeys;
   }
   $self->{data_size}= $self->_get_data_size_from_handle;
   $self;
}

sub _generate_header {
   my $self= shift;
   my $pem= $self->_export_pem;
   my $header= $pem->serialize;
   $header->append($self->_export_bundled_keys)
      if $self->bundled_keys;
   my $pad= $self->data_offset - $header->length;
   croak "Header does not fit in reserved area"
      if $pad < 2;
   $header->append(("\n" x ($pad-1)), "\0")
      if $pad > 0;
   return $header;
}

sub _export_bundled_keys {
   my $self= shift;
   my $method= $self->bundled_keys eq 'public'? 'export_pem_openssl_public_key' : 'export_pem';
   my %keys;
   my $n_missing= 0;
   for my $lock (@{ $self->locks }) {
      for my $tmbl (@{ $lock->{tumblers} }) {
         if (defined $tmbl->{key}) {
            $keys{$tmbl->{key}->fingerprint}= $tmbl->{key};
         } else {
            ++$n_missing;
         }
      }
   }
   carp "Exporting 'bundled_keys' but $n_missing tumblers lack a PKey object"
      if $n_missing;
   my $ret= secret;
   for my $fp (sort keys %keys) {
      my $k= $keys{$fp};
      my $pem= !defined($k->protection_scheme)
         ? $k->export_pem_openssl_public_key
         : $k->$method;
      $ret->append($pem->serialize);
   }
   return $ret;
}

sub _attrs_from_pem {
   my ($self, $pem, $path)= @_;
   my $header_kv= $pem->header_kv;
   croak "Headers must start with version and writer_version"
      unless @$header_kv > 4 && $header_kv->[0] eq 'version' && $header_kv->[2] eq 'writer_version';
   my $min_version= version->parse($header_kv->[1]);
   carp "'$path' requires version $min_version of Crypt::MultiKey::Vault but this is only version "
      .__PACKAGE__->VERSION
      if $min_version > __PACKAGE__->VERSION;
   croak "Headers must end with header_authentication"
      unless @$header_kv > 2 && $header_kv->[-2] eq 'header_authentication';
   my $header_text= '';
   for (0..$#$header_kv-2) {
      $header_text .= $header_kv->[$_] . ($_ & 1? "\n" : ": ");
   }
   my ($mac_algo,$mac_base64)= split ':', $header_kv->[-1], 2;
   my $attrs= Crypt::MultiKey::_inflate_pem_header_kv(@{$header_kv}[4..($#$header_kv-2)]);
   $attrs->{lock_mechanism}= Crypt::MultiKey::LockMechanism->new->_import_attrs($attrs);
   $attrs->{authentication}= [ $header_text, $mac_algo, decode_base64($mac_base64) ];
   return $attrs;
}

sub _export_pem {
   my $self= shift;
   my @header_kv= Crypt::MultiKey::_flatten_to_pem_header_kv(
      version        => '0.001',
      writer_version => __PACKAGE__->VERSION,
      cipher         => $self->cipher,
      sector_size    => $self->sector_size,
      data_start_block => int($self->data_offset / $self->sector_size),
      user_meta      => $self->user_meta,
      %{ $self->lock_mechanism->_export_attrs }
   );
   my $header_text= '';
   for (0..$#header_kv) {
      $header_text .= $header_kv[$_] . ($_ & 1? "\n" : ": ");
   }
   my $header_mac= 'HMAC-SHA256:';
   Crypt::MultiKey::hmac_sha256($self->lock_mechanism->hmac_skey, $header_text)
      ->span->append_to($header_mac, encoding => BASE64);
   push @header_kv, 'header_authentication' => $header_mac;
   return Crypt::SecretBuffer::PEM->new(
      label     => 'CRYPT MULTIKEY VAULT',
      header_kv => \@header_kv,
   );
}

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
      croak 'Header MAC failed; Vault headers have been modified since file was written.'
         if $croak;
      return 0;
   }
   return 1;
}

sub save {
   my ($self, @args)= @_;
   my %opts= @args == 1 && !ref $args[0]? (path => $args[0]) : @args;
   my $path= delete $opts{path};
   my $rewrite= !$self->handle || defined($path);
   $path //= $self->path;
   croak "No path set" unless defined $path;
   my %attr_updates;
   for my $attr (qw( cipher sector_size data_offset user_meta name )) {
      next unless exists $opts{$attr};
      $attr_updates{$attr}= delete $opts{$attr};
   }
   croak "Unknown save options: ".join(', ', sort keys %opts)
      if keys %opts;
   croak "Can't save Vault when no locks are defined"
      unless @{ $self->locks };
   my ($data_size, $plain);
   if ($rewrite && $self->handle) {
      $data_size= $self->data_size;
      $plain= $data_size? $self->read(0, $data_size)->copy : secret;
   }
   for my $attr (sort keys %attr_updates) {
      my $setter= "_set_".$attr;
      $self->$setter($attr_updates{$attr});
   }
   if (!$rewrite) {
      my $hdr= $self->_generate_header;
      _write_data_segment($self->handle, 0, $hdr);
      return $self;
   }
   $data_size= $self->data_size unless defined $data_size;
   $plain= $data_size? $self->read(0, $data_size)->copy : secret unless defined $plain;
   my $bs= $self->sector_size;
   my $target_size= $data_size;
   my $rem= $target_size % $bs;
   $target_size += ($bs - $rem) if $rem;
   $plain->length($target_size)
      if $plain->length < $target_size;
   $self->resize($target_size);
   CORE::open my $fh, '>:raw', $path
      or croak "open(>$path): $!";
   _write_data_segment($fh, 0, $self->_generate_header);
   if ($plain->length) {
      my $skey= $self->_cipher_skey;
      my $cipher= Crypt::MultiKey::symmetric_encrypt({
         cipher      => $self->cipher,
         sector_size => $self->sector_size,
         sector_idx  => 0,
      }, $skey, $plain);
      _write_data_segment($fh, $self->data_offset, $cipher);
   }
   close($fh) or croak "close($path): $!";
   CORE::open my $rw, '+<:raw', $path
      or croak "open(+<$path): $!";
   $self->{handle}= $rw;
   $self->{path}= $path;
   delete $self->{_data};
   $self;
}

=method resize

Extend or truncate the data region of the file.  This is just a call to 'truncate' on the
file handle, so it does not need to reconstruct the file.

=cut

sub resize {
   my ($self, $size)= @_;
   # round up to a multiple of block size
   my $bs= $self->sector_size;
   my $remainder= $size % $bs;
   $size += ($bs - $remainder) if $remainder;
   # If handle exists, change the actual file
   if (defined $self->handle) {
      truncate($self->handle, $size + $self->data_offset)
         or croak "Failed to resize file: $!";
   }
   $self->{data_size}= $size;
   $self;
}

=method read

  $secret= $vault->read($ofs, $size);

Read (and decrypt) a region of the data area.  This does not need to be block-aligned, but is
more efficient when aligned.  Note that there is B<no integrity check> for data blocks.
If you reach the end of the file, the read will be truncated.  If you request from beyond the
end of the file it will return undef.

=cut

sub read {
   my ($self, $ofs, $size)= @_;
   my $skey= $self->_cipher_skey;
   my $data_size= $self->data_size;
   # offset must be at or before end of data
   croak "negative data offset" if $ofs < 0;
   croak "attempt to read beyond end of file" if $ofs > $data_size;
   # truncate if reading from beyond the end of the data_size
   $size= $data_size - $ofs if $ofs + $size > $data_size;
   # eliminate zero-length edge case
   return secret() unless $size;
   # handle is defined when we are operating on a real file
   if (defined(my $fh= $self->handle)) {
      my $sz= $self->sector_size;
      # find which blocks are affected
      my $sec0= int($ofs / $sz);
      my $secN= int(($ofs + $size - 1) / $sz);
      my $full_size= ($secN - $sec0 + 1) * $sz;
      my $file_ofs= $self->data_offset + $sec0 * $sz;
      my $at= sysseek($fh, $file_ofs, Fcntl::SEEK_SET())
         // croak "seek: $!";
      $at == $file_ofs
         or croak "seek returned wrong address";
      my $data= secret;
      while ($data->length < $full_size) {
         $data->append_sysread($fh, $full_size - $data->length)
            or croak "read: ".($! || "unexpected EOF");
      }
      # decrypt the blocks
      Crypt::MultiKey::symmetric_decrypt({
         cipher      => $self->cipher,
         sector_size => $self->sector_size,
         sector_idx  => $sec0,
      }, $skey, $data, $data);
      return $data->span(pos => ($ofs & ($sz-1)), len => $size);
   } else {
      # Staging data before first save.  Read from unencrypted 1MiB buffers.
      # The buffers array can be sparse.
      my $bufs= ($self->{_data} //= []);
      my $out= secret(capacity => $size);
      while ($size) {
         my $idx= $ofs >> STAGING_BUFFER_SHIFT;
         my $buf_ofs= $ofs & STAGING_BUFFER_MASK;
         my $buf_lim= $buf_ofs + $size;
         $buf_lim= STAGING_BUFFER_SIZE
            if $buf_lim > STAGING_BUFFER_SIZE;
         if (my $buf= $bufs->[$idx]) {
            $out->append($buf->span(pos => $buf_ofs, lim => $buf_lim));
         } else {
            # pretend this sparse block is all zeroes
            $out->length($out->length + ($buf_lim - $buf_ofs));
         }
         my $n= $buf_lim - $buf_ofs;
         $ofs += $n;
         $size -= $n;
      }
      return $out->span;
   }
}

=method write

  $vault->write($ofs, $secret_or_span);

Write plaintext to a region of the data area.  This does not need to be block-aligned, but is
more efficient when aligned.  The file will be enlarged if you write beyond the end of the file.

=cut

sub write {
   my ($self, $ofs, $data)= @_;
   croak "negative data offset" if $ofs < 0;
   my $lim= $ofs + $data->length;
   my $skey= $self->_cipher_skey;
   $data= span($data); # Now we have a ::Span object
   if (my $fh= $self->handle) {
      # real file
      my $sz= $self->sector_size;
      my $smask= $sz-1;
      # find which sectors are affected
      my $sec0= int($ofs / $sz);
      my $secN= int(($ofs + $data->len - 1) / $sz);
      if (my $sofs= ($ofs & $smask)) {
         # unaligned write.  Need to load the sector, decrypt it, splice it,
         # and re-encrypt.
         my $len= ($sec0 == $secN)? $data->len : $sz - $sofs;
         my $sdat= $self->read($sec0 * $sz, $sz)->copy;
         $sdat->splice($sofs, $len, $data->subspan(0, $len));
         Crypt::MultiKey::symmetric_encrypt({ cipher => $self->cipher }, $skey, $sdat, $sdat);
         _write_data_segment($fh, $self->data_offset + $sec0 * $sz, $sdat);
         $data->pos($data->pos + $len);
         ++$sec0;
      }
      # Now ofs is aligned. Check new length...
      if (my $tail= ($data->len & $smask)) {
         # also ends with an unaligned write
         my $sdat= $self->read($secN * $sz, $sz)->copy;
         $sdat->splice(0, $tail, $data->subspan(-$tail));
         Crypt::MultiKey::symmetric_encrypt({ cipher => $self->cipher }, $skey, $sdat, $sdat);
         _write_data_segment($fh, $self->data_offset + $secN * $sz, $sdat);
         $data->lim($data->lim - $tail);
      }
      if ($data->len) {
         my $buf= Crypt::MultiKey::symmetric_encrypt({ cipher => $self->cipher }, $skey, $data);
         _write_data_segment($fh, $self->data_offset + $sec0 * $sz, $buf);
      }
   } else {
      # Staging data before first save.  Save unencrypted into 1MiB buffers.
      # The buffers array can be sparse.  This can also enlarge the overall
      # data size if writing beyond the end.
      my $bufs= ($self->{_data} //= []);
      while ($data->len) {
         my $idx= $ofs >> STAGING_BUFFER_SHIFT;
         my $buf_ofs= $ofs & STAGING_BUFFER_MASK;
         my $segment= $data;
         $segment= $segment->clone(len => STAGING_BUFFER_SIZE - $buf_ofs)
            if $buf_ofs + $data->len > STAGING_BUFFER_SIZE;
         my $buf= ($bufs->[$idx] //= secret(length => STAGING_BUFFER_SIZE));
         $buf->splice($buf_ofs, $segment->len, $segment);
         $data->pos($data->pos + $segment->len);
      }
      $self->{data_size}= $lim if $lim > $self->{data_size};
   }
   $self;
}

sub _write_data_segment {
   my ($fh, $ofs, $data)= @_;
   my $at= sysseek($fh, $ofs, Fcntl::SEEK_SET()) // croak "seek: $!";
   $at == $ofs or croak "seek returned wrong address";
   if (!ref $data) {
      my $wrote= syswrite($fh, $data) // croak "write: $!";
      while ($wrote < length($data)) {
         my $wr= syswrite($fh, $data, length($data)-$wrote) or croak "write: $!";
         $wrote += $wr;
      }
   } else {
      my ($data_ofs, $data_len)= (0, $data->length);
      # convert Span object back to SecretBuffer and offset
      unless ($data->can('syswrite')) {
         $data_ofs= $data->pos;
         $data= $data->buf;
      }
      my $wrote= $data->syswrite($fh, $data_len, $data_ofs) // croak "write: $!";
      while ($wrote < $data_len) {
         my $wr= $data->syswrite($fh, $data_len - $wrote, $data_ofs + $wrote) // croak "write: $!";
         $wrote += $wr;
      }
   }
}

=method create_block_device

  $vault->create_block_device(name => $mapper_dev_name);

This currently only works on Linux, and probably requires root access.  If the L</handle> is not
a block device (likely) this starts by creating one with L<losetup(1)>.  It then calls
L<dmsetup(1)> to create a new mapper device using dm-crypt, and then releases the loop device
so that it gets deleted automatically once the mapper device is closed.  You can then directly
perform reads and writes on the data area of this file by reading and writing that block device,
and at the speed of the kernel.

Dies on failure.  It also attempts to clean up the loopback and/or dm device on failure.

Patches welcome for supporting other operating systems.

=cut

sub create_block_device {
   my ($self, %opts)= @_;
   defined fileno($self->handle)
      or croak "create_block_device can only be used when Vault is backed by a real file";
   # throws an exception if the vault is still locked
   my $aes_key= $self->_cipher_skey;
   # make sure handle is functioning
   my $length= sysseek($self->handle, 0, Fcntl::SEEK_END)
      // croak "seek: $!";
   croak "Corrupt vault"
      if $length < $self->data_offset;
   $length -= $self->data_offset;
   my $sz= $self->sector_size;

   if ($^O eq 'linux') {
      my $mapname= $opts{name}
         // croak "mapper device 'name' is required";
      my $mapdev= "/dev/mapper/$mapname";
      croak "$mapdev already exists" if -e $mapdev;

      # Despite declaring a "sector size", all offsets and lengths passed to dmcrypt
      # are in units of 512.
      croak "data_offset must be a multiple of 512"
         if $self->data_offset % 512;
      croak "data length must be a multiple of 512"
         if $length % 512;
      croak "Maximum sector_size for Linux dm-crypt is 4096"
         if $sz > 4096;
      croak "Minimum sector_size for Linux dm-crypt is 512"
         if $sz < 512;

      my @features;
      if ($sz > 512) {
         # For sector sizes larger than 512, iv_large_sectors makes plain64 set the
         # initialization vector to the sector number rather than a 512-byte block
         # offset of the start of the sector.
         push @features, "sector_size:$sz",
                         'iv_large_sectors';
      }

      # avoid race conditions by using the kernel's own symlink to the origin of this handle
      my $path= '/proc/self/fd/'.fileno($self->handle);
      my ($blkdev, $is_new_loop);
      # need a block device
      if (-b $self->handle) {
         $blkdev= $path;
      }
      else {
         CORE::open my $fh, '-|', 'losetup', '--find', '--show', '--', $path
            or die "open losetup pipe failed: $!";
         $blkdev= <$fh>;
         close($fh) or die "losetup failed";
         defined($blkdev) && length($blkdev)
            or die "losetup did not return a device";
         chomp($blkdev);
         -b $blkdev
            or die "losetup didn't return a block device? '$blkdev'";
         $is_new_loop= 1;
      }

      # dm-crypt lengths and offsets are always expressed in 512-byte sectors, even after
      # specifying 'sector_size:x' and even if we set the block size on the loopback device.
      # Table:
      # mapper_ofs mapper_len module cipher aes_key_hex IV_ofs dev src_dev_ofs feature_count [feature...]
      my $dmsetup_table= secret->append(
         '0 '.int($length/512).' crypt aes-xts-plain64 ',
         $aes_key->span->copy(encoding => 'HEX'),
         ' '.join(' ', 0, $blkdev, int($self->data_offset/512), scalar(@features), @features)
      );

      my $err= eval {
         CORE::open(my $fh, '|-', 'dmsetup', 'create', $mapname, '--table', '-')
            or die "open dmsetup pipe failed: $!";
         binmode($fh, ':raw');
         my $ofs= 0;
         while ($ofs < $dmsetup_table->length) {
            my $wrote= $dmsetup_table->syswrite($fh, $dmsetup_table->length - $ofs, $ofs)
               // croak "write to dmsetup failed: $!";
            $ofs += $wrote;
         }
         $fh->close or die "write to dmsetup failed: $!";
         1;
      }? undef : $@;

      # Always free the loop device.  If device mapper is still using it it will persist until
      # the mapped device is closed.
      system('losetup','-d',$blkdev)
         if $is_new_loop;

      croak $err if defined $err;

      # Verify the map by reading one block
      -e $mapdev
         or croak "Mapped device '$mapdev' was not created";

      if ($length >= $sz) {
         unless (eval {
            CORE::open my $dmh, '<:raw', $mapdev
               or die "open($mapdev): $!";
            my $s= secret;
            $s->sysread($dmh, $sz)
               // die "read($mapdev): $!";
            $s->memcmp($self->read(0, $sz)) == 0
               or die "dm-crypt decryption of block 0 gave wrong results";
            1;
         }) {
            system('dmsetup', 'remove', $mapname) == 0
               or carp "Unable to clean up device '$mapdev'";
            croak $@;
         }
      }
      return $mapdev;
   }
   else {
      croak "create_block_device does not support $^O";
   }
}

# Avoid dependency on namespace::clean
delete @Crypt::MultiKey::Vault::{qw(
   carp confess croak
   encode_base64 decode_base64
   blesed looks_like_number basename
   secret span HEX BASE64 ISO8859_1 )};
