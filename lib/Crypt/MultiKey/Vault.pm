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

A Vault is defined in terms of a C<sector_size>.  The header occupies an integer number of
sectors, but also ensures that the data starts on a 4KiB boundary.  The header has an optional
user-defined "preamble" (useful for fun things like a shebang that makes the vault executable)
followed by a format marker, followed by a version declaration, followed by a JSON object
holding the rest of the header data.  The JSON can optionally be followed by serialized PKey
objects (having encrypted private halves) if you wish to keep your keys close to the thing
they unlock.  The remainder of the header is padded with \n bytes, up to the last 32 bytes which
hold an C<HMAC-SHA256> of all bytes in the header up to the HMAC.

The purpose of this format is to allow you to see what is inside it using a text editor, easily
parse it with other tools if you need to, and have all the binary data pushed off the bottom of
the screen by the run of "\n" characters to reduce the chance that you corrupt your terminal.
The run of "\n" characters also provide padding so that the header can be rewritten without
needing to replace the entire file.  I departed from PEM encoding because the primary purpose of
PEM is to be ascii-safe during transmission, but a Vault will always need full 8-bit capability,
and JSON is easier to store user metadata without PEM header restrictions.

  $optional_preamble
  \0
  ===== Crypt::MultiKey::Vault =====
  version: 0.001
  {
    "cipher": "AES-256-XTS",
    "sector_size": 4096,
    "data_sector": 2,
    "user_meta": {
      "name": "Example"
    },
    "locks": [
      { "cipher": "AES-256-GCM",
        "ciphertext": $base64,
        "tumblers": [
          { "ephemeral_pubkey": $base64, "key_fingerprint": "SHA256:base64==" }
        ]
      },
      { "cipher": "AES-256-GCM",
        "ciphertext": $base64,
        "tumblers": [
          { "ephemeral_pubkey": $base64, "key_fingerprint": "SHA256:base64==" },
          { "ephemeral_pubkey": $base64, "key_fingerprint": "SHA256:base64==" }
        ]
      }
    ],
    "writer_version": "0.001"
  }
  \0
  [optional bundled PKey objects in PEM format]
  \n
  \n (repeating until 32 bytes before data_sector)
  $HMAC_BYTES
  [binary data begins at data_sector declared above]

=cut

use v5.12;
use warnings;
use version;
use Carp;
use Fcntl ();
use MIME::Base64 qw/ encode_base64 decode_base64 /;
use List::Util qw/ max /;
use JSON::PP;
use File::Basename qw/ basename /;
use Crypt::MultiKey;
use Crypt::MultiKey::LockMechanism;
use Scalar::Util qw/ blessed looks_like_number /;
use Crypt::SecretBuffer qw/ secret span HEX BASE64 ISO8859_1 /;
use Crypt::SecretBuffer::PEM 0.020;
use constant {
   STAGING_BUFFER_SIZE => 0x400000,
   STAGING_BUFFER_MASK => 0x3FFFFF,
   STAGING_BUFFER_SHIFT => 22,
   DEFAULT_SECTOR_SIZE => 512,
   DEFAULT_DATA_OFFSET => 0x10000,
   DEFAULT_CIPHER => 'AES-256-XTS',
   HEADER_MARKER => "\0===== Crypt::MultiKey::Vault =====\n",
   HEADER_MAC_SIZE => 32, # HMAC-SHA256
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

=cut

sub path   { $_[0]{path} }
sub _set_path { $_[0]{path}= $_[1]; $_[0] }

sub handle { $_[0]{handle} }
sub _set_handle { $_[0]{handle}= $_[1]; $_[0] }

sub cipher { $_[0]{cipher} }
sub _set_cipher {
   $_[1] eq 'AES-256-XTS' or croak "cipher '$_[1]' is unsupported";
   $_[0]{cipher}= $_[1];
   $_[0]
}

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

=attribute header_offset

The byte offset at which the Vault header begins.  Data before this offset is the "preamble".
This is updated automatically if you specify a new preamble during L</save>.

=attribute file_preamble

A user-defined text to write at the beginning of the Vault file.   The text may not include the
string C<"\0===== Crypt::MultiKey::Vault =====\n">.  The feature is provided to allow the Vault
to be prefixed with a script.
This can only be changed during a call to L</save>.

=attribute data_offset

The byte offset at which data blocks begin.  This must be a multiple of the sector size, and by
default will not be smaller than 64KiB to leave room for the header to grow without needing to
rewrite the file.
This can be changed during L</save> if you are saving to a new file.

=attribute data_size

The length in bytes of the data area.  e.g. file size minus L<data_offset>.
This can be changed at any time via L</resize>.  The attribute is read-only for safety.

=cut

# header gets loaded during ->load or generated during ->save
# and should always be present on a Vault having a 'handle'
sub _header { $_[0]{header} }

sub header_offset { $_[0]{header_offset} || 0 }

sub file_preamble {
   my $self= shift;
   return $self->{file_preamble} if defined $self->{file_preamble};
   return '' unless $self->header_offset && $self->_header;
   $self->_header->span(0, $self->header_offset)->copy_to($self->{file_preamble}= '');
   return $self->{file_preamble};
}
sub _set_file_preamble {
   my ($self, $val)= @_;
   croak "file_preamble may not contain the Vault header marker"
      if defined($val) && index($val, HEADER_MARKER) >= 0;
   croak "file_preamble may not contain wide characters"
      unless utf8::downgrade($val, 1);
   $self->{file_preamble}= $val;
   $self->{header_offset}= length $val;
   $self;
}

sub data_offset { $_[0]{data_offset} }
sub _set_data_offset {
   my ($self, $val)= @_;
   $val += 0;
   croak "data_offset must be a non-negative integer"
      if $val < 0 || int($val) != $val;
   croak "data_offset must be a multiple of sector_size"
      if $val % $self->sector_size;
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

=attribute bundled_keys

  $self->bundled_keys(1)        # serialize protected PKeys in header
  $self->bundled_keys('public') # serialize OpenSSL 'PUBLIC KEY' PEM in header

If set to a true value, any PKey object referenced by the L</lock_mechanism> with a
L<protection_scheme|Crypt::MultiKey::PKey/protection_scheme> defined (i.e. encrypted) will be
serialized into the Vault header during L</save>.  If set to the value C<'public'>, only the
public half of each PKey will be serialized, in OpenSSL PUBLIC KEY format and lacking any PKey
metadata.

This feature exists to help keep the PKey objects tightly associated with the Vault file so that
all you need to open the Vault are the credentials for the PKey protection schemes.
This attribute must be specified in the constructor (or L<save method/save>), and will not be
preserved across save/load of the Vault.  This gives the caller control over whether PKey
objects are trusted from this Vault file.

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
   $self->_authenticate(1) if $self->_header;
   $self;
}

sub unlocked {
   my $self= shift;
   !$self->lock_mechanism->initialized || $self->lock_mechanism->unlocked;
}

sub _cipher_skey { shift->lock_mechanism->cipher_skey(64) }

=attribute user_meta

An arbitrary hashref of JSON-compatible metadata that will be added to the Vault header.
Note that headers are B<plaintext>.
If you wish to store secret user metadata it needs to be part of L</content>, which can be
accomplished conveniently using L</content_dict>.

Warning: the authenticity of C<user_meta> does not get checked until you have
L<unlocked|/unlock> the Vault.  Never trust C<user_meta> on a locked Vault unless the file
was stored securely.

=attribute name

A shortcut for C<< ->user_meta->{name} >>.  This helps encourage you to at least provide a label
for the file indicating its purpose or contents.  This defaults to the basename of the L</path>.

=cut

sub user_meta { @_ > 1? shift->_set_user_meta(@_) : ($_[0]{user_meta} ||= {}) }
sub _set_user_meta {
   ref $_[1] eq 'HASH' or croak "user_meta must be a hashref";
   $_[0]{user_meta}= $_[1];
   $_[0]
}

sub name { @_ > 1? shift->_set_name(@_) : $_[0]->user_meta->{name} }
sub _set_name { $_[0]->user_meta->{name}= $_[1]; $_[0] }

=constructor new

  $vault= Crypt::MultiKey::Vault->new(%attributes);

This creates a new uninitialized Vault.  Any configuration or data writes to this object will
be cached in memory until you call L</save>.

=constructor load

  $vault= Crypt::MultiKey::Vault->load($path, %attributes);
  $vault= Crypt::MultiKey::Vault->load($handle, %attributes);
  $vault= Crypt::MultiKey::Vault->load(%attributes); # with 'handle' or 'path'

This loads an existing Vault file and unpacks its metadata.  The data canot be
read until you call L</unlock>.

=cut

our %_attr_priority= ( # controls order attributes get assigned during construction
   cipher => -6,
   sector_size => -5,
   file_preamble => -4,
   user_meta => 1,
   name => 2,
);
sub new {
   my $class= shift;
   my %attrs= @_ == 1? %{$_[0]} : @_;
   my $self= bless {}, $class;
   $self->{cipher}=      DEFAULT_CIPHER;
   $self->{sector_size}= DEFAULT_SECTOR_SIZE;
   $self->{data_offset}= DEFAULT_DATA_OFFSET;
   $self->{data_size}= 0;
   $self->_init(\%attrs) if $self->can('_init');
   for (sort { ($_attr_priority{$a}||0) <=> ($_attr_priority{$b}||0) } keys %attrs) {
      my $setter= "_set_$_";
      $self->$setter($attrs{$_});
   }
   $self->name($self->{path}? basename($self->{path}) : 'Vault')
      unless defined $self->name;
   return $self;
}

sub load {
   my $class_or_self= shift;
   my %opts;
   if (@_ & 1) {
      if (ref($_[0]) eq 'GLOB' || ref($_[0])->can('sysread')) {
         %opts= ( handle => @_ );
      } elsif (-e $_[0]) {
         %opts= ( path => @_ );
      } else {
         croak "Odd number of parameters must start with a handle or path to existing file";
      }
   } else {
      %opts= @_;
   }
   my $self= ref($class_or_self)? $class_or_self : $class_or_self->new;
   my $fh= delete $opts{handle};
   my $path= delete $opts{path};
   my $bundled_keys= delete $opts{bundled_keys};
   croak "Specify exactly one of 'path' or 'handle'"
      unless defined($fh) xor defined($path);
   croak "Unknown options: ".join(', ', sort keys %opts)
      if keys %opts;
   unless (defined $fh) {
      open($fh, '+<:raw', $path)
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
   my $path= $self->path // '(handle)';
   my $at= sysseek($fh, 0, Fcntl::SEEK_SET())
      // croak "seek: $!";
   $at == 0 or croak "seek returned wrong address";

   # Read until we have the marker and the NUL byte that terminates the JSON header.
   # This doesn't need to be in a SecretBuffer, but its a little more efficient this way.
   my $header_buf= secret(stringify_mask => '[HEADER]');
   my ($got, $version);
   my ($header_offset, $ver_end, $json_end)= (-1, -1, -1);
   while ($got= $header_buf->append_read($fh, 64*1024)) {
      # scan the new chunk for the HEADER_MARKER
      if ($header_offset < 0) {
         $header_offset= $header_buf->index(HEADER_MARKER, -$got - length(HEADER_MARKER));
      }
      # scan for newline at end of "version: x"
      if ($header_offset >= 0 && $ver_end < 0) {
         if (($ver_end= $header_buf->index("\n", $header_offset + length(HEADER_MARKER))) >= 0) {
            $header_buf->span(pos => $header_offset + length(HEADER_MARKER), lim => $ver_end)
               ->copy_to(my $ver_buf);
            $ver_buf =~ /^version: ([0-9]+\.[0-9_]+)\z/
               or croak "Invalid version encountered: '$ver_buf'";
            $version= version->parse($1);
            croak "Vault '$path' requires Crypt::MultiKey::Vault $version but this is only version $VERSION"
               if $version > $VERSION;
         }
      }
      if ($ver_end >= 0 && $json_end < 0) {
         last if ($json_end= $header_buf->index("\0", $ver_end)) >= 0;
      }
      croak "Vault header appears unreasonably large"
         if $header_buf->length >= 0x400000;
   }
   if ($json_end < 0) {
      defined $got or croak "error reading Vault header from $path: $!";
      $header_offset >= 0 or croak "No Crypt::MultiKey::Vault marker in file $path";
      croak "Incomplete Crypt::MultiKey::Vault header in file $path";
   }
   # Now decode the JSON and extract the Vault attributes
   $header_buf->span(pos => $ver_end + 1, lim => $json_end)->copy_to(my $json);
   my $attrs= JSON::PP->new->utf8->decode($json);
   croak "Vault JSON header must be an object"
      unless ref $attrs eq 'HASH';
   for my $required (qw( cipher sector_size data_sector locks )) {
      croak "Vault JSON header missing '$required'"
         unless defined $attrs->{$required};
   }
   croak "Vault sector_size is not a power of 2"
      if $attrs->{sector_size} & ($attrs->{sector_size}-1);
   my $data_offset= $attrs->{data_sector} * $attrs->{sector_size};
   croak "Vault data_sector places data before end of header"
      if $data_offset < $json_end + 1 + HEADER_MAC_SIZE;
   $attrs->{lock_mechanism}= Crypt::MultiKey::LockMechanism->new->_import_attrs($attrs);

   # Load the complete header so bundled keys and the header MAC can be inspected later.
   while ($header_buf->length < $data_offset) {
      $header_buf->append_read($fh, $data_offset - $header_buf->length)
         or croak "error reading header: ".($! || "unexpected EOF");
   }
   $header_buf->length($data_offset);

   $self->_set_cipher($attrs->{cipher});
   $self->_set_sector_size($attrs->{sector_size});
   $self->_set_lock_mechanism($attrs->{lock_mechanism});
   $self->_set_user_meta($attrs->{user_meta} || {});
   $self->{header}= $header_buf;
   $self->{header_offset}= $header_offset;
   $self->_set_data_offset($data_offset);
   # delete any previous cache
   delete $self->{data_size};
   delete $self->{file_preamble};

   # bundled_keys attribute must be passed to the constructor, not read from the file.
   # If enabled, scan the padding area for PKey PEM text.
   if ($self->bundled_keys && $json_end + 1 < $data_offset - HEADER_MAC_SIZE) {
      my @pkey_pem= grep {
         $_->label eq 'ENCRYPTED PRIVATE KEY' || $_->label eq 'PUBLIC KEY'
      } Crypt::SecretBuffer::PEM->parse_all(
         $header_buf->span(pos => $json_end + 1, lim => $data_offset - HEADER_MAC_SIZE)
      );
      my @pkeys;
      for my $pk_pem (@pkey_pem) {
         eval { push @pkeys, Crypt::MultiKey::PKey->load($pk_pem) }
            or carp "Warning: failed to load bundled PKey: $@";
      }
      $self->insert_keys(@pkeys) if @pkeys;
   }
   $self;
}

sub _generate_header {
   my $self= shift;
   # The header is not "secret", but Crypt::SecretBuffer is an efficient string buffer
   my $size= $self->data_offset // 64*1024;
   my $header= secret(capacity => $size, stringify_mask => '[HEADER]');
   my $attrs= {
      cipher      => $self->cipher,
      sector_size => 0+$self->sector_size,
      data_sector => int($self->data_offset / $self->sector_size),
      writer      => ref($self).' '.$self->VERSION,
      user_meta   => $self->user_meta,
      %{ $self->lock_mechanism->_export_attrs },
   };
   while (1) {
      $header->append(
         (defined $self->file_preamble? $self->file_preamble : ''),
         HEADER_MARKER,
         "version: 0.000\n",
         JSON::PP->new->utf8->canonical->pretty->encode($attrs),
         "\0"
      );
      $self->_export_bundled_keys($header)
         if $self->bundled_keys;
      # does it fit within the data_offset?
      last if $header->length + HEADER_MAC_SIZE <= $size;
      # Need to choose a new multiple of sector size (or 4KiB, whichever is larger).
      # Since we're picking a new number, also reserve at least 2KiB of padding.
      $size= $header->length + 2048;
      my $blocksize= max($self->sector_size, 4096);
      my $remainder= $size & ($blocksize-1);
      $size += ($blocksize - $remainder) if $remainder;
      $header->length(0);
      $header->capacity($size, 'AT_LEAST');
      $attrs->{data_sector}= int($self->data_offset / $self->sector_size);
      # and now we need to start over, because $attrs->{data_sector} has changed.
   }
   my $pad= $size - ($header->length + HEADER_MAC_SIZE);
   $header->append("\n" x $pad) if $pad > 0;
   my $mac= Crypt::MultiKey::hmac_sha256($self->lock_mechanism->hmac_skey, $header);
   $header->append($mac);
   return $header;
}

sub _export_bundled_keys {
   my ($self, $buf)= @_;
   $buf //= secret;
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
   for my $fp (sort keys %keys) {
      my $k= $keys{$fp};
      my $pem= !defined($k->protection_scheme)
         ? $k->export_pem_openssl_public_key
         : $k->$method;
      $buf->append($pem->serialize);
   }
   return $buf;
}

sub _authenticate {
   my ($self, $croak)= @_;
   # Header should always be available since it gets assigned by _load, and this method should
   # not get called if there is no existing file to authenticate.
   my $header= $self->_header
      or croak 'Vault header not loaded';
   $header->length == $self->data_offset
      or croak 'Vault header buffer is wrong length';
   defined $self->lock_mechanism->primary_skey
      or croak 'Vault is locked';
   # authenticate all bytes up to data_offset - HEADER_MAC_SIZE
   my $mac= Crypt::MultiKey::hmac_sha256(
      $self->lock_mechanism->hmac_skey,
      $header->span(0, - HEADER_MAC_SIZE)
   );
   unless ($mac->memcmp($header->span(-HEADER_MAC_SIZE)) == 0) {
      croak 'Header MAC failed; Vault header has been modified since file was written.'
         if $croak;
      return 0;
   }
   return 1;
}

=method save

  $vault->save(%options);
  #options:
  #  path             - path and file name to write
  #  sector_size      - power of 2 between 512 and 4096
  #  data_offset      - file offset which must point to a sector boundary
  #  user_meta        - arbitrary JSON-compatible perl data
  #  name             - shortcut for user_meta->{name}
  #  cipher           - currently must be 'AES-256-XTS'
  #  file_preamble    - a string to start the file, such as a '#!' line
  #  bundled_keys     - whether to include encrypted/public PKey inside the Vault

Write out a new Vault file, or write changes to the metadata of an existing file.
If you request changes to C<data_offset>, C<sector_size>, or C<cipher> (or enlarge C<user_meta>
beyond what fits before C<data_offset>) this will trigger a complete rewrite of the file.
A complete rewrite requires you to supply a C<path> for the new file and it must not already
exist.

=cut

sub save {
   my ($self, @args)= @_;
   my %opts= @args == 1 && !ref $args[0]? (path => $args[0]) : @args;
   croak "Can't save Vault when no locks are defined"
      unless @{ $self->locks };

   # construct a new object to ensure these parameters are consistent before altering any
   # of the attributes of the current object.
   my %new_attrs;
   my @attrs= qw( path cipher sector_size data_offset user_meta name file_preamble bundled_keys );
   for my $attr (@attrs) {
      $new_attrs{$attr}= delete $opts{$attr} // $self->$attr;
   }
   croak "Unknown save options: ".join(', ', sort keys %opts)
      if keys %opts;

   my $new= ref($self)->new(%new_attrs, lock_mechanism => $self->lock_mechanism);
   my $header= $new->_generate_header;
   # Conditions under which the current file can be updated without a full rewrite
   my $matching_cipher= $new->cipher eq $self->cipher
                     && $new->_cipher_skey->memcmp($self->_cipher_skey) == 0
                     && $new->sector_size == $self->sector_size;
   my $inplace= $self->handle
             && $new->path eq ($self->path//'')
             && $matching_cipher
             && $header->length == $self->data_offset;
   if ($inplace) {
      _write_ofs_data($self->handle, 0, $header);
      $self->{header}= $header;
      $self->{header_offset}= $new->header_offset;
      $self->{user_meta}= $new->user_meta;
      $self->{bundled_keys}= $new->bundled_keys;
      # if a preamble was specified, we're now loading it lazily from ->{header}
   } else {
      croak "No path specified"
         unless defined $new->path && length $new->path;
      # the file must not already exist
      sysopen(my $fh, $new->path, Fcntl::O_RDWR() | Fcntl::O_CREAT() | Fcntl::O_EXCL() ) or do {
         # If the user didn't ask for a new path, they probably need informed that a rewrite
         # is being attempted.
         croak 'Attempt to rewrite Vault without specifying a new path.'
             . '(rewrites occur when sector_size changes, or header grows beyond data_offset)'
            if $new->path eq ($self->path//'');
         croak 'File exists: "'.$new->path.'"'
            if -e $new->path;
         croak "open(".$new->path.", create exclusive): $!";
      };
      # update geometry of new Vault so we can use the write methods
      $new->{handle}= $fh;
      $new->{header}= $header;
      $new->{data_offset}= $header->length;
      # write the header
      _write_ofs_data($fh, 0, $header);
      # prepare data area
      truncate($fh, $new->data_offset + $self->data_size)
         // croak "truncate: $!";
      # now copy all of the data, possibly with a new sector_size
      # The data can either be in the staging buffers ($self->{_data}) or need decrypted
      # from each of the sectors of the existing file.
      if ($self->{_data}) {
         # iterate the staging buffers.  This is efficient as long as STAGING_BUFFER_SIZE
         # is larger than the new sector_size.
         for my $i (0..$#{$self->{_data}}) {
            my $buf= $self->{_data}[$i]
               or next;
            $new->write($i * STAGING_BUFFER_SIZE, $buf);
         }
      } elsif ($self->handle) {
         # If the cipher and sector_size match, we can copy the encrypted blocks directly.
         if ($matching_cipher) {
            $self->_seek_sector(0);
            my $got;
            while ($got= sysread($self->handle, my $buf, STAGING_BUFFER_SIZE) // croak "read: $!") {
               my $wrote= syswrite($new->handle, $buf) // croak "write: $!";
               $wrote == $got or croak "short write";
            }
         }
         else {
            # need to re-encrypt every sector.  Use large chunks to maximize the amount of
            # looping that happens inside XS and minimize seeks or buffer splicing.
            my $size= $self->data_size;
            my $large_copy_size= max(STAGING_BUFFER_SIZE, $self->sector_size, $new->sector_size);
            my $ofs= 0;
            while ($ofs + $large_copy_size <= $size) {
               $new->write($ofs, $self->read($ofs, $large_copy_size));
               $ofs += $large_copy_size;
            }
            $new->write($ofs, $self->read($ofs, $size - $ofs))
               if $size > $ofs;
         }
      }
      
      # Now replace attributes of $self with those of $new
      %$self= %$new;
   }
   %$new= (); # prevent any destruction
   undef $new;
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
      $self->_seek_sector($sec0);
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

sub _seek_sector {
   my ($self, $sector)= @_;
   my $file_ofs= $self->data_offset + $sector * $self->sector_size;
   my $at= sysseek($self->handle, $file_ofs, Fcntl::SEEK_SET())
      // croak "seek: $!";
   $at == $file_ofs
      or croak "seek returned wrong address";
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
   return $self unless $data->length;
   if (my $fh= $self->handle) {
      # real file
      my $sz= $self->sector_size;
      my $data_ofs= $self->data_offset;
      my $data_size= $self->data_size;
      my $smask= $sz-1;
      # find which sectors are affected
      my $sec0= int($ofs / $sz);
      my $secN= int(($ofs + $data->len - 1) / $sz);
      if (my $sofs= ($ofs & $smask)) {
         # unaligned write.  Need to load the sector, decrypt it, splice it,
         # and re-encrypt.
         my $len= ($sec0 == $secN)? $data->len : $sz - $sofs;
         my $sdat= $sec0 * $sz >= $data_size? secret(length => $sz)
                 : $self->read($sec0 * $sz, $sz)->copy;
         $sdat->splice($sofs, $len, $data->subspan(0, $len));
         Crypt::MultiKey::symmetric_encrypt({
               cipher      => $self->cipher,
               sector_size => $sz,
               sector_idx  => $sec0,
            }, $skey, $sdat, $sdat); # inplace within $sdat
         _write_ofs_data($fh, $data_ofs + $sec0 * $sz, $sdat);
         $data->pos($data->pos + $len);
         ++$sec0;
      }
      # Now ofs is aligned. Check new length...
      if (my $tail= ($data->len & $smask)) {
         # also ends with an unaligned write
         my $sdat= $secN * $sz >= $data_size? secret(length => $sz)
                 : $self->read($secN * $sz, $sz)->copy;
         $sdat->splice(0, $tail, $data->subspan(-$tail));
         Crypt::MultiKey::symmetric_encrypt({
               cipher      => $self->cipher,
               sector_size => $sz,
               sector_idx  => $secN,
            }, $skey, $sdat, $sdat); # inplace within $sdat
         _write_ofs_data($fh, $data_ofs + $secN * $sz, $sdat);
         $data->lim($data->lim - $tail);
      }
      if ($data->len) {
         my $buf= Crypt::MultiKey::symmetric_encrypt({
               cipher      => $self->cipher,
               sector_size => $sz,
               sector_idx  => $sec0,
            }, $skey, $data);
         _write_ofs_data($fh, $self->data_offset + $sec0 * $sz, $buf);
      }
   } else {
      # Staging data before first save.  Save unencrypted into 1MiB buffers.
      # The buffers array can be sparse.  This can also enlarge the overall
      # data size if writing beyond the end.
      my $bufs= ($self->{_data} //= []);
      my $idx= $ofs >> STAGING_BUFFER_SHIFT;
      my $buf_ofs= $ofs & STAGING_BUFFER_MASK;
      while ($data->len) {
         my $segment= $data;
         $segment= $segment->clone(len => STAGING_BUFFER_SIZE - $buf_ofs)
            if $buf_ofs + $data->len > STAGING_BUFFER_SIZE;
         my $buf= ($bufs->[$idx] //= secret(length => STAGING_BUFFER_SIZE));
         $buf->splice($buf_ofs, $segment->len, $segment);
         $data->pos($data->pos + $segment->len);
         $idx++;
         $buf_ofs= 0;
      }
      $self->{data_size}= $lim if $lim > $self->{data_size};
   }
   $self;
}

sub _write_ofs_data {
   my ($fh, $ofs, $data)= @_;
   my $at= sysseek($fh, $ofs, Fcntl::SEEK_SET()) // croak "seek: $!";
   unless ($at == $ofs) {
      # writing beyond the end of the file? enlarge it first
      $at= sysseek($fh, 0, Fcntl::SEEK_END()) // croak "seek: $!";
      if ($at < $ofs) {
         truncate($fh, $ofs)
            or croak "Failed to resize file: $!";
      }
      $at= sysseek($fh, $ofs, Fcntl::SEEK_SET()) // croak "seek: $!";
      $at == $ofs or croak "seek returned wrong address";
   }
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
         $wr > 0 or croak "write returned 0";
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
   encode_base64 decode_base64 max
   blessed looks_like_number basename
   secret span HEX BASE64 ISO8859_1 )};
