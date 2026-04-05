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

A Vault is defined in terms of a C<block_size>.  The header occupies an integer number of blocks
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
  block_size: 4096
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
  [binary data begins at a 4K and block_size boundary]

=cut

use strict;
use warnings;
use version;
use Carp;
use Fcntl ();
use Crypt::MultiKey;
use Crypt::MultiKey::LockMechanism;
use Scalar::Util qw/ blessed looks_like_number /;
use Crypt::SecretBuffer qw/ secret HEX BASE64 ISO8859_1 /;
use Crypt::SecretBuffer::PEM 0.020;

=attribute path

The path to the Vault file.

=attribute handle

Every Vault operates on a file handle, which is opened during construction and remains open
for block I/O.

=attribute cipher

Currently only C<AES-256-XTS> is supported.

=attribute block_size

The block size used for encrypting the file.  It must be a power of 2, and cannot be changed
after construction.  The default is 512.  Linux dm-crypt has a maximum of 4096.

=attribute data_offset

The byte offset at which data blocks begin.  This must be a multiple of 4096.  The default is
8192 which allows for a fairly large header.  Changing this value requires reconstruction of the
file.

=attribute size

The length in bytes of the data area.  e.g. file size minus header size.

=cut

sub path { $_[0]{path} }
sub handle { $_[0]{handle} }
sub cipher { 'AES-256-XTS' }
sub block_size { $_[0]{block_size} }
sub data_offset { $_[0]{data_offset} }

=constructor open

  $vault= Crypt::MultiKey::Vault->open(path => $x);
  $vault= Crypt::MultiKey::Vault->open(handle => $x);

=constructor create

  $vault= Crypt::MultiKey::Vault->create(path => $x);
  $vault= Crypt::MultiKey::Vault->create(handle => $x);

=cut

sub new {
   my $class= shift;
   bless {
      block_size => 512,
   }, $class;
}

sub _load {
   my $self= shift;
   
}

sub _generate_header {
   
}

=method resize

Extend or truncate the data region of the file.  This is just a call to 'truncate' on the
file handle, so it does not need to reconstruct the file.

=method read

Read (and decrypt) a region of the data area.  This does not need to be block-aligned, but is
more efficient when aligned.  Note that there is B<no integrity check> for data blocks.
If you reach the end of the file, the read will be truncated.  If you request from beyond the
end of the file it will return undef.

=method write

Write plaintext to a region of the data area.  This does not need to be block-aligned, but is
more efficient when aligned.  The file will be enlarged if you write beyond the end of the file.

=cut

sub resize {
   my ($self, $size)= @_;
   ...
}

sub read {
   my ($self, $ofs, $size)= @_;
   ...
}

sub write {
   my ($self, $ofs, $data)= @_;
   ...
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
   my $aes_key= $self->lock_mechanism->cipher_skey;
   # make sure handle is functioning
   my $length= sysseek($self->handle, 0, Fcntl::SEEK_END)
      // croak "seek: $!";
   croak "Corrupt vault"
      if $length < $self->data_offset;
   $length -= $self->data_offset;
   my $bs= $self->block_size;

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
      croak "Maximum block_size for Linux dm-crypt is 4096"
         if $bs > 4096;
      croak "Minimum block_size for Linux dm-crypt is 512"
         if $bs < 512;

      my @features;
      if ($bs > 512) {
         # For sector sizes larger than 512, iv_large_sectors makes plain64 set the
         # initialization vector to the block number in terms of encryption-sector units
         # rather than 512-byte units.
         push @features, "sector_size:$bs",
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
         open my $fh, '-|', 'losetup', '--find', '--show', '--', $path
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
         open(my $fh, '|-', 'dmsetup', 'create', $mapname, '--table', '-')
            or die "open dmsetup pipe failed: $!";
         binmode($fh, ':raw');
         my $ofs= 0;
         while ($ofs < $dmsetup_table->len) {
            my $wrote= $dmsetup_table->syswrite($fh, $dmsetup_table->len - $ofs, $ofs)
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

      if ($length >= $bs) {
         unless (eval {
            open my $dmh, '<:raw', $mapdev
               or die "open($mapdev): $!";
            my $s= secret;
            $s->sysread($dmh, $bs)
               // die "read($mapdev): $!";
            $s->memcmp($self->read(0, $bs)) == 0
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


1;
