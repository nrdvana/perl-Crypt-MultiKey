use FindBin;
use lib "$FindBin::Bin/lib";
use Test2AndUtils;
use File::Temp;
use File::Spec;
use Crypt::SecretBuffer qw( secret );
use Crypt::MultiKey qw( vault new_vault load_vault );
use Crypt::MultiKey::Vault;
use Crypt::MultiKey::PKey;

# Verify the default constructor geometry for a brand-new Vault.
# This catches accidental changes to the sector size, data offset, or initial
# data length that many later tests assume.
subtest ctor => sub {
   is( new_vault(),
      object {
         call sector_size => 512;
         call data_offset => 65536;
         call data_size => 0;
      },
      'empty vault'
   );
};

# Exercise the basic lifecycle: stage data, save a new file, load it back, and
# unlock it with the key.  Then update only metadata to verify the fast in-place
# header rewrite path preserves encrypted data and padding.
subtest save_open_and_patch_header => sub {
   my $tmpdir= File::Temp->newdir;
   my $path= "$tmpdir/vault.dat";
   my $key= Crypt::MultiKey::PKey->generate;
   my $v= new_vault(
      path => $path,
      name => 'Primary Vault',
      user_meta => { role => 'test' },
   );
   ok( $v->add_access($key), 'add_access' );
   ok( $v->write(3, secret("hello world")), 'write staged' );
   ok( $v->save, 'first save' );
   ok( -f $path, 'file created' );

   my $v2= load_vault(path => $path);
   is( $v2->locked, T, 'opened vault is locked' );
   ok( $v2->unlock($key), 'unlock opened vault' );
   is( $v2->locked, F, 'unlocked vault is not locked' );
   ok( $v2->lock, 'lock opened vault' );
   is( $v2->locked, T, 'vault lock method clears the primary key' );
   ok( $v2->unlock($key), 'unlock opened vault again' );
   is( $v2->read(3, 11)->copy->memcmp("hello world"), 0, 'read/write round trip' );

   $v2->name('Updated Name');
   ok( $v2->save(), 'in-place header patch' );
   is( $v2->read(3, 11)->copy->memcmp("hello world"), 0, 'data preserved after patch save' );
   my $bytes= slurp($path);
   like( $bytes, qr/^\0===== Crypt::MultiKey::Vault =====\nversion: /, 'vault uses JSON header marker' );
   is( substr($bytes, $v2->data_offset - 33, 1), "\n", 'newline padding until HMAC' );
};

# Save a Vault to one file and then rewrite it to a new path while changing
# geometry options.  This verifies rewrite state updates and confirms plaintext
# survives the copy to the replacement file.
subtest save_to_new_path_with_overrides => sub {
   my $tmpdir= File::Temp->newdir;
   my $path1= "$tmpdir/vault-a.dat";
   my $path2= "$tmpdir/vault-b.dat";
   my $key= Crypt::MultiKey::PKey->generate;

   my $v= vault(path => $path1);
   $v->add_access($key);
   $v->write(0, secret("abcdefghijklmno"));
   $v->save;

   ok( $v->save(path => $path2, sector_size => 1024, data_offset => 65536), 'save to new path' );
   ok( -f $path1, 'old file still exists' );
   ok( -f $path2, 'new file exists' );
   is( $v->path, $path2, 'path now points at new file' );
   is( $v->sector_size, 1024, 'sector size overridden' );

   my $v2= load_vault(path => $path2);
   $v2->unlock($key);
   is( $v2->read(0, 15)->copy->memcmp("abcdefghijklmno"), 0, 'content moved to new file' );
};


# Cover the unsaved in-memory staging array before the Vault has a file handle.
# Writes are sparse and unaligned, including one spanning the internal staging
# buffer boundary, and then verified both before and after save/load.
subtest staged_sparse_unaligned_writes => sub {
   my $tmpdir= File::Temp->newdir;
   my $path= "$tmpdir/vault.dat";
   my $key= Crypt::MultiKey::PKey->generate;
   my $chunk_size= Crypt::MultiKey::Vault::STAGING_BUFFER_SIZE();
   my $tail= 'tail-data';

   my $v= Crypt::MultiKey::Vault->new(path => $path);
   $v->add_access($key);

   # Exercise sparse staging buffers with writes before, across, and after a 4 MiB boundary.
   $v->write(7, secret('hello'));
   $v->write($chunk_size - 3, secret('ABCDEF'));
   $v->write($chunk_size + 2048, secret($tail));

   is( $v->data_size, $chunk_size + 2048 + length($tail), 'staged data_size tracks high sparse write' );
   is( $v->read(0, 16)->copy->memcmp("\0" x 7 . 'hello' . "\0" x 4), 0,
      'leading unaligned staged write is readable with zero fill' );
   is( $v->read($chunk_size - 8, 16)->copy->memcmp("\0" x 5 . 'ABCDEF' . "\0" x 5), 0,
      'staged write crossing sparse buffer boundary is readable' );
   is( $v->read($chunk_size + 2048, length($tail))->copy->memcmp($tail), 0,
      'later sparse staged write is readable' );

   $v->save;

   my $v2= Crypt::MultiKey::Vault->load(path => $path);
   ok( $v2->unlock($key), 'unlock saved sparse vault' );
   is( $v2->read(0, 16)->copy->memcmp("\0" x 7 . 'hello' . "\0" x 4), 0,
      'leading staged write survived save' );
   is( $v2->read($chunk_size - 8, 16)->copy->memcmp("\0" x 5 . 'ABCDEF' . "\0" x 5), 0,
      'boundary staged write survived save' );
   is( $v2->read($chunk_size + 2048, length($tail))->copy->memcmp($tail), 0,
      'later sparse staged write survived save' );
};

# Rewrite an existing Vault while changing the encryption sector size upward and
# then downward.  The checks make sure re-encryption preserves data around an
# unaligned patch and also preserves data near the tail.
subtest sector_size_rewrite_grow_and_shrink => sub {
   my $tmpdir= File::Temp->newdir;
   my $path512= "$tmpdir/vault-512.dat";
   my $path4096= "$tmpdir/vault-4096.dat";
   my $path1024= "$tmpdir/vault-1024.dat";
   my $key= Crypt::MultiKey::PKey->generate;
   my $payload= 'x' x 10000;

   my $v= Crypt::MultiKey::Vault->new(path => $path512, sector_size => 512);
   $v->add_access($key);
   $v->write(0, secret($payload));
   $v->write(513, secret('unaligned-middle'));
   $v->save;

   ok( $v->save(path => $path4096, sector_size => 4096), 'rewrite vault with larger sector size' );
   is( $v->sector_size, 4096, 'sector size grew' );
   is( $v->read(500, 40)->copy->memcmp(('x' x 13) . 'unaligned-middle' . ('x' x 11)), 0,
      'rewritten larger-sector vault preserves unaligned plaintext' );

   my $larger= Crypt::MultiKey::Vault->load(path => $path4096);
   ok( $larger->unlock($key), 'unlock larger-sector rewrite' );
   is( $larger->sector_size, 4096, 'larger-sector header loads' );
   is( $larger->read(0, 64)->copy->memcmp('x' x 64), 0,
      'larger-sector rewrite preserves leading plaintext' );
   is( $larger->read(513, 16)->copy->memcmp('unaligned-middle'), 0,
      'larger-sector rewrite preserves patched plaintext' );

   ok( $larger->save(path => $path1024, sector_size => 1024), 'rewrite vault with smaller sector size' );
   is( $larger->sector_size, 1024, 'sector size shrank' );

   my $smaller= Crypt::MultiKey::Vault->load(path => $path1024);
   ok( $smaller->unlock($key), 'unlock smaller-sector rewrite' );
   is( $smaller->sector_size, 1024, 'smaller-sector header loads' );
   is( $smaller->read(513, 16)->copy->memcmp('unaligned-middle'), 0,
      'smaller-sector rewrite preserves patched plaintext' );
   is( $smaller->read(9000, 128)->copy->memcmp('x' x 128), 0,
      'smaller-sector rewrite preserves trailing plaintext' );
};

# Cover less common file-shape paths: writing a preamble before the Vault marker,
# loading through an already-open file handle, and resizing a saved Vault so the
# rounded/truncated data size matches the resulting file size.
subtest preamble_handle_and_resize_edges => sub {
   my $tmpdir= File::Temp->newdir;
   my $path= "$tmpdir/vault.dat";
   my $key= Crypt::MultiKey::PKey->generate;
   my $preamble= "#!/bin/sh\nexec false\n";

   my $v= Crypt::MultiKey::Vault->new(path => $path, file_preamble => $preamble);
   $v->add_access($key);
   $v->write(0, secret('resize-data'));
   $v->resize(3000);
   is( $v->data_size, 3072, 'unsaved resize rounds up to sector size' );
   $v->save;
   like( slurp($path), qr/^\Q$preamble\E\0===== Crypt::MultiKey::Vault =====\n/, 'file preamble saved before marker' );

   open my $fh, '+<:raw', $path or die "open($path): $!";
   my $v2= Crypt::MultiKey::Vault->load(handle => $fh);
   ok( $v2->unlock($key), 'unlock vault loaded from handle' );
   is( $v2->read(0, 11)->copy->memcmp('resize-data'), 0, 'handle-loaded vault reads data' );

   $v2->resize(1000);
   is( $v2->data_size, 1024, 'saved resize shrink rounds up to sector size' );
   is( -s $path, $v2->data_offset + 1024, 'saved resize shrink truncates file' );
};

sub _command_in_path {
   my ($name)= @_;
   for my $dir (File::Spec->path) {
      my $path= File::Spec->catfile($dir, $name);
      return $path if -x $path;
   }
   return;
}

# Integration coverage for using a raw Linux block device as the Vault storage.
# The test creates a loop device, opens that block device directly, saves a Vault
# on the handle, and reloads it from a fresh block-device handle.
subtest linux_block_device_handle_vault => sub {
   skip_all 'block-device handle test requires Linux loopback devices'
      unless $^O eq 'linux';
   skip_all 'block-device handle test requires root privileges to create loopback devices'
      unless $> == 0;
   skip_all 'block-device handle test requires losetup in PATH'
      unless _command_in_path('losetup');

   my $loop_probe= qx(losetup --find 2>/dev/null);
   skip_all 'block-device handle test requires an available loopback device'
      unless defined $loop_probe && $loop_probe =~ m{^/dev/loop}m;

   my $tmp= File::Temp->new;
   my $tmpname= "$tmp";
   my $loopdev;
   my $err= eval {
      truncate($tmp, 1024 * 1024)
         or die "truncate($tmpname): $!";
      $tmp->flush
         or die "flush($tmpname): $!";

      open my $losetup, '-|', 'losetup', '--find', '--show', '--', $tmpname
         or die "open losetup pipe failed: $!";
      $loopdev= <$losetup>;
      close($losetup) or die "losetup failed";
      defined($loopdev) && length($loopdev)
         or die "losetup did not return a device";
      chomp($loopdev);
      ok( -b $loopdev, 'created loopback block device' );

      my $key= Crypt::MultiKey::PKey->generate;
      my $payload= 'vault-on-block-device';

      open my $block_fh, '+<:raw', $loopdev
         or die "open($loopdev): $!";
      my $v= Crypt::MultiKey::Vault->new(handle => $block_fh);
      $v->add_access($key);
      ok( $v->save, 'saved new vault header directly to block-device handle' );
      ok( $v->write(123, secret($payload)), 'wrote vault data through block-device handle' );
      close($block_fh) or die "close($loopdev): $!";

      open my $read_fh, '+<:raw', $loopdev
         or die "open($loopdev): $!";
      my $loaded= Crypt::MultiKey::Vault->load(handle => $read_fh);
      ok( $loaded->unlock($key), 'unlocked vault loaded from block-device handle' );
      is( $loaded->read(123, length($payload))->copy->memcmp($payload), 0,
         'read data from vault stored directly on block device' );
      close($read_fh) or die "close($loopdev): $!";
      1;
   }? undef : $@;

   if (defined $loopdev) {
      system('losetup', '-d', $loopdev) == 0
         or warn "losetup -d $loopdev failed";
   }
   die $err if defined $err;
};

# Integration coverage for Vault->create_block_device and the dm-crypt mapping
# it creates from a normal Vault file.  When the environment has the needed Linux
# privileges and tools, reads and writes through /dev/mapper are compared to Vault IO.
subtest linux_block_device => sub {
   skip_all 'create_block_device currently only supports Linux'
      unless $^O eq 'linux';
   skip_all 'create_block_device test requires root privileges for loopback and dm-crypt setup'
      unless $> == 0;
   skip_all 'create_block_device test requires losetup in PATH'
      unless _command_in_path('losetup');
   skip_all 'create_block_device test requires dmsetup in PATH'
      unless _command_in_path('dmsetup');

   my $loop_probe= qx(losetup --find 2>/dev/null);
   skip_all 'create_block_device test requires an available loopback device'
      unless defined $loop_probe && $loop_probe =~ m{^/dev/loop}m;

   my $tmpdir= File::Temp->newdir;
   my $path= "$tmpdir/vault.dat";
   my $key= Crypt::MultiKey::PKey->generate;
   my $plaintext= ('0123456789ABCDEF' x 512);
   my $replacement= 'written-through-dmcrypt';
   my $mapname= sprintf 'cmk_vault_%d_%07X', $$, int(rand(0xFFFFFFF));
   my $mapdev;

   my $v= Crypt::MultiKey::Vault->new(path => $path, sector_size => 512);
   $v->add_access($key);
   $v->write(0, secret($plaintext));
   $v->resize(length($plaintext));
   $v->save;

   my $err= eval {
      my $loaded= Crypt::MultiKey::Vault->load(path => $path);
      ok( $loaded->unlock($key), 'unlock file-backed vault before mapping' );
      $mapdev= $loaded->create_block_device(name => $mapname);
      ok( -b $mapdev, 'mapped vault block device exists' );

      open my $rd, '<:raw', $mapdev or die "open($mapdev): $!";
      read($rd, my $block_data, length($plaintext)) == length($plaintext)
         or die "read($mapdev): $!";
      close $rd or die "close($mapdev): $!";
      is( $block_data, $plaintext, 'block device reads decrypted vault data' );

      open my $wr, '+<:raw', $mapdev or die "open($mapdev): $!";
      sysseek($wr, 123, 0) == 123 or die "seek($mapdev): $!";
      print {$wr} $replacement or die "write($mapdev): $!";
      close $wr or die "close($mapdev): $!";

      is( $loaded->read(123, length($replacement))->copy->memcmp($replacement), 0,
         'vault reads data written through mapped block device' );
      1;
   }? undef : $@;

   if (defined $mapdev) {
      system('dmsetup', 'remove', $mapname) == 0
         or warn "dmsetup remove $mapname failed";
   }
   die $err if defined $err;
};

# Force metadata growth beyond the reserved header area without providing a new
# path.  This verifies save() reports the required full rewrite instead of
# silently corrupting or truncating the existing file.
subtest patch_header_overflow_croaks => sub {
   my $tmpdir= File::Temp->newdir;
   my $path= "$tmpdir/vault.dat";
   my $key= Crypt::MultiKey::PKey->generate;
   my $v= Crypt::MultiKey::Vault->new(path => $path, data_offset => 1024);
   $v->add_access($key);
   $v->save;
   $v->user_meta->{oversized}= ('x' x 20000);
   like(
      dies { $v->save },
      qr/rewrite.*?header grows/,
      'save without path croaks when header no longer fits'
   );
};

# Tamper with the saved JSON header while leaving the rest of the file intact.
# Unlock must reject the modified header MAC so callers do not trust altered
# metadata or lock parameters.
subtest header_authentication => sub {
   my $tmpdir= File::Temp->newdir;
   my $path= "$tmpdir/vault.dat";
   my $key= Crypt::MultiKey::PKey->generate;

   my $v= Crypt::MultiKey::Vault->new(path => $path, user_meta => { role => 'test' });
   $v->add_access($key);
   $v->write(0, secret("authenticated data"));
   $v->save;

   my $bytes= slurp($path);
   substr($bytes, index($bytes, '"test"') + 1, 1)= 'T';
   mkfile($path, $bytes);

   my $v2= Crypt::MultiKey::Vault->load(path => $path);
   like(
      dies { $v2->unlock($key) },
      qr/Header MAC failed/,
      'unlock rejects a vault whose JSON header was modified'
   );
};

# Verify bundled PKey serialization in the Vault header.  The loaded Vault should
# recover the encrypted private key object, decrypt it with the passphrase, and
# unlock without the caller separately supplying the original key.
subtest bundled_keys => sub {
   my $tmpdir= File::Temp->newdir;
   my $path= "$tmpdir/vault.dat";
   my $key= Crypt::MultiKey::PKey->generate;
   $key->encrypt_private('secret-passphrase');

   my $v= Crypt::MultiKey::Vault->new(path => $path, bundled_keys => 1);
   $v->add_access($key);
   $v->write(0, secret("bundled data"));
   $v->save;

   my $v2= Crypt::MultiKey::Vault->load(path => $path, bundled_keys => 1);
   my $tmbl_key= $v2->locks->[0]{tumblers}[0]{key};
   ok( $tmbl_key, 'bundled key parsed from header area' );
   ok( $tmbl_key->decrypt_private('secret-passphrase'), 'decrypt bundled private key' );
   ok( $v2->unlock(), 'unlock using bundled key object' );
   is( $v2->read(0, 12)->copy->memcmp("bundled data"), 0, 'bundled-key vault content readable' );
};

done_testing;
