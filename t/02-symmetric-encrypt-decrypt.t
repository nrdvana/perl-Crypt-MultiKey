use FindBin;
use lib "$FindBin::Bin/lib";
use Test2AndUtils;
use Crypt::SecretBuffer qw( secret span );
use Crypt::MultiKey;
use File::Temp;

sub str_of_len {
   my $len= shift;
   return validator(sub{ length $_ == $len; });
}

subtest gcm_no_padding => sub {
   my $aes_key= secret(append_random => 32);
   my @lengths= (0, 1, 7, 8, 9, 15, 16, 17, 31, 32, 33, 65535, 65536);
   if ($ENV{TEST_CRYPT_MULTIKEY_EXHAUSTIVE}) {
      @lengths= (0..1024, 65535, 65536);
      # Test 2GiB which is larger than 'INT_MAX' (EVP_EncryptUpdate uses int lengths)
      # This will use at least 6GiB of ram, for initial secret, encrypted, and decrypted.
      # Can't allocate that much unless compiled with 64 bit pointers.
      require Config;
      push @lengths, 0x80000000 if $Config::Config{sizesize} >= 8;
   }
   for my $len (@lengths) {
      my $s1= secret(append_random => $len);
      my %params= ( cipher => 'AES-256-GCM' );
      my $ciphertext= Crypt::MultiKey::symmetric_encrypt(\%params, $aes_key, $s1);
      is( length $ciphertext, $len + 30, 'length $ciphertext' );
      my $s2= Crypt::MultiKey::symmetric_decrypt(\%params, $aes_key, $ciphertext);
      is( $s1->memcmp($s2), 0, "length=$len: s1 == s2" );
   }
};

subtest gcm_padding => sub {
   my $aes_key= secret(append_random => 32);
   #define VARSIZE_1BYTE_LIM 0x80
   #define VARSIZE_2BYTE_LIM 0x4080
   #define VARSIZE_4BYTE_LIM 0x20004080
   #define VARSIZE_8BYTE_LIM 0x1000000020004080
   my @lengths= (0, 1, 7, 8, 9, 15, 16 );#, 17, 31, 32, 33, 0x80-1, 0x80, 0x4080-1, 0x4080 );
   if ($ENV{TEST_CRYPT_MULTIKEY_EXHAUSTIVE}) {
      @lengths= (0..0x4081, 0x20004080-1, 0x20004080, 0x2000408+1 );
      # Test 2GiB which is larger than 'INT_MAX' (EVP_EncryptUpdate uses int lengths)
      # This will use at least 6GiB of ram, for initial secret, encrypted, and decrypted.
      # Can't allocate that much unless compiled with 64 bit pointers.
      require Config;
      push @lengths, 0x80000000 if $Config::Config{sizesize} >= 8;
   }
   for my $len (@lengths) {
      my $s1= secret("x" x $len);
      my %params= ( cipher => 'AES-256-GCM', pad => $len + 200 );
      my $ciphertext= undef;
      Crypt::MultiKey::symmetric_encrypt(\%params, $aes_key, $s1, $ciphertext);
      is( length $ciphertext, $len + 200, 'length $ciphertext' );
      my $s2= Crypt::MultiKey::symmetric_decrypt(\%params, $aes_key, $ciphertext);
      is( $s2->length, $len, "decoded length=$len" );
      is( $s1->memcmp($s2), 0, "s1 == s2" )
         or diag $s1->unmask_to(\&escape_nonprintable), "\n", $s2->unmask_to(\&escape_nonprintable);
   }
};

subtest gcm_auth_data => sub {
   my $aes_key= secret(append_random => 32);
   my $s1= secret(append_random => 100);
   my %params= ( cipher => 'AES-256-GCM', auth_data => 'some context' );
   my $ciphertext= undef;
   Crypt::MultiKey::symmetric_encrypt(\%params, $aes_key, $s1, $ciphertext);
   my $s2= Crypt::MultiKey::symmetric_decrypt(\%params, $aes_key, $ciphertext);
   is( $s1->memcmp($s2), 0, "s1 == s2" );

   $params{auth_data}= 'tampered-with context';
   ok( !eval { $s2= Crypt::MultiKey::symmetric_decrypt(\%params, $aes_key, $ciphertext); 1 },
      'decrypt fails with tampered context' );
   delete $params{auth_data};
   ok( !eval { $s2= Crypt::MultiKey::symmetric_decrypt(\%params, $aes_key, $ciphertext); 1 },
      'decrypt fails with missing context' );
};

subtest gcm_inplace => sub {
   my $aes_key= secret(append_random => 32);
   my $plaintext= "inplace test payload";
   my %params= ( cipher => 'AES-256-GCM' );
   my $buf= secret($plaintext);
   $buf->append("\0" x 64);
   my $s_plain= span($buf)->subspan(0, length($plaintext));
   Crypt::MultiKey::symmetric_encrypt(\%params, $aes_key, $s_plain, $buf);
   my $s2= Crypt::MultiKey::symmetric_decrypt(\%params, $aes_key, $buf, $buf);
   is( $s2->length, length($plaintext), "decoded plaintext length" );
   is( $s2->memcmp($plaintext), 0, "decoded plaintext matches" );

   my %pad_params= ( cipher => 'AES-256-GCM', pad => 64 );
   ok( !eval { Crypt::MultiKey::symmetric_encrypt(\%pad_params, $aes_key, $buf, $buf); 1 },
      'inplace encryption rejects pad' );
};

subtest xts => sub {
   my $aes_key= secret(append_random => 64);
   my $s1= secret("0123456789ABCDEF" x 512);
   for my $block_size (512, 1024, 2048, 4096) {
      my %params= ( cipher => 'AES-256-XTS', sector_size => $block_size, sector_idx => 5 );
      my $ciphertext= undef;
      Crypt::MultiKey::symmetric_encrypt(\%params, $aes_key, $s1, $ciphertext);
      is( length $ciphertext, $s1->length, 'length $ciphertext' );

      my $s2= Crypt::MultiKey::symmetric_decrypt(\%params, $aes_key, $ciphertext);
      is( $s2->length, $s1->length, 'decode length' );
      is( $s2->memcmp($s1), 0, 's1 == s2' );

      # One of the main goals for Vault is to match the encryption of dm-crypt so that
      # it can be used for mounting filesystems.  Of course, this is hard to test because
      # it requires root and only works on Linux.  Also people need to opt-in to this
      # since it is messing around with loop devices.
      subtest "linux_dm_crypt_$block_size" => sub {
         skip_all "Requires Linux, root, and env variable TEST_CRYPT_MULTIKEY_DM_CRYPT"
            unless $^O eq 'linux' and $> == 0 and $ENV{TEST_CRYPT_MULTIKEY_DM_CRYPT};

         my $tmp= File::Temp->new;
         my $tmpname= "$tmp";
         
         # Backing file must exist at the target size before losetup/dmsetup
         truncate($tmp, $s1->length)
            or die "truncate($tmpname, ".$s1->length.") failed: $!";
         $tmp->flush or die "flush($tmpname) failed: $!";
         
         is(-s $tmpname, $s1->length, 'size of tmp file');
         
         my $loopdev;
         {
            open my $fh, '-|', 'losetup', '--find', '--show', $tmpname
               or die "open losetup pipe failed: $!";
            $loopdev= <$fh>;
            close($fh) or die "losetup failed";
            defined($loopdev) && length($loopdev)
               or die "losetup did not return a device";
            chomp($loopdev);
            -b $loopdev
               or die "not a block device: $loopdev";
         }
         note "loop device $loopdev";
         
         my $mapname= sprintf "cmk_test02_%s_%07X", $block_size, int(rand(0xFFFFFFF));
         my $mapdev= "/dev/mapper/$mapname";
         
         my $err;
         my $s_backing= secret;
         eval {
            my $key_hex;
            $aes_key->span->copy_to($key_hex, encoding => 'HEX');
         
            # despite changing "sector size", all offsets and lengths passed to dmcrypt
            # are in units of 512.
            my $length_512= int($s1->length / 512);
            $length_512 * 512 == $s1->length
               or die "plaintext length must be multiple of 512";
            note "length=$length_512";
         
            my $table= join ' ',
               0,                   # starting offset within devicemapper device
               $length_512,         # length within devicemapper device
               'crypt',
               'aes-xts-plain64',
               $key_hex,
               5*($block_size/512), # starting sector_idx offset, also measured in 512 units
               $loopdev,            # device
               0,                   # offset within device
               2,                   # feature count
               "sector_size:$block_size", # feature to change sector size (encryption block size)
               'iv_large_sectors';  # feature that uses sector number as -XTS IV
         
            note "dmsetup table: $table";
         
            system('dmsetup', 'create', $mapname, '--table', $table) == 0
               or die "dmsetup create failed (exit ".($? >> 8).")";
         
            -b $mapdev
               or die "mapped device not created: $mapdev";
         
            {
               open my $fh, '>:raw', $mapdev
                  or die "open($mapdev) for write failed: $!";
         
               my $off= 0;
               my $want= $s1->length;
               while ($off < $want) {
                  my $n= $s1->syswrite($fh, $want - $off, $off);
                  defined($n) or die "writing plaintext to $mapdev failed: $!";
                  $off += $n;
               }
               is($off, $want, 'wrote full plaintext through dm-crypt');
         
               close($fh)
                  or die "close($mapdev) failed: $!";
            }
            1;
         } or diag "Exception: $@";
         # Read the backing file after dm-crypt encrypted into it
         $s_backing->load_file($tmpname);
         is($s_backing->length, length($ciphertext), 'backing file length');
         is($s_backing->memcmp($ciphertext), 0, 'backing file ciphertext matches module ciphertext');

         system('dmsetup', 'remove', $mapname) == 0
            or warn "dmsetup remove $mapname failed";
         system('losetup', '-d', $loopdev) == 0
            or warn "losetup -d $loopdev failed";
      };
   }
};

done_testing;
