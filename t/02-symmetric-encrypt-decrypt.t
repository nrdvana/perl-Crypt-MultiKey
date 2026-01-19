use FindBin;
use lib "$FindBin::Bin/lib";
use Test2AndUtils;
use Crypt::SecretBuffer qw( secret );
use Crypt::MultiKey;

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
      Crypt::MultiKey::symmetric_encrypt(\%params, $aes_key, $s1);
      my $s2= Crypt::MultiKey::symmetric_decrypt(\%params, $aes_key);
      is( $s1->memcmp($s2), 0, "length=$len: s1 == s2" );
   }
};

subtest gcm_padding => sub {
   subtest 'all variable-length size encodings' => sub {
      skip_all 'TEST_CRYPT_MULTIKEY_EXHAUSTIVE is not set'
         unless $ENV{TEST_CRYPT_MULTIKEY_EXHAUSTIVE};
      skip_all 'TEST_CRYPT_MULTIKEY_EXHAUSTIVE was not set in Makefile during build'
         unless Crypt::MultiKey->can('_test_all_var_size_encodings');
      note 'This may take a while';
      Crypt::MultiKey::_test_all_var_size_encodings();
      pass('_test_all_var_size_encodings');
   };

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
      my %params= ( cipher => 'AES-256-GCM', pad_to => $len + 20 );
      Crypt::MultiKey::symmetric_encrypt(\%params, $aes_key, $s1);
      is( length $params{ciphertext}, 12 + $len + 20 + 16, 'length $ciphertext' );
      my $s2= Crypt::MultiKey::symmetric_decrypt(\%params, $aes_key);
      is( $s2->length, $len, "decoded length=$len" );
      is( $s1->memcmp($s2), 0, "s1 == s2" )
         or diag $s1->unmask_to(\&escape_nonprintable), "\n", $s2->unmask_to(\&escape_nonprintable);
   }
};

done_testing;
