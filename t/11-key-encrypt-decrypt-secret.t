use FindBin;
use lib "$FindBin::Bin/lib";
use Test2AndUtils;
use Crypt::MultiKey::PKey;

sub str_of_len {
   my $len= shift;
   return validator(sub{ length $_ == $len; });
}

subtest x25519 => sub {
   my $key= Crypt::MultiKey::PKey->generate('x25519');
   my $fields= $key->encrypt("Test");
   is($fields,
      {
         cipher           => 'AES-256-GCM',
         ciphertext       => D,
         ephemeral_pubkey => D,
         kdf_salt         => str_of_len(32),
      },
      'encrypted fields' );
   my $secret= $key->decrypt($fields);
   my $decrypted;
   $secret->span->copy_to($decrypted);
   is($decrypted, 'Test');
};

subtest rsa => sub {
   my $key= Crypt::MultiKey::PKey->generate('RSA:bits=1024'); # 1024 for speed
   my $fields= $key->encrypt("Test");
   is($fields,
      {
         cipher             => 'AES-256-GCM',
         ciphertext         => D,
         rsa_key_ciphertext => D,
         kdf_salt           => str_of_len(32),
      },
      'encrypted fields' );
   my $secret= $key->decrypt($fields);
   my $decrypted;
   $secret->span->copy_to($decrypted);
   is($decrypted, 'Test');
};

done_testing;
