use FindBin;
use lib "$FindBin::Bin/lib";
use Test2AndUtils;
use Crypt::MultiKey::Key;

subtest x25519 => sub {
   my $key= Crypt::MultiKey::Key->new(type => 'x25519');
   my $fields= $key->encrypt_secret("Test");
   is($fields,
      {
         encrypted => D,
         ephemeral_pubkey => D,
      },
      'encrypted fields' );
   my $secret= $key->decrypt_secret($fields);
   my $decrypted;
   $secret->span->copy_to($decrypted);
   is($decrypted, 'Test');
};

subtest rsa => sub {
   my $key= Crypt::MultiKey::Key->new(type => 'RSA:bits=1024'); # 1024 generates faster than 4096
   my $fields= $key->encrypt_secret("Test");
   is($fields,
      {
         encrypted => D,
      },
      'encrypted fields' );
   my $secret= $key->decrypt_secret($fields);
   my $decrypted;
   $secret->span->copy_to($decrypted);
   is($decrypted, 'Test');
};

done_testing;
