use FindBin;
use lib "$FindBin::Bin/lib";
use Test2AndUtils;
use Crypt::MultiKey::PKey;

sub str_of_len {
   my $len= shift;
   return validator(sub{ length $_ == $len; });
}

for (qw( x25519 RSA:bits=1024 secp256k1 )) {
   subtest $_ => sub {
      my $key= Crypt::MultiKey::PKey->generate($_);
      $key->encrypt_private("password", 99);
      like( $key->{private_encrypted}, qr{^\x30}s, 'private_encrypted PKCS#8 DER created' );
      ok( $key->has_private, 'has_private_loaded is true' );
      note "call ->clear_private";
      $key->clear_private;
      ok( !$key->has_private, 'has_private_loaded is false' );
      my $enc= $key->encrypt("Example Secret");
      note "encrypted secret";
      ok( !eval { $key->decrypt($enc); 1 }, "can't decrypt secret" );
      note "call ->decrypt_private";
      $key->decrypt_private("password");
      ok( $key->has_private, 'has_private_loaded is true' );
      my $secret= $key->decrypt($enc);
      my $decrypted;
      $secret->span->copy_to($decrypted);
      is($decrypted, 'Example Secret', 'able to decrypt secret');
   };
}

done_testing;
