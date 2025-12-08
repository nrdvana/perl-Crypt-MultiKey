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
      my $key= Crypt::MultiKey::PKey->new(type => $_);
      $key->encrypt_private("password", 99);
      like( $key->{private_encrypted}, qr{^[a-zA-Z0-9./=]+\z}, 'private_encrypted created' );
      ok( $key->has_private_loaded, 'has_private_loaded is true' );
      $key->clear_private;
      ok( !$key->has_private_loaded, 'has_private_loaded is false' );
      my $enc= $key->encrypt("Example Secret");
      ok( !eval { $key->decrypt($enc); 1 }, "can't decrypt secret" );
      $key->decrypt_private("password");
      ok( $key->has_private_loaded, 'has_private_loaded is true' );
      my $secret= $key->decrypt($enc);
      my $decrypted;
      $secret->span->copy_to($decrypted);
      is($decrypted, 'Example Secret', 'able to decrypt secret');
   };
}

done_testing;
