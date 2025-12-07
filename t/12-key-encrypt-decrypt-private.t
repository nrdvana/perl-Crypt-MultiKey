use FindBin;
use lib "$FindBin::Bin/lib";
use Test2AndUtils;
use Crypt::MultiKey::PKey;

sub str_of_len {
   my $len= shift;
   return validator(sub{ length $_ == $len; });
}

for (qw( x25519 RSA:bits=1024 )) {
   subtest $_ => sub {
      my $key= Crypt::MultiKey::PKey->new(type => $_);
      ok( $key->_validate_private, 'validate private' );
      $key->encrypt_private("password", 99);
      ok( length $key->private_pkcs8, 'private_pkcs8 defined' );
      $key->clear_private;
      ok( !eval { $key->_validate_private; 1 }, 'missing private' );
      my $enc= $key->encrypt("Example Secret");
      ok( !eval { $key->decrypt($enc); 1 }, "can't decrypt secret" );
      $key->decrypt_private("password");
      ok( $key->_validate_private, 'private key restored' );
      my $secret= $key->decrypt($enc);
      my $decrypted;
      $secret->span->copy_to($decrypted);
      is($decrypted, 'Example Secret', 'able to decrypt secret');
   };
}

done_testing;
