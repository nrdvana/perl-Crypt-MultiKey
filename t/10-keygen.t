use FindBin;
use lib "$FindBin::Bin/lib";
use Test2AndUtils;
use MIME::Base64;
use Crypt::MultiKey::PKey;

is( Crypt::MultiKey::PKey->generate('x25519'),
   object {
      call algorithm => 'X25519';
      call sub { length decode_base64($_[0]->public) }, 44;
   },
   'x25519');

is( Crypt::MultiKey::PKey->generate('RSA'),
   object {
      call algorithm => 'RSA:bits=4096';
      call sub { length decode_base64($_[0]->public) }, within(550,5);
   },
   'RSA');

is( Crypt::MultiKey::PKey->generate('RSA2048'),
   object {
      call algorithm => 'RSA:bits=2048';
      call sub { length decode_base64($_[0]->public) }, within(294,5);
   },
   'RSA:bits=2048');

is( Crypt::MultiKey::PKey->generate('secp256k1'),
   object {
      call algorithm => 'EC:curve=secp256k1';
      call sub { length decode_base64($_[0]->public) }, 88;
   },
   'secp256k1');

done_testing;
