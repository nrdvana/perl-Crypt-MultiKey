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

is( Crypt::MultiKey::PKey->generate('ed25519'),
   object {
      call algorithm => 'ED25519';
      call sub { length decode_base64($_[0]->public) }, 44;
   },
   'ed25519');

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

{
   my $mlkem = eval { Crypt::MultiKey::PKey->generate('ML-KEM-768') };
   if ($mlkem) {
      is( $mlkem,
         object {
            call algorithm => 'ML-KEM-768';
            call sub { length decode_base64($_[0]->public) }, within(1400, 300);
         },
         'ML-KEM-768');

      is( Crypt::MultiKey::PKey->generate('ml-kem-768'),
         object {
            call algorithm => 'ML-KEM-768';
            call sub { length decode_base64($_[0]->public) }, within(1400, 300);
         },
         'ml-kem-768');
   }
   else {
      like( dies { Crypt::MultiKey::PKey->generate('ML-KEM-768') },
         qr/OpenSSL 3\.5 or newer/i,
         'ML-KEM-768 reports OpenSSL requirement when unsupported');
      like( dies { Crypt::MultiKey::PKey->generate('ml-kem-768') },
         qr/OpenSSL 3\.5 or newer/i,
         'ml-kem-768 reports OpenSSL requirement when unsupported');
   }
}

done_testing;
