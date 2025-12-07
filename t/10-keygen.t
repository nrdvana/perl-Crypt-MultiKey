use FindBin;
use lib "$FindBin::Bin/lib";
use Test2AndUtils;
use Crypt::MultiKey::PKey;

is( Crypt::MultiKey::PKey->new(type => 'x25519'),
   object {
      call type => 'x25519';
      call sub { length $_[0]->public }, 44;
      call private => object { call length => 48; };
   },
   'x25519');

is( Crypt::MultiKey::PKey->new(type => 'RSA'),
   object {
      call type => 'RSA';
      call sub { length $_[0]->public }, within(550,5);
      call private => object { call length => within(2348, 10); };
   },
   'RSA');

is( Crypt::MultiKey::PKey->new(type => 'RSA2048'),
   object {
      call type => 'RSA:bits=2048';
      call sub { length $_[0]->public }, within(294,5);
      call private => object { call length => within(1191, 10); };
   },
   'RSA:bits=2048');

is( Crypt::MultiKey::PKey->new(type => 'secp256k1'),
   object {
      call type => 'EC:group=secp256k1';
      call sub { length $_[0]->public }, 88;
      call private => object { call length => 118; };
   },
   'secp256k1');

done_testing;
