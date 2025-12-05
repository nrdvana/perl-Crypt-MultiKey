use FindBin;
use lib "$FindBin::Bin/lib";
use Test2AndUtils;
use Crypt::MultiKey::Key;

is( Crypt::MultiKey::Key->new(type => 'x25519'),
   object {
      call type => 'x25519';
      call sub { length $_[0]->public }, 44;
      call private => object { call length => 48; };
   },
   'x25519');

is( Crypt::MultiKey::Key->new(type => 'RSA'),
   object {
      call type => 'RSA';
      call sub { length $_[0]->public }, within(550,5);
      call private => object { call length => within(2348, 10); };
   },
   'RSA');

is( Crypt::MultiKey::Key->new(type => 'RSA:bits=2048'),
   object {
      call type => 'RSA:bits=2048';
      call sub { length $_[0]->public }, within(294,5);
      call private => object { call length => within(1191, 10); };
   },
   'RSA:bits=2048');

done_testing;
