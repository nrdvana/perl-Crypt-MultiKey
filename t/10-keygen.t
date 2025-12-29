use FindBin;
use lib "$FindBin::Bin/lib";
use Test2AndUtils;
use Crypt::MultiKey::PKey;

is( Crypt::MultiKey::PKey->generate('x25519'),
   object {
      call type => 'x25519';
      call sub { $_[0]->_export_pubkey(my $buf); length $buf }, 44;
   },
   'x25519');

is( Crypt::MultiKey::PKey->generate('RSA'),
   object {
      call type => 'RSA';
      call sub { $_[0]->_export_pubkey(my $buf); length $buf }, within(550,5);
   },
   'RSA');

is( Crypt::MultiKey::PKey->generate('RSA2048'),
   object {
      call type => 'RSA:bits=2048';
      call sub { $_[0]->_export_pubkey(my $buf); length $buf }, within(294,5);
   },
   'RSA:bits=2048');

is( Crypt::MultiKey::PKey->generate('secp256k1'),
   object {
      call type => 'EC:group=secp256k1';
      call sub { $_[0]->_export_pubkey(my $buf); length $buf }, 88;
   },
   'secp256k1');

done_testing;
