use FindBin;
use lib "$FindBin::Bin/lib";
use Test2AndUtils;
use Crypt::MultiKey::Key;

ok( my $key= Crypt::MultiKey::Key->new(type => 'x25519'), 'x25519' );

done_testing;
