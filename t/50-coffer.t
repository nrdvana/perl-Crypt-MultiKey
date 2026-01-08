use FindBin;
use lib "$FindBin::Bin/lib";
use Test2AndUtils;
use Crypt::SecretBuffer qw( secret );
use Crypt::MultiKey::Coffer;

subtest ctor => sub {
   ok( my $c= Crypt::MultiKey::Coffer->new() );
};

done_testing;
