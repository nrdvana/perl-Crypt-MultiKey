use FindBin;
use lib "$FindBin::Bin/lib";
use Test2AndUtils;
use Crypt::SecretBuffer qw( secret );
use Digest::SHA qw( sha256 );
use Crypt::MultiKey;

for (
   [ "test" ],
   [ "test", "test2" ],
   [ "", "\0", "\x01" ],
) {
   my $buf= Crypt::MultiKey::sha256(@$_);
   my $expect= sha256(join '', @$_);
   $buf->unmask_to(sub { is( $_[0], $expect ); });
}

done_testing;
