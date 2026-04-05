use FindBin;
use lib "$FindBin::Bin/lib";
use Test2AndUtils;
use File::Temp;
use Crypt::SecretBuffer qw( secret );
use Crypt::MultiKey::Vault;

subtest ctor => sub {
   is( Crypt::MultiKey::Vault->new(),
      object {
         call block_size => 512;
      },
      'empty vault'
   );
};

done_testing;
