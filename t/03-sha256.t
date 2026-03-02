use FindBin;
use lib "$FindBin::Bin/lib";
use Test2AndUtils;
use Crypt::SecretBuffer qw( secret );
use Digest::SHA qw( sha256 );
use Crypt::MultiKey;

subtest sha256 => sub {
   for (
      [ "test" ],
      [ "test", "test2" ],
      [ "", "\0", "\x01" ],
   ) {
      my $buf= Crypt::MultiKey::sha256(@$_);
      my $expect= sha256(join '', @$_);
      $buf->unmask_to(sub { is( $_[0], $expect ); });
   }
};

subtest hmac_sha256 => sub {
   my $key= secret(append_random => 32);
   is( my $mac1= Crypt::MultiKey::hmac_sha256($key, "one two three"),
       object {
         call length => 32;
       });
   is( my $mac2= Crypt::MultiKey::hmac_sha256($key, "one ", "two three"),
       object {
         call length => 32;
         call [ memcmp => $mac1 ] => 0;
       },
       'generated from fragments' );
};

done_testing;
