use FindBin;
use lib "$FindBin::Bin/lib";
use Test2AndUtils;
use Crypt::SecretBuffer qw( secret );
use Crypt::MultiKey::Coffer;

subtest ctor => sub {
   is( Crypt::MultiKey::Coffer->new(),
      object {
         call has_content => F;
         call has_ciphertext => F;
         call aes_key => undef;
         call unlocked => F;
         call locks => [];
         call content_type => undef;
      },
      'empty coffer'
   );
   is( Crypt::MultiKey::Coffer->new(content => "abc"),
      object {
         call has_content => T;
         call has_ciphertext => F;
         call content_type => undef;
         call content => object { call [ memcmp => "abc" ], 0; };
      },
      'coffer with initial content'
   );
   is( Crypt::MultiKey::Coffer->new(content_kv => { a => 1, b => "x" }),
      object {
         call has_content => T;
         call has_ciphertext => F;
         call content_type => 'application/crypt-multikey-coffer-kv';
         call content_kv => {
            a => object { call [ memcmp => 1 ], 0; },
            b => object { call [ memcmp => 'x' ], 0; },
         };
      },
      'coffer with initial content_kv'
   );
};

subtest encrypt_lock_unlock_decrypt => sub {
   my $data= "Testing 1 2 3";
   my $key= Crypt::MultiKey::PKey->generate;
   my $c= Crypt::MultiKey::Coffer->new(content => $data, content_type => 'text/plain');
   ok( $c->add_access($key), 'add_access' );
   ok( $c->encrypt, 'encrypt' );
   ok( $c->lock, 'lock' );
   note explain $c->locks;
   ok( $c->unlock($key), 'unlock' );
   ok( $c->decrypt, 'decrypt' );
   is( $c->content->memcmp($data), 0, 'secret matches' );
};


done_testing;
