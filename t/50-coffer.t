use FindBin;
use lib "$FindBin::Bin/lib";
use Test2AndUtils;
use File::Temp;
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
   ok( $c->unlock($key), 'unlock' );
   ok( $c->decrypt, 'decrypt' );
   is( $c->content->memcmp($data), 0, 'secret matches' );
};

subtest save_load_unlock => sub {
   my $data= "Testing 2 3 4";
   my $tmpdir= File::Temp->newdir;
   my $key= Crypt::MultiKey::PKey->generate;
   my $c= Crypt::MultiKey::Coffer->new(
      name => "Example",
      user_meta => { a => 1, b => [ 1, 2, 3 ] },
      content => $data,
      content_type => 'text/plain'
   );
   ok( $c->add_access($key), 'add_access' );
   ok( $c->save("$tmpdir/coffer.pem"), 'save' );
   my $slurp= do { local $/; open my $fh, '<', "$tmpdir/coffer.pem" or die; <$fh> or die; };
   note $slurp;
   is( my $c2= Crypt::MultiKey::Coffer->load("$tmpdir/coffer.pem"),
      object {
         call name => 'Example';
         call user_meta => {
            name => "Example",
            a => 1,
            b => [ 1, 2, 3 ],
         };
         call unlocked => F;
         call has_content => F;
         call has_ciphertext => T;
      }
   );
   ok( $c2->unlock($key), 'unlock' );
   #note explain $c2;
   is( $c2->content->memcmp($data), 0, 'content matches' );
};

done_testing;
