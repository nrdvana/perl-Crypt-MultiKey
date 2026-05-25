use FindBin;
use lib "$FindBin::Bin/lib";
use Test2AndUtils;
use File::Temp;
use Crypt::SecretBuffer qw( secret );
use Crypt::MultiKey qw( coffer new_coffer load_coffer );
use Crypt::MultiKey::Coffer;

subtest ctor => sub {
   is( new_coffer(),
      object {
         call has_content => F;
         call has_ciphertext => F;
         call locked => F;
         call initialized => F;
         call locks => [];
         call content_type => undef;
         call content => undef;
      },
      'empty coffer'
   );
   is( coffer(content => "abc"),
      object {
         call has_content => T;
         call has_ciphertext => F;
         call locked => F;
         call initialized => T;
         call content_type => undef;
         call content => object { call [ memcmp => "abc" ], 0; };
      },
      'coffer with initial content'
   );
   is( Crypt::MultiKey::Coffer->new(content => [ a => 1, b => "x" ]),
      object {
         call has_content => T;
         call has_ciphertext => F;
         call locked => F;
         call initialized => T;
         call content_type => 'application/crypt-multikey-coffer-dict';
         call [ get => 'a' ] => object { call [ memcmp => 1 ], 0; };
         call [ get => 'b' ] => object { call [ memcmp => 'x' ], 0; };
      },
      'coffer with initial dict-like content arrayref'
   );
   is( Crypt::MultiKey::Coffer->new(content => { a => 1, b => "x" }),
      object {
         call has_content => T;
         call has_ciphertext => F;
         call locked => F;
         call initialized => T;
         call content_type => 'application/crypt-multikey-coffer-dict';
         call [ get => 'a' ] => object { call [ memcmp => 1 ], 0; };
         call [ get => 'b' ] => object { call [ memcmp => 'x' ], 0; };
      },
      'coffer with initial dict-like content hashref'
   );
};

subtest dict_names => sub {
   my $c= Crypt::MultiKey::Coffer->new;
   $c->set('alpha', 'a');
   $c->set('alphabet', 'ab');
   $c->set('beta', 'b');
   is( [ $c->list_names_plaintext('alpha') ], ['alpha'], 'exact name match' );
   is( [ $c->list_names_plaintext('alp', Crypt::MultiKey::Coffer::LIST_NAMES_PREFIX) ],
      [ 'alpha', 'alphabet' ],
      'prefix name matches'
   );
   is( $c->get('alphabet')->memcmp('ab'), 0, 'get by name' );
   $c->set('alpha', undef);
   is( [ $c->list_names_plaintext('alp', Crypt::MultiKey::Coffer::LIST_NAMES_PREFIX) ],
      [ 'alphabet' ],
      'delete updates index'
   );
   is( [ $c->list_names('alp', Crypt::MultiKey::Coffer::LIST_NAMES_PREFIX) ],
      array {
         item object { call [ memcmp => 'alphabet' ], 0; };
         end;
      },
      'list_names returns spans by default'
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
   {
      my $key= Crypt::MultiKey::PKey->generate;
      my $c= Crypt::MultiKey::Coffer->new(
         name => "Example",
         user_meta => { a => 1, b => [ 1, 2, 3 ] },
         content => $data,
         content_type => 'text/plain'
      );
      ok( $c->add_access($key), 'add_access' );
      ok( $c->save("$tmpdir/coffer.pem"), 'save coffer' );
      $key->encrypt_private('keypassword');
      ok( $key->save("$tmpdir/key.pem"), 'save key' );
   }
   my $slurp= do { local $/; open my $fh, '<', "$tmpdir/coffer.pem" or die; <$fh> or die; };
   note $slurp;
   is( my $c2= load_coffer("$tmpdir/coffer.pem"),
      object {
         call name => 'Example';
         call user_meta => {
            name => "Example",
            a => 1,
            b => [ 1, 2, 3 ],
         };
         call locked => T;
         call has_content => F;
         call has_ciphertext => T;
      }
   );
   my $key= Crypt::MultiKey::PKey->load("$tmpdir/key.pem");
   ok( $key->has_public, 'public loaded' );
   $key->decrypt_private('keypassword');
   ok( $key->has_private, 'private loaded' );
   ok( $c2->unlock($key), 'unlock' );
   #note explain $c2;
   is( $c2->content->memcmp($data), 0, 'content matches' );
};


subtest bundled_keys => sub {
   my $tmpdir= File::Temp->newdir;
   my $path= "$tmpdir/coffer.pem";
   my $key= Crypt::MultiKey::PKey->generate;
   $key->encrypt_private('secret-passphrase');

   my $c= Crypt::MultiKey::Coffer->new(
      path => $path,
      bundled_keys => 1,
      content => 'bundled data',
      content_type => 'text/plain',
   );
   $c->add_access($key);
   ok( $c->save, 'save coffer with bundled key' );

   my $c2= Crypt::MultiKey::Coffer->load($path, bundled_keys => 1);
   my $tmbl_key= $c2->locks->[0]{tumblers}[0]{key};
   ok( $tmbl_key, 'bundled key parsed after coffer PEM' );
   ok( $tmbl_key->decrypt_private('secret-passphrase'), 'decrypt bundled private key' );
   ok( $c2->unlock(), 'unlock using bundled key object' );
   is( $c2->content->memcmp('bundled data'), 0, 'bundled-key coffer content readable' );
};

done_testing;
