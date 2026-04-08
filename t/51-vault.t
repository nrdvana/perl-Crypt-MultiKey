use FindBin;
use lib "$FindBin::Bin/lib";
use Test2AndUtils;
use File::Temp;
use Crypt::SecretBuffer qw( secret );
use Crypt::MultiKey::Vault;
use Crypt::MultiKey::PKey;

subtest ctor => sub {
   is( Crypt::MultiKey::Vault->new(),
      object {
         call sector_size => 512;
         call data_offset => 65536;
         call data_size => 0;
      },
      'empty vault'
   );
};

subtest save_open_and_patch_header => sub {
   my $tmpdir= File::Temp->newdir;
   my $path= "$tmpdir/vault.dat";
   my $key= Crypt::MultiKey::PKey->generate;
   my $v= Crypt::MultiKey::Vault->new(
      path => $path,
      name => 'Primary Vault',
      user_meta => { role => 'test' },
   );
   ok( $v->add_access($key), 'add_access' );
   ok( $v->write(3, secret("hello world")), 'write staged' );
   ok( $v->save, 'first save' );
   ok( -f $path, 'file created' );

   my $v2= Crypt::MultiKey::Vault->open(path => $path);
   is( $v2->unlocked, F, 'opened vault is locked' );
   ok( $v2->unlock($key), 'unlock opened vault' );
   is( $v2->read(3, 11)->copy->memcmp("hello world"), 0, 'read/write round trip' );
   ok( $v2->authenticate(1), 'header auth validates' );

   $v2->name('Updated Name');
   ok( $v2->save(), 'in-place header patch' );
   is( $v2->read(3, 11)->copy->memcmp("hello world"), 0, 'data preserved after patch save' );
   my $bytes= slurp($path);
   is(
      substr($bytes, $v2->data_offset - 2, 2),
      "\n\0",
      'header ends with newline + NUL at data_start boundary'
   );
};

subtest save_to_new_path_with_overrides => sub {
   my $tmpdir= File::Temp->newdir;
   my $path1= "$tmpdir/vault-a.dat";
   my $path2= "$tmpdir/vault-b.dat";
   my $key= Crypt::MultiKey::PKey->generate;

   my $v= Crypt::MultiKey::Vault->new(path => $path1);
   $v->add_access($key);
   $v->write(0, secret("abcdefghijklmno"));
   $v->save;

   ok( $v->save(path => $path2, sector_size => 1024, data_offset => 65536), 'save to new path' );
   ok( -f $path1, 'old file still exists' );
   ok( -f $path2, 'new file exists' );
   is( $v->path, $path2, 'path now points at new file' );
   is( $v->sector_size, 1024, 'sector size overridden' );

   my $v2= Crypt::MultiKey::Vault->open(path => $path2);
   $v2->unlock($key);
   is( $v2->read(0, 15)->copy->memcmp("abcdefghijklmno"), 0, 'content moved to new file' );
};

subtest patch_header_overflow_croaks => sub {
   my $tmpdir= File::Temp->newdir;
   my $path= "$tmpdir/vault.dat";
   my $key= Crypt::MultiKey::PKey->generate;
   my $v= Crypt::MultiKey::Vault->new(path => $path, data_offset => 1024);
   $v->add_access($key);
   $v->save;
   $v->user_meta->{oversized}= ('x' x 20000);
   like(
      dies { $v->save },
      qr/Header does not fit in reserved area/,
      'save without path croaks when header no longer fits'
   );
};

subtest bundled_keys => sub {
   my $tmpdir= File::Temp->newdir;
   my $path= "$tmpdir/vault.dat";
   my $key= Crypt::MultiKey::PKey->generate;
   $key->encrypt_private('secret-passphrase');

   my $v= Crypt::MultiKey::Vault->new(path => $path, bundled_keys => 1);
   $v->add_access($key);
   $v->write(0, secret("bundled data"));
   $v->save;

   my $v2= Crypt::MultiKey::Vault->open(path => $path, bundled_keys => 1);
   my $tmbl_key= $v2->locks->[0]{tumblers}[0]{key};
   ok( $tmbl_key, 'bundled key parsed from header area' );
   ok( $tmbl_key->decrypt_private('secret-passphrase'), 'decrypt bundled private key' );
   ok( $v2->unlock(), 'unlock using bundled key object' );
   is( $v2->read(0, 12)->copy->memcmp("bundled data"), 0, 'bundled-key vault content readable' );
};

done_testing;
