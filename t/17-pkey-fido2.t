use strict;
use warnings;
use Test2::V0;

use lib 'lib';
use Crypt::SecretBuffer qw( secret );
use Crypt::MultiKey::PKey;
use Crypt::MultiKey::PKey::FIDO2;

sub mock_list_devices {
   return [ { path => '/dev/hidraw-fido0' }, { path => '/dev/hidraw-fido1' } ];
}

sub mock_make_credential {
   my ($path, $name)= @_;
   is($path, '/dev/hidraw-fido0', 'credential creation uses selected path');
   is($name, 'test-credential', 'credential creation uses configured name');
   return secret("\x01\x02\x03\x04");
}

sub mock_chalresp {
   my ($path, $challenge, $cred_id)= @_;
   is($path, '/dev/hidraw-fido0', 'chalresp uses selected path');
   ok(ref($challenge), 'challenge is secret buffer');
   ok(ref($cred_id), 'credential id is secret buffer');
   return secret("\x55" x 32);
}

{
   no warnings 'redefine';
   local *Crypt::MultiKey::_have_fido2= sub { 1 };
   local *Crypt::MultiKey::_fido2_list_devices= \&mock_list_devices;
   local *Crypt::MultiKey::_fido2_make_credential= \&mock_make_credential;
   local *Crypt::MultiKey::_fido2_chalresp= \&mock_chalresp;

   my $key= Crypt::MultiKey::PKey->generate('x25519')->mechanism('FIDO2');
   $key->credential_name('test-credential');
   $key->create_credential('/dev/hidraw-fido0');

   is($key->fido2_path, '/dev/hidraw-fido0', 'stored fido2_path');
   ok($key->fido2_cred_id, 'stored fido2_cred_id');

   $key->encrypt_private;
   ok($key->kdf_salt, 'kdf_salt assigned after encrypt_private');

   my $msg= 'fido2 mechanism secret';
   my $enc= $key->encrypt($msg);
   $key->clear_private;
   ok($key->can_obtain_private, 'can_obtain_private true when device path present');
   $key->obtain_private;

   my $secret= $key->decrypt($enc);
   my $decrypted= '';
   $secret->span->copy_to($decrypted);
   is($decrypted, $msg, 'decrypt after obtain_private');
}

{
   my $key= Crypt::MultiKey::PKey->generate('x25519')->mechanism('FIDO2');
   $key->clear_private;
   $key->private_encrypted('AAAA');
   like(
      dies { $key->obtain_private },
      qr/Cannot obtain private key without fido2_path/,
      'obtain_private requires fido2_path',
   );
}

{
   no warnings 'redefine';
   local *Crypt::MultiKey::_have_fido2= sub { 0 };
   my $key= Crypt::MultiKey::PKey->generate('x25519')->mechanism('FIDO2');
   like(
      dies { $key->create_credential },
      qr/FIDO2 support not available/,
      'create_credential fails when fido2 unavailable',
   );
}

done_testing;
