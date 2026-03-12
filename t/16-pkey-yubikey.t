use strict;
use warnings;
use Test2::V0;

use lib 'lib';
use Crypt::SecretBuffer qw( secret );
use Crypt::MultiKey::PKey;
use Crypt::MultiKey::PKey::YubiKey;

sub mock_ykman {
   my ($self, @args)= @_;
   return "11111111\n22222222\n"
      if @args == 2 && $args[0] eq 'list' && $args[1] eq '--serials';
   die "Unexpected ykman args: @args";
}

sub mock_ykchalresp {
   my ($self, @args)= @_;

   if (@args == 2 && $args[0] eq '-x') {
      my $challenge_hex= $args[1];
      my $serial= $self->yubikey_serial // '00000000';
      my $seed= "$serial:$challenge_hex";
      my $hex= unpack('H*', $seed);
      $hex= substr($hex . ('0' x 64), 0, 64);
      return secret(pack('H*', $hex));
   }

   die "Unexpected ykchalresp args: @args";
}

sub round_trip {
   my ($selector, $expect_serial)= @_;

   my $key= Crypt::MultiKey::PKey->generate('x25519')->mechanism('YubiKey');
   no warnings 'redefine';
   local *Crypt::MultiKey::PKey::YubiKey::_run_ykman= \&mock_ykman;
   local *Crypt::MultiKey::PKey::YubiKey::_run_ykchalresp= \&mock_ykchalresp;

   defined $selector? $key->encrypt_private($selector) : $key->encrypt_private;
   is($key->yubikey_serial, $expect_serial, 'selected expected yubikey serial');
   ok($key->kdf_salt, 'kdf_salt assigned');

   my $msg= 'yubikey test secret';
   my $enc= $key->encrypt($msg);

   $key->clear_private;
   ok(!$key->has_private, 'private key cleared');
   ok($key->can_obtain_private, 'can_obtain_private is true with matching yubikey serial');

   $key->obtain_private;
   ok($key->has_private, 'private key restored via obtain_private');

   my $secret= $key->decrypt($enc);
   my $decrypted= '';
   $secret->span->copy_to($decrypted);
   is($decrypted, $msg, 'decrypted ciphertext after obtain_private');
}

round_trip(undef, '11111111');
round_trip('22222222', '22222222');

my $missing= Crypt::MultiKey::PKey->generate('x25519')->mechanism('YubiKey');
{
   no warnings 'redefine';
   local *Crypt::MultiKey::PKey::YubiKey::_run_ykman= sub {
      my ($self, @args)= @_;
      return "11111111\n" if @args == 2 && $args[0] eq 'list' && $args[1] eq '--serials';
      die "Unexpected ykman args: @args";
   };
   local *Crypt::MultiKey::PKey::YubiKey::_run_ykchalresp= sub {
      my ($self, @args)= @_;
      return secret("\xaa" x 32) if @args == 2 && $args[0] eq '-x';
      die "Unexpected ykchalresp args: @args";
   };
   like(
      dies { $missing->encrypt_private('99999999') },
      qr/YubiKey serial 99999999 is not currently connected/,
      'dies for unknown yubikey serial selector',
   );
}

my $unset= Crypt::MultiKey::PKey->generate('x25519')->mechanism('YubiKey');
$unset->clear_private;
$unset->private_encrypted('AAAA');
like(
   dies { $unset->obtain_private },
   qr/Cannot obtain private key without yubikey_serial/,
   'obtain_private requires yubikey_serial',
);

my $without_serial= Crypt::MultiKey::PKey->generate('x25519')->mechanism('YubiKey');
{
   no warnings 'redefine';
   local *Crypt::MultiKey::PKey::YubiKey::_run_ykman= \&mock_ykman;
   ok(!$without_serial->can_obtain_private, 'can_obtain_private is false when yubikey_serial is unset');
}

{
   no warnings 'redefine';
   local *Crypt::MultiKey::_have_fido2= sub { 1 };
   local *Crypt::MultiKey::_fido2_list_devices= sub {
      return [ { serial => '33333333', path => '/dev/hidraw-fido' } ];
   };
   local *Crypt::MultiKey::_fido2_chalresp= sub {
      die '_fido2_chalresp should not be used; ykchalresp semantics are authoritative';
   };
   local *Crypt::MultiKey::PKey::YubiKey::_run_ykman= sub {
      die 'ykman should not be used when fido2 enumeration provides serials';
   };
   local *Crypt::MultiKey::PKey::YubiKey::_run_ykchalresp= sub {
      my ($self, @args)= @_;
      is($args[0], '-x', 'ykchalresp called in hex challenge mode');
      like($args[1], qr/^[0-9a-f]+\z/, 'ykchalresp challenge is hex');
      return secret("\xbb" x 32);
   };

   my $key= Crypt::MultiKey::PKey->generate('x25519')->mechanism('YubiKey');
   $key->encrypt_private('33333333');
   is($key->yubikey_serial, '33333333', 'selected yubikey serial via fido2 listing');

   my $msg= 'fido2-backed challenge-response';
   my $enc= $key->encrypt($msg);
   $key->clear_private;
   ok($key->can_obtain_private, 'can_obtain_private is true via fido2 listing');
   $key->obtain_private;
   my $secret= $key->decrypt($enc);
   my $decrypted= '';
   $secret->span->copy_to($decrypted);
   is($decrypted, $msg, 'decrypted ciphertext after fido2-backed obtain_private');
}

done_testing;
