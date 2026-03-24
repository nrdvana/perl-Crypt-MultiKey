use FindBin;
use lib "$FindBin::Bin/lib";
use Test2AndUtils;
use File::Temp qw( tempdir );
use File::Spec;
use Crypt::SecretBuffer qw( secret );
use Crypt::MultiKey::PKey::YubiKey;

my $tmp= tempdir(CLEANUP => 0);
my $fname= File::Spec->catdir($tmp, 'ykinfo');
$Crypt::MultiKey::command_path{ykinfo}= $fname;
note "Writing mock ykinfo to $fname";
mkfile($fname, <<PL, 0777);
#! $^X
# Simulate having 3 YubiKeys where the first has serial number disabled,
# the second uses slot 2 for chalresp, and the third uses slot 1.
use strict;

my \$serial= 0;
my %opts;
for (\@ARGV) {
   if (/^-n(\\d+)\\z/) {
      \$serial += \$1 * 10000000 + \$1;
      if (\$1 > 2) {
         print STDERR "Yubikey core error: no yubikey present\n";
         exit 1;
      }
   }
   elsif (/^-([asHmvtp12iI])\\z/) {
      \$opts{\$1}++;
   }
   else {
      print STDERR "unsupported option\n";
      exit 1;
   }
}
printf "serial: %08d\\n", \$serial     if \$opts{a} || \$opts{s};
printf "serial_hex: %06x\\n", \$serial if \$opts{a} || \$opts{H};
printf "serial_modhex: xxxxxx\\n"      if \$opts{a} || \$opts{m};
printf "version: 5.4.3\\n"             if \$opts{a} || \$opts{v};
printf "touch_level: 775\\n"           if \$opts{a} || \$opts{t};
printf "programming_sequence: 3\\n"    if \$opts{a} || \$opts{p};
printf "slot1_status: 1\\n"            if \$opts{a} || \$opts{1};
printf "slot2_status: 1\\n"            if \$opts{a} || \$opts{2};
printf "vendor_id: 1050\\n"            if \$opts{a} || \$opts{i};
printf "product_id: 407\\n"            if \$opts{a} || \$opts{I};
exit 0;
PL

is(
   Crypt::MultiKey::PKey::YubiKey->_enumerate_devices,
   [
      { serial => '00000000', version => '5.4.3', touch_level => '775',
        programming_sequence => 3, slot1_status => 1, slot2_status => 1,
        vendor_id => 1050, product_id => 407, idx => 0,
      },
      { serial => '10000001', version => '5.4.3', touch_level => '775',
        programming_sequence => 3, slot1_status => 1, slot2_status => 1,
        vendor_id => 1050, product_id => 407, idx => 1,
      },
      { serial => '20000002', version => '5.4.3', touch_level => '775',
        programming_sequence => 3, slot1_status => 1, slot2_status => 1,
        vendor_id => 1050, product_id => 407, idx => 2,
      },
   ],
   'enumerate_devices'
);

$fname= File::Spec->catdir($tmp, 'ykchalresp');
note "Writing mock ykchalresp to $fname";
$Crypt::MultiKey::command_path{ykchalresp}= $fname;
mkfile($fname, <<PL, 0777);
#! $^X
# Simulate having 3 YubiKeys where the first has serial number disabled,
# the second uses slot 2 for chalresp, and the third uses slot 1.
use strict;
use Digest::SHA "sha1";

my \$serial= 0;
my %secret= (
   '0,1' => "112233445566778899aabbccddeeff0011223344",
   '0,2' => "2233445566778899aabbccddeeff001122334455",
   '10000001,2' => "33445566778899aabbccddeeff00112233445566",
   '20000002,1' => "445566778899aabbccddeeff0011223344556677",
);
my %opts;
my \$challenge= pop \@ARGV;
for (\@ARGV) {
   if (/^-n(\\d+)\\z/) {
      \$serial += \$1 * 10000000 + \$1;
      if (\$1 > 2) {
         print STDERR "Yubikey core error: no yubikey present\\n";
         exit 1;
      }
   }
   elsif (/^-([12HYxt])\\z/) {
      \$opts{\$1}++;
   }
   else {
      print STDERR "unsupported option \$_\\n";
      exit 1;
   }
}
my \$slot= \$opts{2}? 2 : 1;
my \$secret= \$secret{"\$serial,\$slot"};
if (\$secret) {
   \$challenge= pack("H*", \$challenge) if \$opts{x};
   print unpack('H*', sha1(\$secret . \$challenge))."\\n";
   exit 0;
} else {
   print STDERR "Yubikey core error: timeout \$serial \$slot\\n";
   exit 1;
}
PL

sub round_trip {
   my ($selector, $expect_serial, $expect_slot)= @_;
   my $key= Crypt::MultiKey::PKey->generate('x25519')->mechanism('YubiKey');

   defined $selector? $key->encrypt_private($selector) : $key->encrypt_private;
   is($key->yubikey_serial, $expect_serial, 'selected expected yubikey serial');
   is($key->yubikey_slot, $expect_slot, 'selected correct slot' );
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

round_trip(undef, '10000001', 2);
round_trip('10000001', '10000001', 2);
round_trip('20000002', '20000002', 1);

my $missing= Crypt::MultiKey::PKey->generate('x25519')->mechanism('YubiKey');
like(
   dies { $missing->encrypt_private('99999999') },
   qr/Required YubiKey.*?not connected/,
   'dies for unknown yubikey serial selector',
);

my $unset= Crypt::MultiKey::PKey->generate('x25519')->mechanism('YubiKey');
$unset->clear_private;
$unset->private_encrypted('AAAA');
like(
   dies { $unset->obtain_private },
   qr/Can't obtain private key without attributes yubikey_serial/,
   'obtain_private requires yubikey_serial',
);

my $without_serial= Crypt::MultiKey::PKey->generate('x25519')->mechanism('YubiKey');
ok(!$without_serial->can_obtain_private, 'can_obtain_private is false when yubikey_serial is unset');

done_testing;
