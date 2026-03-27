use FindBin;
use lib "$FindBin::Bin/lib";
use Test2AndUtils;
use File::Temp qw( tempdir );
use File::Spec;
use Crypt::SecretBuffer qw( secret );
use Crypt::MultiKey::PKey::YKChalResp;

# Export as an envionment variable for external command wrappers to use
$ENV{TEST_PERL_INTERPRETER}= $^X;
# Need wrappers on the commands in order to set the perl interpreter to the same as used for
# running this test.  (or perform voodoo on the Makefile.PL to rewrite the test scripts, but
# lets not do that)
for (qw( ykinfo ykchalresp )) {
   my $wrapper= $^O eq 'MSWin32'? "mock-$_.bat" : "mock-$_.sh";
   $Crypt::MultiKey::command_path{$_} = File::Spec->catfile($FindBin::Bin, 'bin', $wrapper);
}

is(
   Crypt::MultiKey::PKey::YKChalResp->_enumerate_devices,
   [
      { serial => '00000000', version => '5.4.3', touch_level => '775',
        programming_sequence => 3, slot1_status => 1, slot2_status => 1,
        vendor_id => 4176, product_id => 1031, idx => 0,
      },
      { serial => '10000001', version => '5.4.3', touch_level => '775',
        programming_sequence => 3, slot1_status => 1, slot2_status => 1,
        vendor_id => 4176, product_id => 1031, idx => 1,
      },
      { serial => '20000002', version => '5.4.3', touch_level => '775',
        programming_sequence => 3, slot1_status => 1, slot2_status => 1,
        vendor_id => 4176, product_id => 1031, idx => 2,
      },
   ],
   'enumerate_devices'
);

sub round_trip {
   my ($selector, $expect_serial, $expect_slot)= @_;
   my $key= Crypt::MultiKey::PKey->generate('x25519')->mechanism('YKChalResp');

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

round_trip(undef, '00000000', 1);
round_trip('10000001', '10000001', 2);
round_trip('20000002', '20000002', 1);

my $missing= Crypt::MultiKey::PKey->generate('x25519')->mechanism('YKChalResp');
like(
   dies { $missing->encrypt_private('99999999') },
   qr/Required YubiKey.*?not connected/,
   'dies for unknown yubikey serial selector',
);

my $unset= Crypt::MultiKey::PKey->generate('x25519')->mechanism('YKChalResp');
$unset->clear_private;
$unset->private_encrypted('AAAA');
like(
   dies { $unset->obtain_private },
   qr/Can't obtain private key without attributes yubikey_serial/,
   'obtain_private requires yubikey_serial',
);

my $without_serial= Crypt::MultiKey::PKey->generate('x25519')->mechanism('YKChalResp');
ok(!$without_serial->can_obtain_private, 'can_obtain_private is false when yubikey_serial is unset');

done_testing;
