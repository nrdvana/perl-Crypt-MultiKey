use FindBin;
use lib "$FindBin::Bin/lib";
use Test2AndUtils;
use Crypt::MultiKey::FIDO2;
use Crypt::MultiKey::FIDO2::Device;

plan skip_all => 'libfido2 not available'
   unless Crypt::MultiKey::FIDO2::enabled();

my @devices;
ok( eval { @devices= Crypt::MultiKey::FIDO2::list_devices(); 1; }, 'list_devices' )
   or note "died: $@";

subtest device_methods => sub {
   my $dev= $devices[0]
      or plan skip_all => "No device to test with";

   # path attribute should have been set
   is( $dev->path, T, 'path' );
   # test one attribute from the cbor packet which should always be present
   is( $dev->aaguid, T, 'aaguid' );
   # test one attribute that calls a fido_dev_ method on the device
   is( $dev->supports_uv, D, 'supports_uv' );

   note explain $dev;
};

done_testing;
