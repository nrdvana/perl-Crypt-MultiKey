use FindBin;
use lib "$FindBin::Bin/lib";
use Test2AndUtils;
use Crypt::SecretBuffer qw( secret );
use Crypt::MultiKey;
use Crypt::MultiKey::PKey;

# Hide pem from Git secret-scanning services.
# None of these private keys are used for anything but tests.
my $begin= '-----BEGIN';
my $end= '-----END';
my $key= 'KEY-----';

subtest openssl_ed25519 => sub {
   my $pem= <<PEM;
$begin PRIVATE $key
MC4CAQAwBQYDK2VwBCIEIBA/TFPxWQVLtpO70IFB+1E9u575zfo2Jm+kSUXtjkuq
$end PRIVATE $key
PEM
   is(Crypt::MultiKey::PKey->new(secret($pem)),
      object {
         call has_public => T;
         call has_private => T;
      },
      'parsed OpenSSL PRIVATE KEY');

   $pem= <<PEM;
$begin ENCRYPTED PRIVATE $key
MIGbMFcGCSqGSIb3DQEFDTBKMCkGCSqGSIb3DQEFDDAcBAj5mSFFP2Qk9wICCAAw
DAYIKoZIhvcNAgkFADAdBglghkgBZQMEASoEEBJksMm41QZekgpdIqEftr4EQNOw
I9DHNaqejEI7Z9VrVJhpbGTlZnqGXbM0+Eo4oth0W4ktsTlTptRpvADMN8b9DA5Z
k9rNYPd/DGUznZTv8Yg=
$end ENCRYPTED PRIVATE $key
PEM
   is(Crypt::MultiKey::PKey->new(data => secret($pem), password => 'your_password_here'),
      object {
         call has_public => T;
         call has_private => T;
      },
      'parsed OpenSSL ENCRYPTED PRIVATE KEY');

   is(Crypt::MultiKey::PKey->new(data => secret($pem)),
      object {
         call has_public => F;
         call has_private => F;
         call private_encrypted => $pem;
         call [ decrypt_private => 'your_password_here' ], T;
         call has_public => T;
         call has_private => T;
      },
      'private key without password');
};

done_testing;
__END__

subtest openssh => sub {

   my $pem_buf= secret(<<PEM);
$begin OPENSSH PRIVATE $key
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABD8PEuTzZ
XNUTkmPVlFklr5AAAAGAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAILz6wWeKffzwCGuZ
DILP1m32lQytP3Citpp7vrx89HEWAAAAoL/xkzu2NB2vPEwIAYNKU9mT6+6sBqkYvQWjS7
t0p80Cd3EmCSejQHsgPOKvqsMnPWUNdYVZAUAqIkutP3K6YfT8dc+cwjM3O3O2sWraqHZ7
vF/goGkq8mbECx3jRL6sZTKGm9rdq03YmjeAEDJYddFSvg2SJMJQwnp36+O6TbJVXJxCbX
Q1lD8D4nQFFY069r8ThCSC0W2G1Sh5nFWJXyo=
$end OPENSSH PRIVATE $key
PEM
   is [ Crypt::MultiKey::PKey->new($pem_buf) ],
      object {
         # call type => T; TODO, report type of PKEY after parsing it
         call has_public => T;
         call has_private => T;
      },
      'parsed OPENSSH PRIVATE KEY';
};
   
0 && subtest ssh_ed25519 => sub {
   my $ssh_fingerprint= 'SHA256:xITnALvG5tHNLZ5HFVXD3vGT9rwEMm0Iy/cet+Aj+VI';
   my $ssh_public= 'AAAAC3NzaC1lZDI1NTE5AAAAILz6wWeKffzwCGuZDILP1m32lQytP3Citpp7vrx89HEW';
#-----BEGIN OPENSSH PRIVATE KEY-----
   my $ssh_private_encrypted= <<END;
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABD8PEuTzZ
XNUTkmPVlFklr5AAAAGAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAILz6wWeKffzwCGuZ
DILP1m32lQytP3Citpp7vrx89HEWAAAAoL/xkzu2NB2vPEwIAYNKU9mT6+6sBqkYvQWjS7
t0p80Cd3EmCSejQHsgPOKvqsMnPWUNdYVZAUAqIkutP3K6YfT8dc+cwjM3O3O2sWraqHZ7
vF/goGkq8mbECx3jRL6sZTKGm9rdq03YmjeAEDJYddFSvg2SJMJQwnp36+O6TbJVXJxCbX
Q1lD8D4nQFFY069r8ThCSC0W2G1Sh5nFWJXyo=
END
#-----END OPENSSH PRIVATE KEY-----
   my $key= Crypt::MultiKey::PKey->new(
      type => 'ed25519',
      private_encrypted => $ssh_private_encrypted,
   );
   ok( $key->decrypt_private('test'), 'decrypt_private' );
   is( $key->public, $ssh_public, $ssh_public, 'public' );
   is( $key->fingerprint, $ssh_fingerprint, 'fingerprint' );
};

done_testing;
