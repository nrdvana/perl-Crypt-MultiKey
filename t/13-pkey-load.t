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
   # openssl genpkey -algorithm ED25519 -out -
   my $pem= <<PEM;
$begin PRIVATE $key
MC4CAQAwBQYDK2VwBCIEIBA/TFPxWQVLtpO70IFB+1E9u575zfo2Jm+kSUXtjkuq
$end PRIVATE $key
PEM
   is(Crypt::MultiKey::PKey->load(\$pem),
      object {
         call has_public => T;
         call has_private => T;
      },
      'parsed OpenSSL PRIVATE KEY');

   # openssl genpkey -algorithm ED25519 -aes-256-cbc -out -
   (my $base64= <<B64) =~ s/\s+//g;
MIGbMFcGCSqGSIb3DQEFDTBKMCkGCSqGSIb3DQEFDDAcBAj5mSFFP2Qk9wICCAAw
DAYIKoZIhvcNAgkFADAdBglghkgBZQMEASoEEBJksMm41QZekgpdIqEftr4EQNOw
I9DHNaqejEI7Z9VrVJhpbGTlZnqGXbM0+Eo4oth0W4ktsTlTptRpvADMN8b9DA5Z
k9rNYPd/DGUznZTv8Yg=
B64
   $pem= <<PEM;
$begin ENCRYPTED PRIVATE $key
$base64
$end ENCRYPTED PRIVATE $key
PEM
   is(Crypt::MultiKey::PKey->load(\$pem, password => 'your_password_here'),
      object {
         call has_public => T;
         call has_private => T;
      },
      'parsed OpenSSL ENCRYPTED PRIVATE KEY');

   is(Crypt::MultiKey::PKey->load(\$pem),
      object {
         call has_public => F;
         call has_private => F;
         call private_encrypted => $base64;
         call [ decrypt_private => 'your_password_here' ], T;
         call has_public => T;
         call has_private => T;
      },
      'private key without password');

   # openssl pkey -in ed25519.key -pubout >> ed25519.key
   ($base64= <<B64) =~ s/\s+//g;
MIGbMFcGCSqGSIb3DQEFDTBKMCkGCSqGSIb3DQEFDDAcBAj5mSFFP2Qk9wICCAAw
DAYIKoZIhvcNAgkFADAdBglghkgBZQMEASoEEBJksMm41QZekgpdIqEftr4EQNOw
I9DHNaqejEI7Z9VrVJhpbGTlZnqGXbM0+Eo4oth0W4ktsTlTptRpvADMN8b9DA5Z
k9rNYPd/DGUznZTv8Yg=
B64
   my $priv_and_pub= <<PEM;
$begin ENCRYPTED PRIVATE $key
$base64
$end ENCRYPTED PRIVATE $key
$begin PUBLIC $key
MCowBQYDK2VwAyEASS5bxena7Pppz7YoLwoBWNTYZ/YY+wns0BrLuIaIqU8=
$end PUBLIC $key
PEM
   is(Crypt::MultiKey::PKey->load(\$priv_and_pub),
      object {
         call has_public => T;
         call has_private => F;
         call private_encrypted => $base64;
         call [ decrypt_private => 'your_password_here' ], T;
         call has_public => T;
         call has_private => T;
      },
      'private key with pubkey');
};

subtest openssh_ed25519 => sub {
   my $ssh_fingerprint= 'SHA256:xITnALvG5tHNLZ5HFVXD3vGT9rwEMm0Iy/cet+Aj+VI';
   my $ssh_public= 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILz6wWeKffzwCGuZDILP1m32lQytP3Citpp7vrx89HEW';
   my $ssh_private= <<PEM;
$begin OPENSSH PRIVATE $key
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACC8+sFnin388AhrmQyCz9Zt9pUMrT9woraae768fPRxFgAAAJhnTDGZZ0wx
mQAAAAtzc2gtZWQyNTUxOQAAACC8+sFnin388AhrmQyCz9Zt9pUMrT9woraae768fPRxFg
AAAECRGKRiESoqfh3yVTBNnzOtzXDw0VHmZ5xODuaN/wV9ELz6wWeKffzwCGuZDILP1m32
lQytP3Citpp7vrx89HEWAAAAEnNpbHZlcmRpcmtAb3NhbmdhcgECAw==
$end OPENSSH PRIVATE $key
PEM
   my $ssh_private_encrypted= <<PEM;
$begin OPENSSH PRIVATE $key
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABD8PEuTzZ
XNUTkmPVlFklr5AAAAGAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAILz6wWeKffzwCGuZ
DILP1m32lQytP3Citpp7vrx89HEWAAAAoL/xkzu2NB2vPEwIAYNKU9mT6+6sBqkYvQWjS7
t0p80Cd3EmCSejQHsgPOKvqsMnPWUNdYVZAUAqIkutP3K6YfT8dc+cwjM3O3O2sWraqHZ7
vF/goGkq8mbECx3jRL6sZTKGm9rdq03YmjeAEDJYddFSvg2SJMJQwnp36+O6TbJVXJxCbX
Q1lD8D4nQFFY069r8ThCSC0W2G1Sh5nFWJXyo=
$end OPENSSH PRIVATE $key
PEM
   is(Crypt::MultiKey::PKey->load(\$ssh_public),
      object {
         call has_public => T;
         call has_private => F;
         #call fingerprint => $ssh_fingerprint;
      },
      'public key');
   is(Crypt::MultiKey::PKey->load(\$ssh_private),
      object {
         call has_public => T;
         call has_private => T;
      },
      'private key');
   is(Crypt::MultiKey::PKey->load(\$ssh_private_encrypted),
      object {
         call has_public => T;
         call has_private => F;
         call private_encrypted => $ssh_private_encrypted;
         call [ decrypt_private => 'test' ], T;
         call has_private => T;
      },
      'private key encrypted');
};

done_testing;
