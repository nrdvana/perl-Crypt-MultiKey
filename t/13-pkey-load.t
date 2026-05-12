use FindBin;
use lib "$FindBin::Bin/lib";
use Test2AndUtils;
use Crypt::SecretBuffer qw( secret );
use MIME::Base64 qw( decode_base64 );
use Crypt::MultiKey qw( pkey new_pkey load_pkey );
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
         call sub { $_[0]->private_encrypted }, decode_base64($base64);
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
         call sub { $_[0]->private_encrypted }, decode_base64($base64);
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
         call private_encrypted_foreign => $ssh_private_encrypted;
         call [ decrypt_private => 'test' ], T;
         call has_private => T;
      },
      'private key encrypted');
};

subtest documented_accessors => sub {
   my $key= Crypt::MultiKey::PKey->generate('x25519');
   my $public= $key->public;
   my $public_b64= $key->public_b64;
   my $private= $key->private;

   is(new_pkey(public => $public),
      object {
         call has_public => T;
         call has_private => F;
         call public => $public;
      },
      'public attribute imports SubjectPublicKeyInfo DER bytes');

   is(new_pkey(public_b64 => $public_b64),
      object {
         call has_public => T;
         call has_private => F;
         call public => $public;
         call public_b64 => $public_b64;
      },
      'public_b64 attribute imports base64 SubjectPublicKeyInfo');

   is(new_pkey(private => $private),
      object {
         call has_public => T;
         call has_private => T;
         call public => $public;
      },
      'private attribute imports PKCS#8 private key bytes');

   my $enc= $key->export_pkcs8_encrypted('password', 99);
   is(new_pkey(private_encrypted => $enc)->decrypt_private('password'),
      object {
         call has_public => T;
         call has_private => T;
         call public => $public;
      },
      'private_encrypted attribute imports encrypted PKCS#8 DER bytes');
};

subtest constructor_helpers => sub {
   my $key= new_pkey(generate => 'x25519');
   ok($key->has_private, 'new_pkey delegates to PKey constructor');

   my $pem= $key->export_pem_openssl_public_key->serialize;
   is(load_pkey($pem),
      object {
         call has_public => T;
         call has_private => F;
         call public => $key->public;
      },
      'load_pkey delegates to PKey loader');

   ok(!eval { new_pkey(generate => 'x25519', save => 'not-written.pem'); 1 },
      'PKey constructor rejects method-style options other than generate');
   like($@, qr/Unknown PKey constructor option 'save'/, 'rejection names the unknown option');

   is(pkey(generate => 'x25519'),
      object { call has_private => T },
      'pkey keeps existing even-argument constructor dispatch');
   is(pkey($pem),
      object { call has_public => T; call has_private => F },
      'pkey keeps existing odd-argument loader dispatch');
};

subtest decrypt_private_public_mismatch => sub {
   my $correct= new_pkey(generate => 'x25519');
   my $wrong= new_pkey(generate => 'x25519');
   my $wrong_public= $wrong->public;
   my $encrypted= $correct->export_pkcs8_encrypted('password', 99);
   my $pkey= new_pkey(public => $wrong_public, private_encrypted => $encrypted);

   like(
      dies { $pkey->decrypt_private('password') },
      qr/does not match the existing public key/,
      'decrypt_private rejects a mismatched public key'
   );
   is($pkey->public, $wrong_public, 'original public key restored after mismatch');
   ok(!$pkey->has_private, 'private key not retained after mismatch');
};

done_testing;
