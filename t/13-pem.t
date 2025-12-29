use FindBin;
use lib "$FindBin::Bin/lib";
use Test2AndUtils;
use Crypt::SecretBuffer qw( secret );
use Crypt::MultiKey;
use Crypt::MultiKey::PKey;

subtest parse_pem => sub {
   my $pem_buf= secret(<<PEM);
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABD8PEuTzZ
XNUTkmPVlFklr5AAAAGAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAILz6wWeKffzwCGuZ
DILP1m32lQytP3Citpp7vrx89HEWAAAAoL/xkzu2NB2vPEwIAYNKU9mT6+6sBqkYvQWjS7
t0p80Cd3EmCSejQHsgPOKvqsMnPWUNdYVZAUAqIkutP3K6YfT8dc+cwjM3O3O2sWraqHZ7
vF/goGkq8mbECx3jRL6sZTKGm9rdq03YmjeAEDJYddFSvg2SJMJQwnp36+O6TbJVXJxCbX
Q1lD8D4nQFFY069r8ThCSC0W2G1Sh5nFWJXyo=
-----END OPENSSH PRIVATE KEY-----
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
