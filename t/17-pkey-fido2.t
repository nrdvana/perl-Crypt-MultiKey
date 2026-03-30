use strict;
use warnings;
use Test2::V0;

use lib 'lib';
use Crypt::SecretBuffer qw( secret );
use Crypt::MultiKey::PKey;
use Crypt::MultiKey::PKey::FIDO2;

{
   package Local::MockFIDO2Device;
   use parent 'Crypt::MultiKey::FIDO2::Device';

   sub new {
      my ($class, %args)= @_;
      return bless {
         aaguid => ($args{aaguid} // ("\xAA" x 16)),
         credential => ($args{credential} // {
            id => "cred-id-1",
            pubkey => "pubkey-1",
            cose_alg => 'ES256',
         }),
         hmac_secret => ($args{hmac_secret} // ("\x55" x 32)),
         assert_should_match => ($args{assert_should_match} // 1),
         make_calls => 0,
         assert_calls => 0,
      }, $class;
   }

   sub aaguid { $_[0]{aaguid} }

   sub make_hmac_secret_credential {
      my ($self, %opts)= @_;
      $self->{make_calls}++;
      main::is(
         \%opts,
         {
            user_name => 'Crypt::MultiKey::PKey::FIDO2',
            user_display_name => 'Crypt::MultiKey::PKey::FIDO2',
         },
         'create_credential sends expected enrollment options'
      );
      return {
         id => $self->{credential}{id},
         pubkey => $self->{credential}{pubkey},
         cose_alg => $self->{credential}{cose_alg},
      };
   }

   sub assert_hmac_secret {
      my ($self, %opts)= @_;
      $self->{assert_calls}++;
      main::ok(defined $opts{challenge}, 'assert_hmac_secret receives challenge');
      main::is($opts{credential}{id}, $self->{credential}{id}, 'assert_hmac_secret credential id matches enrolled credential');
      return unless $self->{assert_should_match};
      return (main::secret($self->{hmac_secret}), $self->{credential});
   }
}

subtest 'encrypt_private + obtain_private with mock device object' => sub {
   my $dev= Local::MockFIDO2Device->new;
   my $key= Crypt::MultiKey::PKey->generate('x25519')->mechanism('FIDO2');

   $key->encrypt_private($dev);
   ok($key->private_encrypted, 'private key encrypted');
   ok($key->kdf_salt, 'kdf_salt generated');
   is(length($key->kdf_salt), 16, 'kdf_salt is 16 bytes');
   ok($key->fido2_credential, 'fido2_credential assigned');
   is($key->fido2_aaguid, $dev->aaguid, 'fido2_aaguid assigned from device');

   my $cipher= $key->encrypt('fido2 message');
   $key->clear_private;
   ok(!$key->has_private, 'private key was cleared');

   {
      no warnings 'redefine';
      local *Crypt::MultiKey::FIDO2::enabled= sub { 1 };
      local *Crypt::MultiKey::FIDO2::list_devices= sub { ($dev) };
      ok($key->can_obtain_private, 'can_obtain_private finds matching AAGUID');
      $key->obtain_private;
   }

   ok($key->has_private, 'private key restored via obtain_private');
   my $plain= '';
   $key->decrypt($cipher)->span->copy_to($plain);
   is($plain, 'fido2 message', 'decrypt works after obtain_private');
   is($dev->{make_calls}, 1, 'enrollment called once');
   is($dev->{assert_calls}, 2, 'assert called for encrypt_private and obtain_private');
};

subtest 'obtain_private supports supplied hmac_secret and avoids device lookup' => sub {
   my $dev= Local::MockFIDO2Device->new;
   my $key= Crypt::MultiKey::PKey->generate('x25519')->mechanism('FIDO2');
   $key->encrypt_private($dev);
   $key->clear_private;

   $key->obtain_private(hmac_secret => secret("\x55" x 32));
   ok($key->has_private, 'private restored from supplied hmac_secret');
};

subtest 'encrypt_private with existing credential needs matching AAGUID if no explicit device' => sub {
   my $dev1= Local::MockFIDO2Device->new(aaguid => ("\x01" x 16));
   my $dev2= Local::MockFIDO2Device->new(aaguid => ("\x02" x 16));
   my $key= Crypt::MultiKey::PKey->generate('x25519')->mechanism('FIDO2');

   $key->encrypt_private($dev1);

   {
      no warnings 'redefine';
      local *Crypt::MultiKey::FIDO2::list_devices= sub { ($dev2) };
      like(
         dies { $key->encrypt_private },
         qr/No device present with matching aaguid/,
         'fails if no connected device has matching AAGUID'
      );
   }
};

subtest 'export/load roundtrip preserves FIDO2 headers needed for unlock' => sub {
   my $dev= Local::MockFIDO2Device->new(aaguid => ("\xAB" x 16));
   my $key= Crypt::MultiKey::PKey->generate('x25519')->mechanism('FIDO2');
   $key->challenge("\x00challenge with weird\nchars\xff");
   $key->encrypt_private($dev);

   my $pem= $key->export;
   my $loaded= Crypt::MultiKey::PKey->load($pem);

   isa_ok($loaded, 'Crypt::MultiKey::PKey::FIDO2');
   is($loaded->fido2_aaguid, $key->fido2_aaguid, 'AAGUID roundtrips via PEM');
   is($loaded->fido2_credential->{id}, $key->fido2_credential->{id}, 'credential id roundtrips');
   is($loaded->fido2_credential->{pubkey}, $key->fido2_credential->{pubkey}, 'credential pubkey roundtrips');
   is($loaded->challenge, $key->challenge, 'challenge roundtrips');
   is($loaded->kdf_salt, $key->kdf_salt, 'kdf_salt roundtrips');
};

subtest 'obtain_private validates required enrollment fields' => sub {
   my $key= Crypt::MultiKey::PKey->generate('x25519')->mechanism('FIDO2');
   $key->clear_private;
   $key->private_encrypted('AAAA');

   like(
      dies { $key->obtain_private },
      qr/Cannot obtain private key without fido2_credential and fido2_aaguid/,
      'obtain_private rejects un-enrolled key'
   );
};

done_testing;
