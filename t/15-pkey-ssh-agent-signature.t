use strict;
use warnings;
use Test2::V0;

use lib 'lib';
use Crypt::MultiKey qw( sha256 );
use Crypt::MultiKey::PKey;
use Crypt::MultiKey::PKey::SSHAgentSignature;

{
   package TestAgent;
   use strict;
   use warnings;

   sub new {
      my $class= shift;
      bless {}, $class;
   }

   sub get_key_list {
      return [
         { type => 'ecdsa-sha2-nistp256', pubkey_base64 => 'NOPE', comment => 'ignored' },
         { type => 'ssh-ed25519', pubkey_base64 => 'AAA_KEY_1', comment => 'first-key' },
         { type => 'ssh-rsa', pubkey_base64 => 'AAA_KEY_2', comment => 'deploy-key' },
      ];
   }

   sub sign {
      my ($self, $pubkey, $data)= @_;
      my $pubkey_base64= ref($pubkey) eq 'HASH'? $pubkey->{pubkey_base64} : $pubkey;
      return main::sha256($pubkey_base64, $data);
   }
}

sub round_trip {
   my ($selector, $expect_pubkey)= @_;

   my $key= Crypt::MultiKey::PKey->generate('x25519')->mechanism('SSHAgentSignature');
   $key->{agent}= TestAgent->new;

   defined $selector? $key->encrypt_private($selector) : $key->encrypt_private;
   is($key->agent_pubkey, $expect_pubkey, 'selected expected agent key');
   ok($key->kdf_salt, 'kdf_salt assigned');

   my $msg= 'ssh-agent-signature test secret';
   my $enc= $key->encrypt($msg);

   $key->clear_private;
   ok(!$key->has_private, 'private key cleared');
   ok($key->can_obtain_private, 'can_obtain_private is true with matching agent key');

   $key->obtain_private;
   ok($key->has_private, 'private key restored via obtain_private');

   my $secret= $key->decrypt($enc);
   my $decrypted= '';
   $secret->span->copy_to($decrypted);
   is($decrypted, $msg, 'decrypted ciphertext after obtain_private');
}

round_trip(undef, 'AAA_KEY_1');
round_trip('AAA_KEY_2', 'AAA_KEY_2');
round_trip(qr/deploy/, 'AAA_KEY_2');

my $missing= Crypt::MultiKey::PKey->generate('x25519')->mechanism('SSHAgentSignature');
$missing->{agent}= TestAgent->new;
like(dies { $missing->encrypt_private('NO_SUCH_KEY') }, qr/No SSH agent key matched selector/, 'dies for unknown selector');

my $ambiguous= Crypt::MultiKey::PKey->generate('x25519')->mechanism('SSHAgentSignature');
$ambiguous->{agent}= bless {}, 'TestAgentDup';
{
   package TestAgentDup;
   use strict;
   use warnings;

   sub get_key_list {
      return [
         { type => 'ssh-rsa', pubkey_base64 => 'A1', comment => 'dup-key' },
         { type => 'ssh-dsa', pubkey_base64 => 'A2', comment => 'dup-key' },
      ];
   }

   sub sign {
      my ($self, $pubkey, $data)= @_;
      my $pubkey_base64= ref($pubkey) eq 'HASH'? $pubkey->{pubkey_base64} : $pubkey;
      return main::sha256($pubkey_base64, $data);
   }
}
like(dies { $ambiguous->encrypt_private(qr/dup-key/) }, qr/Selector matched multiple SSH agent keys/, 'dies for ambiguous regex selector');

done_testing;
