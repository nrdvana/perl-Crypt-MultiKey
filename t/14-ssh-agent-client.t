use strict;
use warnings;
use Test2::V0;

use lib 'lib';
use Crypt::MultiKey::SSHAgentClient;

{
   package TestClient;
   our @ISA= ('Crypt::MultiKey::SSHAgentClient');

   sub _get_key_list_via_agent_socket {
      die "no socket" if $_[0]{socket_fail};
      return [ { type => 'ssh-ed25519', pubkey_base64 => 'AAAATEST', comment => 'sock' } ];
   }

   sub _get_key_list_via_ssh_add {
      return [ { type => 'ssh-rsa', pubkey_base64 => 'BBBBTEST', comment => 'fallback' } ];
   }

   sub _sign_via_agent_socket {
      die "no socket" if $_[0]{socket_fail};
      return "socket-signature";
   }

   sub _sign_via_ssh_keygen {
      return "fallback-signature";
   }
}

my $ok= TestClient->new;
is($ok->get_key_list->[0]{comment}, 'sock', 'prefers socket keys');
is($ok->sign('AAAATEST', 'data'), 'socket-signature', 'prefers socket sign');

my $fallback= TestClient->new;
$fallback->{socket_fail}= 1;
is($fallback->get_key_list->[0]{comment}, 'fallback', 'falls back to ssh-add');
is($fallback->sign('AAAATEST', 'data'), 'fallback-signature', 'falls back to ssh-keygen');

my $plain= Crypt::MultiKey::SSHAgentClient->new;
my ($type, $b64)= Crypt::MultiKey::SSHAgentClient::_split_pubkey_blob(
   pack('Na*', length('ssh-ed25519'), 'ssh-ed25519')."\x00\x00\x00\x01x"
);
is($type, 'ssh-ed25519', 'parse key type from blob');
ok(length($b64), 'returns base64 for blob');

is(Crypt::MultiKey::SSHAgentClient::_pack_ssh_string('abc'), "\x00\x00\x00\x03abc", 'pack ssh string');

my $tmp= "\x00\x00\x00\x03abcrest";
is(Crypt::MultiKey::SSHAgentClient::_parse_ssh_string(\$tmp), 'abc', 'parse ssh string');
is($tmp, 'rest', 'parse ssh string consumed bytes');

done_testing;
