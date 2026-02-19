package Crypt::MultiKey::PKey::SSHAgentSignature;
# VERSION
# ABSTRACT: use signature from ssh-agent to unlock a private key

use strict;
use warnings;
use Carp;
use parent 'Crypt::MultiKey::PKey';
use IPC::Run;

=head1 DESCRIPTION

Ideally, we could ask ssh-agent to decrypt some data that had been encrypted with the public
key, but that is not possible because the Agent only signs messages.  SSH operates on a
principle of proving the ownership of the private key via signed challenges, rather than using
the private key for actual encryption/decryption.

So, the only way to use a SSH Agent to decrypt resources on a remote server is to give it a
challenge to be signed by a deterministic (non-random-salted) signing algorithm, and then use
the signature as if it were a password.  This is less cryptographically ideal than a proper
public/private exchange with a remote service, but better and more convenient than typing a
regular password into a terminal, so it seemed worth including.

Note that this means the SSH Agent must be available for the initial creation of the serialized
PKey file.  It also means that anyone with the C<agent_challenge> and access to that SSH Agent
can retrieve this password at any time.

Also note that only keys of type RSA, DSA, or x25519 use a deterministic signing algorithm.
ECDSA signing adds random salt to each signature, making it unusable as a password.

=cut

sub mechanism { 'SSHAgentSignature' }

=attribute agent_key

Specifies which SSH public key (as a string of the Base64 of the OpenSSH public key format)
was used to encrypt the private half of this PKey.  This is assigned during L</encrypt_private>
and used during L</decrypt_private>.

=cut

sub agent_key {
   $_[0]{agent_key}= $_[1] if @_ > 1;
   $_[0]{agent_key};
}

=attribute agent_challenge

Specifies a portion of the string to be signed by the agent, as Base64.

=cut

sub agent_challenge {
   $_[0]{agent_challenge}= $_[1] if @_ > 1;
   $_[0]{agent_challenge};
}

sub _import_pem_headers {
   my ($self, $pem)= @_;
   $self->agent_key($pem->headers->{cmk_agent_key});
   $self->agent_challenge($pem->headers->{cmk_agent_challenge});
}

=head2 is_key_available

Returns a boolean whether the L</agent_key> attribute is found among the current keys in the
ssh agent.

=cut

sub is_key_available {
   my $self= shift;
   my $key= $self->public_key;
   $key= $2 if $key =~ /^(\S+) (\S+)/;
   return scalar grep $_->{public_key} eq $key, eval { $self->list_usable_keys };
}

=method encrypt_private

  $pkey->encrypt_private($ssh_pubkey);
  $pkey->encrypt_private($ssh_fingerprint);
  $pkey->encrypt_private(qr/ssh_key_comment_pattern/);
  $pkey->encrypt_private; # chooses the best/first key available

This differs from the base class in that the SSH Agent must be available, and the optional
parameter you specify indicates which of the Agent's public keys to use.

=cut

sub encrypt_private {
   ...
}

=method decrypt_private

  $pkey->decrypt_private;

This differs from the base class in that the SSH Agent must be available, and there is no
password parameter.

=cut

sub decrypt_private {
   ...
}

sub _get_agent_signature {
   my $self= shift;
   my $key= $self->public_key;
   my @cmd= ( 'ssh-keygen', -Y => 'sign', -n => 'Crypt::MultiKey::PKey', '-q', -f => "/dev/fd/3" );
   my $signed= capture_cmd_with_fds([$message, undef, undef, $key], @cmd);
   IPC::Run::run(\@cmd, '0<', \$key, '1>', \my $out, '2>', \my $err, '3<', $key)
      or die "Failed running ssh-keygen: $err";
   return sha256($out);
}

=head1 CLASS METHODS

=head2 check_dependencies

  $bool_found= $class->check_dependencies();
  $bool_found= $class->check_dependencies(\%details_out);

This checks the host environment for an ssh-agent and whether ssh-keygen supports signing.

It returns a boolean whether everything was detected.  You may pass C<%details_out> to receive
details about each thing that was or wasn't found.

=head2 list_available_keys

  @available= $class->list_available_keys;

This is basically a wrapper around C<< ssh-add -l >>, but parses the type, public_key, and
comment fields, returning them in hash keys.  It also includes a 'usable' flag to indicate which
keys deliver a consistent signature usable by this module.  If there was an error accessing the
agent, this throws an exception.  Otherwise it returns a list (not arrayref) of hashrefs,
possibly empty.

=head2 list_usable_keys

  @usable= $class->list_usable_keys;

Like list_available_keys, but filters out ecdsa keys which are not usable.

=cut

sub list_available_keys {
   my $class= shift;
   return @{ $class->_run_ssh_add_list };
}

sub list_usable_keys {
   my $class= shift;
   grep $_->{usable}, @{ $class->_run_ssh_add_list };
}

sub check_dependencies {
   my ($self, $details)= @_;
   $details //= {};
   local $@;
   my $success= 1;
   my ($out, $err);
   unless (eval { $self->_run_ssh_add_list; 1 }) {
      $details->{ssh_agent}= $@;
      $success= 0;
   }
   if (eval { IPC::Run::run([qw( ssh-keygen -? )], \'', \$out, \$err); 1 }) {
      if ($? != 1<<8) {
         $details->{ssh_keygen}= 'unexpected result running ssh-keygen: '.$err;
         $success= 0;
      } elsif ($err !~ /ssh-keygen\s+-Y\s+sign/) {
         $details->{ssh_keygen}= 'ssh-keygen does not support "-Y sign" option';
         $success= 0;
      }
   } else {
      $details->{ssh_keygen}= $@;
      $success= 0;
   }
   return $success;
}

my %usable_type= ( map +($_ => 1), qw( ssh-rsa ssh-dsa ssh-ed25519 ) );

sub _run_ssh_add_list {
   my $class= shift;
   my ($out, $err);
   IPC::Run::run([qw( ssh-add -L )], \'', \$out, \$err)
      or die "ssh-add -L failed: $? : $err";
   my @keys;
   while ($out =~ /^(\S+) (\S+) (.*)/mg) {
      push @keys, { type => $1, usable => $usable_type{$1}, public_key => $2, comment => $3 };
   }
   return \@keys
}

1;
