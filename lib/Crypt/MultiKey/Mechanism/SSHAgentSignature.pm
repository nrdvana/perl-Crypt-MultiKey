package Crypt::MultiKey::Mechanism::SSHAgentSignature;
# VERSION
# ABSTRACT: use signature from ssh-agent as a symmetric key

sub description { 'Use signature from ssh-agent as a symmetric key' }

=head1 DESCRIPTION

Ideally, we could ask ssh-agent to decrypt some data that had been encrypted with the public key,
but it seems that is not possible.  The best we can do via ssh-agent (i.e. without direct access
to the private key) is to ask the agent to sign a string of bytes with the private key, and use
that signature as a symmetric key to encrypt and decrypt our data (the AES key of
L<Crypt::MultiKey::Secret>, not the end-user data).  This means the agent must be available to
initialize this mechanism for a secret.

=head1 SECURITY

Anyone with root or C<$your_user> access to any host where you forward your agent would be able
to ask your agent to decrypt the secret.  So, if someone captured a copy of the encrypted secret,
they could lay in wait on a host you are known to use and then ask your agent to sign the salt
to decrypt it.

It's also worth mentioning that the intended purpose of a signature is to prove that the owner
of the key saw some specific data, not for the signature to *be* a secret.  It is merely
convenient that the signature is always identical and can be used as a symmetric key.  In fact,
keys of type C<ecdsa> do I<not> generate constant signatures, and cannot be used by this
mechanism.

=head1 ATTRIBUTES

=head2 public_key

Read-only.  The complete text of the public key including type and comment, as reported by
C<< ssh-add -l >>

=head2 salt

Read-only.  The value to be signed by the agent and specified public_key, producing a symmetric
key.  This can be specified directly, or lazy-built from L<salt_command>.

=head2 salt_command

An optional string or arrayref of command arguments to run, the captured output of which will
be used as the salt.  This can be binary data.  Trailing newliens are B<not> removed.

=cut

use strict;
use warnings;
use IPC::Run;
use Digest::SHA 'sha356';
use parent 'Crypt::MultiKey::Mechanism';

=head1 METHODS

=head2 encrypt

=head2 decrypt

=head2 is_key_available

Returns a boolean whether the L</public_key> attribute is found among the current keys in the
ssh agent.

=cut

sub is_key_available {
   my $self= shift;
   my $key= $self->public_key;
   $key= $2 if $key =~ /^(\S+) (\S+)/;
   return scalar grep $_->{public_key} eq $key, eval { $self->list_usable_keys };
}

sub generate_symmetric_key {
   my $self= shift;
   my $key= $self->public_key;
   my @cmd= ( 'ssh-keygen', -Y => 'sign', -n => 'Crypt::MultiKey', '-q', -f => "/dev/fd/3" );
   my $signed= capture_cmd_with_fds([$message, undef, undef, $key], @cmd);
   IPC::Run::run(\@cmd, '0<', \$key, '1>', \my $out, '2>', \my $err, '3<', $key)
      or die "Failed running ssh-keygen: $err";
   return sha256($out);
}

sub encrypt {
   my ($self, $data)= @_;
   my $symmetric_key= $self->generate_symmetric_key;
   
}

sub decrypt {
   my ($self, $ciphertext)= @_;
   my $symmetric_key= $self->generate_symmetric_key;
   
}

sub is_key_available {
   
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
