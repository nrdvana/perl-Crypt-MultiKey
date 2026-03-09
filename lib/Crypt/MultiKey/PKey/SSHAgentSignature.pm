package Crypt::MultiKey::PKey::SSHAgentSignature;
# VERSION
# ABSTRACT: use signature from ssh-agent to unlock a private key

use strict;
use warnings;
use Carp;
use parent 'Crypt::MultiKey::PKey';

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

=attribute agent

Lazy-built instance of L<Crypt::MultiKey::SSHAgentClient>.  You can use this object to specify
a custom SSH socket or path to the ssh-add and ssh-keygen commands.

=over

=item usable_agent_keys

Call C<< ->agent->get_key_list >> and filter for key types with a deterministic signature
algorithm. (ssh-rsa, ssh-dsa, ssh-ed25519)

=back

=cut

sub agent {
   require Crypt::MultiKey::SSHAgentClient;
   $_[0]{agent} ||= Crypt::MultiKey::SSHAgentClient->new;
}

our %usable_type= ( map +($_ => 1), qw( ssh-rsa ssh-dsa ssh-ed25519 ) );
sub usable_agent_keys {
   my $class= shift;
   grep $usable_type{$_->{type}}, @{ $self->agent->get_key_list };
}

=attribute agent_pubkey

Specifies which SSH public key (as a string of the Base64 of the OpenSSH public key format)
was used to encrypt the private half of this PKey.  This is assigned during L</encrypt_private>
and used during L</decrypt_private>.

=attribute kdf_salt

A string of random salt (base64) which is combined with the public half of this PKey and used
as the data to be signed by the SSH agent.  (the signature from the agent is then combined with
this salt again to produce the password for decryption)

=cut

sub agent_pubkey { @_ > 1? shift->_set_agent_pubkey(@_) : $_[0]{agent_pubkey} }
sub _set_agent_pubkey { $_[0]{agent_pubkey}= $_[1] }

sub kdf_salt { @_ > 1? shift->_set_kdf_salt(@_) : $_[0]{kdf_salt} }
sub _set_kdf_salt { $_[0]{kdf_salt}= $_[1] }

=method can_obtain_private

Returns true if the resources needed for obtaining the private half of the PKey are available.
For SSHAgentSignature, this means that the SSH agent is available and C<< "ssh-add -L" >>
includes the L</agent_pubkey>.

=cut

sub can_obtain_private {
   my $self= shift;
   my $key= $self->agent_pubkey;
   return scalar grep $_->{pubkey_base64} eq $key, eval { $self->usable_agent_keys };
}

=method obtain_private

Attempts to contact the agent and ask it to repeat the signature that is used as the password
for decrypting the private half of this PKey.  It either decrypts the private half of this key,
or croaks.

=cut

sub obtain_private {
   my $self= shift;
   $self->_export_spki(my $raw_pubkey_bytes);
   my %kdf_params= (
      size => 32,
      kdf_info => 'Crypt::MultiKey::PKey::SSHAgentSignature',
      kdf_salt => $self->kdf_salt,
   );
   my $to_be_signed= Crypt::MultiKey::hkdf(\%kdf_params, $raw_pubkey_bytes);
   my $signed= $self->agent->sign($self->agent_pubkey, $to_be_signed);
   my $pw= Crypt::MultiKey::hkdf(\%kdf_params, $signed);
   $self->decrypt_private($pw);
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

# When parent class loads PEM file, capture additional attributes
sub _import_pem_headers {
   my ($self, $pem)= @_;
   $self->agent_pubkey($pem->headers->{cmk_agent_pubkey});
}

sub _export_pem_headers {
   my ($self, $pem)= @_;
   # This type of key may only be exported when the private key has been encrypted with the
   # agent signature.
   croak "Cannot export ::PKey::SSHAgentSignature without selecting agent_pubkey"
      unless defined $self->agent_pubkey;
   croak "Cannot export ::PKey::SSHAgentSignature without first encrypting the private half"
      unless defined $self->encrypted_private;
   $self->next::method($pem);
   $pem->headers->append(cmk_agent_pubkey => $self->agent_pubkey);
}

1;
