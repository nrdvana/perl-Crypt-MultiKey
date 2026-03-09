package Crypt::MultiKey::SSHAgentClient;

=head1 SYNOPSIS

  my $agent= Crypt::MultiKey::SSHAgentClient->new;
  my $keys= $agent->get_key_list;
  my $signature_bytes= $agent->sign($keys->[0], $data_bytes);

=head1 DESCRIPTION

You can ask OpenSSH to sign arbitrary data using `ssh-keygen -Y`, however this feature is an
option when building OpenSSH and even some modern Linux distros haven't enabled it.  So, this
module makes a direct socket connection to your SSH agent!  If that fails, it falls back to
running the 'ssh-add' and 'ssh-keygen' commands.

=constructor new

Create a new object.  This object connects to the agent on demand, so it creating the object
might succeed but then throw an exception during C<get_key_list> if it can't connect and the
'ssh-add' program isn't found or 'ssh-keygen' doesn't support C<-Y>.

=cut

sub new {
   my $class= shift;
   my %attrs= @_ == 1? %{$_[0]} : @_;
   my $self= bless {}, $class;
   # Hook for subclasses to process attributes
   $self->_init(\%attrs) if $self->can('_init');
   # Every remaining attribute must have a writable accessor
   $self->$_($attrs{$_})
      for keys %attrs;
   return $self;
}

=attribute ssh_auth_sock

Path of SSH agent socket.  Defaults to C<< $ENV{SSH_AUTH_DOCK} >>.

=attribute ssh_add_path

Path to binary 'ssh-add'

=attribute ssh_keygen_path

Path to binary 'ssh-keygen'

=cut

sub ssh_auth_sock   {
   @_ > 1? shift->_set_ssh_auth_sock(@_)
   : ($_[0]{ssh_auth_sock} || shift->_build_ssh_auth_sock)
}
sub ssh_add_path {
   @_ > 1? shift->_set_ssh_add_path(@_)
   : ($_[0]{ssh_add_path} || shift->_build_ssh_add_path)
}
sub ssh_keygen_path {
   @_ > 1? shift->_set_ssh_keygen_path(@_)
   : ($_[0]{ssh_keygen_path} || shift->_build_ssh_keygen_path)
}

=method get_key_list

  my @keys= $agent->get_key_list;
  # (
  #   { type          => $algo,
  #     pubkey_base64 => $base64,
  #     comment       => $text,
  #   },
  #   ...
  # )

Return a list of keys available in the agent.  C<type>, C<pubkey_base64>, and C<comment> are
the exact strings seen in the output of C<< ssh-add -L >>.

=method sign

  my $signature_secretbuffer= $agent->sign($pubkey, $data_bytes, $namespace);

The C<$pubkey> can be either the base64 string of the public key, or the hashref for that key
returned by C<get_key_list>.  C<$data_bytes> can be either a string or L<SecretBuffer|Crypt::SecretBuffer>.
The C<$namespace> defaults to C<"Crypt::MultiKey">.

=cut

sub get_key_list {
   my $self= shift;
   # if agent is available via socket,
   #   connect if not connected yet, or die
   #   request list of keys
   #   encode each pubkey as base64
   # else
   #    look for ssh-add, or die
   #   `ssh-add -L` and split into 3 fields
}

sub sign {
   my $self= shift;
   # if agent is available via socket,
   #   connect if not connected yet, or die
   #   request signing of data
   # else
   #   look for ssh-keygen supporting '-Y sign', or die
   #   `ssh-keygen -Y sign -n $namespace -f key -q`
   # return result in a SecretBuffer
}

1;
