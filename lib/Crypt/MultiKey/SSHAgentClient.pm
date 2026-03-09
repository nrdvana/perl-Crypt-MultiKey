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

=cut

use strict;
use warnings;
use Carp;
use Crypt::SecretBuffer qw( secret );
use IO::Socket::UNIX;
use MIME::Base64;
use File::Spec;
use File::Temp;
use IPC::Open3;
use Symbol;

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

Path of SSH agent socket.  Defaults to C<< $ENV{SSH_AUTH_SOCK} >>.

=attribute ssh_add_path

Path to binary 'ssh-add'

=attribute ssh_keygen_path

Path to binary 'ssh-keygen'

=cut

sub _set_ssh_auth_sock   { $_[0]{ssh_auth_sock}= $_[1] }
sub _set_ssh_add_path    { $_[0]{ssh_add_path}= $_[1] }
sub _set_ssh_keygen_path { $_[0]{ssh_keygen_path}= $_[1] }

sub _build_ssh_auth_sock {
   return $ENV{SSH_AUTH_SOCK};
}

sub _build_ssh_add_path {
   return $_[0]->_find_command('ssh-add');
}

sub _build_ssh_keygen_path {
   return $_[0]->_find_command('ssh-keygen');
}

sub ssh_auth_sock {
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

=cut

sub get_key_list {
   my $self= shift;
   my $list= eval { $self->_get_key_list_via_agent_socket };
   return $list if $list;
   return $self->_get_key_list_via_ssh_add;
}

=method sign

  my $signature_bytes= $agent->sign($pubkey, $data_bytes, $namespace);

The C<$pubkey> can be either the base64 string of the public key, or the hashref for that key
returned by C<get_key_list>.  C<$data_bytes> can be any scalar containing bytes.
The C<$namespace> defaults to C<"Crypt::MultiKey">.

=cut

sub sign {
   my ($self, $pubkey, $data, $namespace)= @_;
   $namespace= 'Crypt::MultiKey' unless defined $namespace;
   croak "Expected a public key argument" unless defined $pubkey;
   croak "Expected data bytes argument" unless defined $data;

   my $pubkey_base64= ref $pubkey eq 'HASH'? $pubkey->{pubkey_base64} : $pubkey;
   croak "Public key must be base64 or hash with pubkey_base64" unless defined $pubkey_base64;

   my $sig= eval { $self->_sign_via_agent_socket($pubkey_base64, $data, $namespace) };
   return $sig if defined $sig;
   return $self->_sign_via_ssh_keygen($pubkey_base64, $data, $namespace);
}

sub _get_key_list_via_agent_socket {
   my $self= shift;
   my $sock= $self->_agent_socket_or_die;
   my $resp= $self->_agent_request($sock, chr(11));
   my $msg_type= ord substr($resp, 0, 1, '');
   croak "ssh-agent rejected identities request"
      if $msg_type == 5;
   croak "Unexpected ssh-agent response type $msg_type"
      unless $msg_type == 12;

   my $count= _unpack_u32(substr($resp, 0, 4, ''));
   my @keys;
   my $i;
   for ($i= 0; $i < $count; $i++) {
      my $blob= _parse_ssh_string(\$resp);
      my $comment= _parse_ssh_string(\$resp);
      my ($type, $key_b64)= _split_pubkey_blob($blob);
      push @keys, {
         type          => $type,
         pubkey_base64 => $key_b64,
         comment       => $comment,
      };
   }
   return \@keys;
}

sub _sign_via_agent_socket {
   my ($self, $pubkey_base64, $data, $namespace)= @_;
   my $sock= $self->_agent_socket_or_die;
   my $blob= MIME::Base64::decode_base64($pubkey_base64);
   croak "Invalid public key base64"
      unless defined $blob && length $blob;

   # Build SSH2_AGENTC_SIGN_REQUEST with key blob and payload bytes.
   my $payload= chr(13)
      ._pack_ssh_string($blob)
      ._pack_ssh_string($data)
      .pack('N', 0);

   # Read sign response directly into SecretBuffer so signature bytes avoid perl heap.
   return $self->_agent_sign_request_secret($sock, $payload);
}

sub _get_key_list_via_ssh_add {
   my $self= shift;
   my $path= $self->ssh_add_path
      or croak "Unable to locate ssh-add for fallback mode";

   my ($out, $err, $rc)= _run_cmd($path, '-L');
   croak "ssh-add -L failed: $err"
      if $rc;

   my @keys;
   while ($out =~ /^(\S+)\s+(\S+)\s*(.*)$/mg) {
      push @keys, {
         type          => $1,
         pubkey_base64 => $2,
         comment       => $3,
      };
   }
   return \@keys;
}

sub _sign_via_ssh_keygen {
   my ($self, $pubkey_base64, $data, $namespace)= @_;
   my $path= $self->ssh_keygen_path
      or croak "Unable to locate ssh-keygen for fallback mode";

   my $pubkey_type= _pubkey_type_from_base64($pubkey_base64);

   my $pubkey_file= File::Temp->new(SUFFIX => '.pub');
   print $pubkey_file $pubkey_type.' '.$pubkey_base64." cmk\n"
      or croak "Failed writing temporary public key file";
   close $pubkey_file or croak "Failed closing temporary public key file";

   my $data_file= File::Temp->new();
   binmode $data_file;
   print $data_file $data
      or croak "Failed writing temporary signing payload";
   my $data_path= $data_file->filename;
   close $data_file or croak "Failed closing temporary signing payload";

   my ($out, $err, $rc)= _run_cmd(
      $path,
      '-Y', 'sign',
      '-n', $namespace,
      '-q',
      '-f', $pubkey_file->filename,
      $data_path,
   );
   croak "ssh-keygen -Y sign failed: $err"
      if $rc;

   my $sig_path= $data_path.'.sig';
   my $sig= secret(load_file => $sig_path);
   unlink $sig_path;
   return $sig;
}

sub _agent_socket_or_die {
   my $self= shift;
   my $sock_path= $self->ssh_auth_sock
      or croak "SSH_AUTH_SOCK is not set";

   my $sock= IO::Socket::UNIX->new(
      Type => Socket::SOCK_STREAM(),
      Peer => $sock_path,
   );
   croak "Unable to connect to ssh-agent socket '$sock_path': $!"
      unless $sock;
   binmode $sock;
   return $sock;
}

sub _agent_request {
   my ($self, $sock, $payload)= @_;
   my $pkt= pack('N', length($payload)).$payload;
   my $written= syswrite($sock, $pkt);
   croak "Write to ssh-agent failed: $!"
      unless defined $written && $written == length($pkt);

   my $hdr= _read_exact($sock, 4);
   my $len= _unpack_u32($hdr);
   croak "ssh-agent returned oversized response"
      if $len > 8*1024*1024;
   return _read_exact($sock, $len);
}

sub _agent_sign_request_secret {
   my ($self, $sock, $payload)= @_;
   my $pkt= pack('N', length($payload)).$payload;
   my $written= syswrite($sock, $pkt);
   croak "Write to ssh-agent failed: $!"
      unless defined $written && $written == length($pkt);

   my $hdr= _read_exact($sock, 4);
   my $len= _unpack_u32($hdr);
   croak "ssh-agent returned oversized response"
      if $len > 8*1024*1024;
   croak "Malformed ssh-agent sign response"
      if $len < 1;

   my $type= _read_exact($sock, 1);
   $type= ord($type);
   my $remaining= $len - 1;

   if ($type == 5) {
      _discard_exact($sock, $remaining);
      croak "ssh-agent rejected sign request";
   }
   croak "Unexpected ssh-agent response type $type"
      unless $type == 14;
   croak "Malformed ssh-agent sign response"
      if $remaining < 4;

   my $sig_len= _unpack_u32(_read_exact($sock, 4));
   $remaining -= 4;
   croak "Malformed ssh-agent sign response"
      if $sig_len > $remaining;

   my $sig= secret;
   # Stream signature bytes directly into SecretBuffer in bounded chunks.
   my $want= $sig_len;
   while ($want > 0) {
      my $chunk= $want > 16384? 16384 : $want;
      my $n= $sig->append_sysread($sock, $chunk);
      croak "Unexpected EOF from ssh-agent"
         unless defined $n && $n > 0;
      $want -= $n;
      $remaining -= $n;
   }

   _discard_exact($sock, $remaining)
      if $remaining > 0;
   return $sig;
}

sub _read_exact {
   my ($fh, $len)= @_;
   my $buf= '';
   while (length($buf) < $len) {
      my $chunk;
      my $want= $len - length($buf);
      my $n= sysread($fh, $chunk, $want);
      croak "Unexpected EOF from ssh-agent"
         unless defined $n && $n > 0;
      $buf .= $chunk;
   }
   return $buf;
}

sub _discard_exact {
   my ($fh, $len)= @_;
   while ($len > 0) {
      my $chunk;
      my $want= $len > 8192? 8192 : $len;
      my $n= sysread($fh, $chunk, $want);
      croak "Unexpected EOF from ssh-agent"
         unless defined $n && $n > 0;
      $len -= $n;
   }
}

sub _pack_ssh_string {
   my ($bytes)= @_;
   return pack('N', length($bytes)).$bytes;
}

sub _parse_ssh_string {
   my ($ref)= @_;
   croak "Malformed ssh-agent response"
      if length($$ref) < 4;
   my $len= _unpack_u32(substr($$ref, 0, 4, ''));
   croak "Malformed ssh-agent response"
      if length($$ref) < $len;
   return substr($$ref, 0, $len, '');
}

sub _unpack_u32 {
   return unpack('N', $_[0]);
}

sub _split_pubkey_blob {
   my ($blob)= @_;
   my $tmp= $blob;
   my $type= _parse_ssh_string(\$tmp);
   my $b64= MIME::Base64::encode_base64($blob, '');
   return ($type, $b64);
}

sub _pubkey_type_from_base64 {
   my ($pubkey_base64)= @_;
   my $blob= MIME::Base64::decode_base64($pubkey_base64);
   croak "Invalid public key base64"
      unless defined $blob && length $blob;
   my ($type)= _split_pubkey_blob($blob);
   return $type;
}

sub _find_command {
   my ($self, $name)= @_;
   my $path= $ENV{PATH} || '';
   my @path= File::Spec->path;
   my @ext= ('');
   if ($^O =~ /MSWin32|cygwin/i) {
      my $pathext= $ENV{PATHEXT} || '.EXE;.BAT;.CMD;.COM';
      @ext= split /;/, $pathext;
      push @ext, '';
   }

   my $dir;
   for $dir (@path) {
      my $ext;
      for $ext (@ext) {
         my $candidate= File::Spec->catfile($dir, $name.$ext);
         return $candidate if -f $candidate && -x $candidate;
      }
   }
   return;
}

sub _run_cmd {
   my @cmd= @_;
   my ($wtr, $rdr, $err);
   $err= Symbol::gensym();
   my $pid= eval { IPC::Open3::open3($wtr, $rdr, $err, @cmd) };
   croak "Failed to execute '$cmd[0]': $@"
      unless $pid;
   close $wtr;
   local $/;
   my $out= <$rdr>;
   my $err_txt= <$err>;
   waitpid($pid, 0);
   my $rc= $?;
   return ($out || '', $err_txt || '', $rc);
}

1;
