package Crypt::MultiKey::Key;
use strict;
use warnings;
use Carp;
use JSON;

=head1 DESCRIPTION

{ uuid: "1234-5678-12-123456-1234",
    pubkey: "base64.....",
    privkey: "base64.....",   /* encrypted */
    
    /* fields for password-encrypted privkey */
    pbkdf2_iter: N,
    salt: "base64.....",
    
    /* fields for yubikey chal/resp encrypted privkey */
    yubikey_serial: "...",
    
    /* fields for ssh-agent chal/resp encrypted privkey */
    ssh_agent_pubkey: "ssh-dsa HJGFKJHGJKHGKJHGJKHGJKGH Hostname"
  }

=cut

sub load_class_for_type {
   my ($class, $type)= @_;
   $type =~ /^[A-Za-z0-9_]\z/ or croak "Invalid key type '$type'";
   $class= "Crypt::MultiKey::Key::$type";
   if (!$class->can("new")) {
      (my $fname= $class . '.pm') =~ s,::,/,g;
      require $fname;
   }
   return $class;
}

sub new_from_file {
   my ($class, $path)= @_;
   open my $fh, '<', $path or croak "open($path): $!";
   my $data= eval { local $/; JSON->new->decode(scalar <$fh>) };
   defined $data or croak "exception while decoding JSON of $path: $@";
   defined $data->{type} or croak "Key data is missing 'type' field";
   $class= $class->load_class_for_type(delete $data->{type});
   $class->new(%$data);
}

sub new {
   my $class= shift;
   return $class->new_from_file(shift) if @_ == 1;
   my %args= @_;
   length $args{type} or croak "Key base-class constructor requires 'type'";
   $class= $class->load_class_for_type(delete $args{type});
   $class->new(%args);
}

1;
