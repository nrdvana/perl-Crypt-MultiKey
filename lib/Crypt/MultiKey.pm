package Crypt::MultiKey;
# VERSION
# ABSTRACT: Encrypt secrets with multiple keys, where any key can unlock them

=head1 SYNOPSIS

  use Crypt::MultiKey;
  use Crypt::SecretBuffer 'secret';
  
  my $repo= Crypt::MultiKey->new('/some/path/');
  say $_->name for $repo->vault_list;
  say $_->name for $repo->key_list;

  # Create a password-based key
  print "Enter your password: ";
  my $pw= secret;
  $pw->append_console_line(STDIN) or die "aborted";
  $repo->new_key('master_pw', Password => { password => $pw });
  
  # Create a key that can be activated by your SSH agent
  $repo->new_key("ssh-$username", SSHAgentSignature => { pubkey => $pubkey_string });
  
  # Create a key that can be activated by the holder of the key to a SSL certificate
  $repo->new_key('our_keyserver', KeyServer => { url => $url });
  
  # Create a vault and store into it the secret used to encrypt a ZFS dataset
  my $vault= $repo->new_vault('ZFS-key');
  $vault->pair_with($repo->key_list);
  my $zfs_key= secret(append_random => 16);
  $vault->store('zfs_key', $zfs_key);
  
  ... # later,
  
  my $vault= $repo->vault('ZFS-key');
  $vault->unlock(interactive => 1); # try ssh agent, try key server, fall back to pw
  my $zfs_key= $vault->load('zfs_key');

=head1 DESCRIPTION

This module is an implementation of a "key wrapping scheme" (such as done by age or libsodium),
but with a focus on applying it to specifc workflows rather than being just an abstract tool.

Since there are so many "secrets" and "keys" involved in this system, I'm using the following
metaphor to help disambiguate them:

=over

=item Vault

A Vault object is an encrytion context that can be used to encrypt or decrypt user data, and is
initially created with a secret AES symmetric key in an "unlocked" state.  The Vault
conceptually contains a key/value dictionary of secrets which can be loaded and stored while
the vault is unlocked.  The Vault may be paired with any number of Key objects, and pairing can
only occur while the Vault is unlocked.  *Any* paired key can unlock the Vault.

Vaults are stored in a JSON file, with the encrypted name/value data stored in hexidecimal.
For larger encrypted data (over a configurable threshold), a directory of the same name of the
Vault file is created and the large data streams are written to files named with GUIDs.
The names of data stored in the Vault cannot be determined without first unlocking the Vault.
The name/value data stored in the Vault is not intended to be a performant database, but rather
just a simple convenient way to store more than one thing in the same Vault.  The Vault is
re-encrypted and written to disk after every ->store operation.

=item Key

The Key objects are wrappers around a public/private key system, and then the private half
is either encrypted or stored separately.  A Key is "enabled" when the private half is known
and "disabled" when it isn't.  The private half is used to decrypt the AES key of a Vault.

The fact that every Key has a public component is what allows them to be paired with a Vault
even while they are disabled.  The practical application of this is that you can establish a
Key for a hardware device, or a password physically stored in a safe deposit box, and then
later pair this Key with new Vaults without first needing to enable it.

=back

=head2 Motivation

The use case this module was designed to solve was to allow encryped volumes on a server to be
unlocked with more than one method:

=over

=item * A key server, using SSL certs for authentication

=item * A SSH private key from the Agent of a logged-in user

=item * A Yubikey

=item * A very secure password stored offline

=back

Every time the server boots, it needs the encrypted volumes unlocked.  If it is online, it
contacts the central key server and the key server is able to send a response that allows the
activation of that key.   If the key server is offline or unavailable, an admin with a SSH key
can connect and forward their SSH agent to unlock the volumes.  If an admin can't connect
remotely or can't be reached, someone on-site with a physically secure Yubikey can retrieve and
plug in the key and then udev rules automatically trigger to unlock the encrypted volumes.
If all else fails, someone can go to the safe deposit box and get the sheet of paper where the
secret is written.

This module collection facilitates all of that.

=head2 Design

A typical directory of MultiKey files might look like:

  /etc/mk/
  /etc/mk/vault-root.json
  /etc/mk/vault-root/12345678-1234-12-12-123456789ABCDEF.enc
  /etc/mk/key-master_pw.json
  /etc/mk/key-yubikey.json
  /etc/mk/key-our_company_keyserver.json
  /etc/mk/key-ssh_user1.json

Vaults start with C<"vault-">.  In this case there is only one, named C<"root">.
The contents of the vault named "root" could include any number of name/value pairs, but at
least one of them was large enough to get written out as its own file in the C<< vault-root/ >>
subdirectory.  The vault json includes details about which keys it has been paired with, such
as the salt that was used in the pairing for the encryption context.  It references the keys
by UUID rather than filename, so you can rename the key files without breaking things.

Keys are stored in files with the prefix C<< key- >>.  In this example, there is one key named
'master_pw' encrypted with a password, one key named 'yubikey' that is tied to a specific USB
hardware device, one key named 'our_company_keyserver' which refers to a different host by URL,
and a key named 'ssh_user1' which is linked to the ssh key of user1.  Each key json contains
the UUID, and public key components of the public/private keypair.  It will also contain details
which algorithm to use to enable it.

While you *can* put all the files into a standard directory layout like this, you are not
required to.  You could pair a key with a vault then completely remove the key file from the
filesystem to e.g. a USB stick.  Later, your perl script could point a MultiKey instance at the
file on the removable media to make the key available as if it had been in the directory with
the others.

=cut

use strict;
use warnings;
use Carp;
use parent qw( DynaLoader );
sub dl_load_flags {0x01} # Share extern symbols with other modules
__PACKAGE__->bootstrap;

sub new_vault {
   my ($self, $name)= splice @_, 0, 2;
   my $path= $self->_subpath("vault-$name.json");
   $self->{vault}{$name} || -e $path
      and croak "Path already exists: $path";
   my @opts= ( path => $path, name => $name, ref $_[0] eq 'HASH'? %{$_[0]} : @_ );
   Crypt::MultiKey::Vault->new(@opts)
}

sub vault {
   my ($self, $name)= @_;
   $self->{vault}{$name} //= do {
      my $path= $self->_subpath("vault-$name.json");
      return undef unless -f $path;
      Crypt::MultiKey::Vault->new_from_file($path);
   };
}

sub new_key {
   my ($self, $name, $type)= splice @_, 0, 3;
   my $path= $self ->_subpath("key-$name.json");
   $self->{key}{$name} || -e $path
      and croak "Key '$name' already exists";
   my @opts= ( path => $path, name => $name, ref $_[0] eq 'HASH'? %{$_[0]} : @_ );
   Crypt::MultiKey::PKey->load_class_for_type($type)->new(@opts)
}

sub key {
   my ($self, $name)= @_;
   $self->{key}{$name} //= do {
      my $path= $self->_subpath("key-$name.json");
      return undef unless -f $path;
      Crypt::MultiKey::PKey->new_from_file($path);
   };
}

# For security, only permit loading packages which are known to be installed
our %_lazy_load_ok= map +($_ => 1), qw(
   Crypt::MultiKey::PKey::Unencrypted
   Crypt::MultiKey::PKey::Manual
   Crypt::MultiKey::PKey::Password
   Crypt::MultiKey::PKey::Yubikey
   Crypt::MultiKey::PKey::SSHAgentSignature
);

sub _lazy_load_class {
   my ($class)= @_;
   croak "For security, class '$class' cannot be 'require'd on demand"
      unless $_lazy_load_ok{$class};
   (my $fname= $class . '.pm') =~ s,::,/,g;
   require $fname;
   return $class;
}

require Crypt::MultiKey::PKey;

1;
