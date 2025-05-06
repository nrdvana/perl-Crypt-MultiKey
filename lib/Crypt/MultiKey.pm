package Crypt::MultiKey;
# VERSION
# ABSTRACT: Encrypt a secret with multiple keys where any key can unlock it

=head1 SYNOPSIS

  use Crypt::MultiKey 'secret';
  
  # List available plugins for unlocking secrets
  say for Crypt::MultiKey->mechanisms;
  
  # List available plugins for applying secrets to systems
  say for Crypt::MultiKey->applications;
  
  my $secret= secret('/some/path/');
  $secret->unlock_interactive;  # prompts to unlock secret
  $secret->apply(ZFS => 'MY_POOL');

=head1 DESCRIPTION

There are lots of cases where you want N-factor auth, requiring both keys in order to unlock a
resource.  This is the inverse of that, where you want multiple ways to decrypt a secret.
You might call it 1/N-factor auth.

The use case this module was designed to solve was to allow encryped volumes on a server to be
unlocked with more than one method:

=over

=item * A SSH private key served by an Agent

=item * A Yubikey

=item * A very secure password stored offline

=back

Every time the server boots, it needs the encrypted volumes unlocked.  If it is online, it
contacts the central key server and the key server is in posession of a SSH key which can be used
to decrypt the secret.  If the key server is offline, an admin with a SSH key can connect and
forward their SSH agent to unlock the volumes.  If an admin can't connect remotely or can't be
reached, someone on-site with a physically secure Yubikey can retrieve and plug in the key and
then udev rules automatically trigger to unlock the encrypted volumes.  If all else fails, someone
can go to the safe deposit box and get the sheet of paper where the secret is written.

This module collection facilitates the described workflow.

=head1 DESIGN

This module uses OpenSSL to encrypt and decrypt arbitrary length data, using AES.  The key for AES
is created in memory, used to encrypt your actual secret, and then itself encrypted with one or
more mechanisms.  The encrypted secret and multi-encrypted AES key are then stored in a directory.
The encrypted secret is named 'secret' and each encryption of the AES key is a file named
`key-$name.json`.

Each encryption of the AES key is described by the following attributes:

=over

=item name

A human-readable label

=item mechanism

The name of a plugin perl module

=item public_key

For mechanisms using public/private keys, this holds the public key in its native format, to be
parsed by external tools.  Mechanisms that use public keys allow changing the AES key without
re-applying the various auth factors.

Mechanisms that lack this attribute will require you to re-initialize that entry, such as by
plugging in the Yubikey.

=item salt

Any mechanism that involves hashing a password will apply this string of bytes to the password
in some way to prevent an attacker from pre-calculating a database of hashes.

=back

=head2 

=cut

use strict;
use warnings;
use Exporter 'import';
our @EXPORT_OK= qw( secret );

sub secret {
	require Crypt::MultiKey::Secret;
	if (@_ != 1) {
		return Crypt::MultiKey::Secret->new(@_);
	} elsif (ref $_[0] eq 'HASH') {
		return Crypt::MultiKey::Secret->new($_[0]);
	} elsif (ref $_[0] eq 'SCALAR') {
		return Crypt::MultiKey::Secret->new_from_string($_[0]);
	} else {
		return Crypt::MultiKey::Secret->new_from_file($_[0]);
	}
}

1;
