package Crypt::MultiKey;
# VERSION
# ABSTRACT: Encrypt secrets with multiple keys, where any key can unlock them

=head1 SYNOPSIS

  use Crypt::MultiKey qw( repo lockbox key );
  
  # List available plugins for unlocking keys
  say for Crypt::MultiKey->key_mechanisms;
  
  # List available plugins for applying secrets to targets
  say for Crypt::MultiKey->applications;
  
  my $repo= repo('/some/path/');
  say $_->name for $repo->secret_list;
  say $_->name for $repo->key_list;
  
  $repo->new_key('pw',  Password => { source => \*STDIN });
  $repo->new_key($name2, SSHAgentSignature => { pubkey => $pubkey_string });
  $repo->new_key($name3, SSLCert => { cert_path => $path_to_cert });
  $repo->new_lockbox('ZFS-key', { data => \$scalar })->lock_with($repo->key_list);
  
  my $secret= $repo->secret('ZFS-key');
  # OR:
  my $secret= secret($path);
  $secret->unlock_interactive; # prompts to unlock secret
  $secret->apply(ZFS => $pool_name);

=head1 DESCRIPTION

This module implements a "key wrapping scheme" where secrets are encrypted with an internal
secret and then that secret is encrypted with one or more public keys, such that B<any> of the
private keys can unlock the secret to decrypt the data.  Further, the private keys can be
encrypted with a secret such as a SSH Agent signature, or Yubikey challenge-response.

Unlike some other tools, more secrets can be added later, automatically wrapped by each of the
known public keys.  Likewise, as long as you have one unlocked key, you can add additional keys
and apply wrappings to all existing secrets in the directory.

Finally, when it is time to unlock a secret, you can automatically scan whether any of the known
keys are unlocked or can be unlocked in the current environment (such as checking your ssh-agent
or looking for a Yubikey on the USB bus)

The use case this module was designed to solve was to allow encryped volumes on a server to be
unlocked with more than one method:

=over

=item * A key server, using SSL certs for authentication

=item * A SSH private key served by an Agent

=item * A Yubikey

=item * A very secure password stored offline

=back

Every time the server boots, it needs the encrypted volumes unlocked.  If it is online, it
contacts the central key server and the key server is in posession of a SSH key which can be used
to decrypt the secret.  If the key server is offline, an admin with a SSH key can connect and
forward their SSH agent to unlock the volumes.  If an admin can't connect remotely or can't be
reached, someone on-site with a physically secure Yubikey can retrieve and plug in the key and
then udev rules automatically trigger to unlock the encrypted volumes.  If all else fails,
someone can go to the safe deposit box and get the sheet of paper where the secret is written.

This module collection facilitates the described workflow.

=head1 DESIGN

This module uses OpenSSL to encrypt and decrypt arbitrary length data, using AES.  The key for
AES is created in memory, used to encrypt your actual secret, and then a wrapping of that key
is created using each of the public keys you previously created.  This way, any of the keys can
be used to decrypt their wrapping to retrieve the AES key, and decrypt the original data.

This module consists of a "Repo" (directory) containing Keys (key-XXXXX.json) and secrets
(secret-XXXXX.json) and sometimes a separate file for the secret data (secret-XXXXX.aes) to
avoid a large secret needing to be encoded as base64 in json.

The Key json generally looks like:

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

And each secret generally looks like:

  { uuid: "1234-5678-12-123456-1234",
    locks: [
      {
        key: $uuid, /* references a Key file by UUID */
        pubkey: "base64.....",
        nonce: "base64.....",
        gcm_tag: "base64.....",
        hkdf_salt: "base64.....",
        aes_key_enc: "base64.....",
      },
      ... /* for each key which can unlock the secret */
    ],
    data: "base64....."                      /* if secret is small */
    data: { uri: "file:secret-Example.enc" } /* if secret is large */
  }

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
