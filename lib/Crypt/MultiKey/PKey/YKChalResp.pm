package Crypt::MultiKey::PKey::YKChalResp;
# VERSION
# ABSTRACT: use YubKey challenge/response to unlock a private key

use strict;
use warnings;
use Carp;
use Symbol ();
use MIME::Base64 qw( encode_base64 decode_base64 );
use IPC::Open3 ();
use Crypt::SecretBuffer qw( secret HEX ISO8859_1 );
use Crypt::MultiKey ();
use Crypt::MultiKey::YubicoOTP;
use parent 'Crypt::MultiKey::PKey';

=head1 DESCRIPTION

This module uses the L<YubiKey OTP protocol|Crypt::MultiKey::YubicoOTP>'s
challenge/response feature to generate a password to decrypt the private half of a PKey.
Not all YubiKeys support the OTP protocol, particularly the cheaper "Security Key" variety.
(for those, see L<Crypt::MultiKey::PKey::FIDO2>)
You must have also configured one of the slots on your YubiKey to allow challenge/response.

Linux support is available via XS.  Other platforms are supported by the external tools
L<ykinfo(1)> and L<ykchalresp(1)>, which you must install separately.

=head1 SECURITY MODEL

This mechanism of challenge/response basically just takes a local string of public bytes and a
string of secret bytes within the YubiKey, runs them both through SHA-1 within the device, and
returns a portion of the result.
This mode of operation is just making use of the YubiKey as an un-copyable string of bytes which
can only be hashed when touching the button of the device.
Anyone who can see the contents of your PKey PEM file can reconstruct the challenge, and if they
then have access to the YubiKey (including a button press) they can capture the response, and
use it to decrypt the PKey.
Someone who knows the correct response could also build a fake USB device that emits the
correct response without actually knowing the secret.

For comparison, L<FIDO2|Crypt::MultiKey::PKey::FIDO2> authenticates the identify of the hardware
device so that it can't be faked even if an attacker knows the correct response for a challenge.
The downside with FIDO2 is that it requires an enrollment process and credential stored on the
device for each enrolled PKey.  This C<YKChalResp> key can be set up without storing anything
on the authenticator device.

=cut

sub protection_scheme {
   @_ > 1? $_[0]->_set_protection_scheme($_[1]) : 'YKChalResp';
}

=attribute yubikey_serial

This identifies which YubiKey to issue the challenge to.  You can see a
YubiKey's serial number (from the OTP protocol) using C<< ykinfo -s >>.

If assigned prior to L</encrypt_private>, it forces that method to use only that
key for the encryption.  Otherwise, that method uses the first available key and
assigns this attribute with the serial of whichever one it used.

=cut

sub yubikey_serial {
   @_ > 1? shift->_set_yubikey_serial(@_) : $_[0]{yubikey_serial};
}
sub _set_yubikey_serial {
   my ($self, $value)= @_;
   if (defined $value) {
      $value =~ /^\d+\z/
         or croak "yubikey_serial must be numeric";
      $value =~ /[^0]/
         or warn "yubikey_serial is zero, which means we won't know if the correct key is present\n";
   }
   $self->{yubikey_serial}= $value;
   $self;
}

=attribute yubikey_slot

Either C<1> or C<2>.  The YubiKey OTP protocol defines two slots which can be
configured for challenge/response.  The default is to attempt them both and record
which slot was used.

=cut

sub yubikey_slot {
   @_ > 1? shift->_set_yubikey_slot(@_) : $_[0]{yubikey_slot};
}
sub _set_yubikey_slot {
   my ($self, $val)= @_;
   !defined $val || $val =~ /^[12]\z/
      or croak "yubikey_slot must be '1' or '2'";
   $self->{yubikey_slot}= $val;
   $self;
}

=attribute kdf_salt

Random salt (base64) used to build the YubiKey challenge.

=cut

sub kdf_salt { @_ > 1? shift->_set_kdf_salt(@_) : $_[0]{kdf_salt} }
sub _set_kdf_salt {
   my ($self, $val)= @_;
   $val =~ /^[\/A-Za-z0-9+]+=*\z/
      or croak "expected base64";
   $self->{kdf_salt}= $val;
   $self;
}

sub _update_device_list {
   my $self= shift;
   $self->{_device_list}= [ Crypt::MultiKey::YubicoOTP::list_devices() ];
}

=method list_yubikeys

Return a list of hashrefs about any connected YubiKeys (limited to those which
support the OTP protocol)

=cut

sub list_yubikeys {
   my $self= shift;
   $self->_update_device_list;
   return @{ $self->{_device_list} || {} };
}

=method can_obtain_private

Returns true if the configured YubiKey serial number is connected.

=cut

sub can_obtain_private {
   my $self= shift;
   my $want= $self->yubikey_serial;
   defined $want && grep $_->serial == $want, @{ $self->_update_device_list };
}

=method obtain_private

Pass the challenge to the configured YubiKey, and L</decrypt_private> using the
response as a password.

=cut

sub obtain_private {
   my $self= shift;
   unless ($self->has_private) {
      defined $self->private_encrypted
         or croak "Can't decrypt an empty private_encrypted attribute";
      defined $self->yubikey_serial && defined $self->yubikey_slot
         or croak "Can't obtain private key without attributes yubikey_serial and yubikey_slot";
      my $pw= $self->_derive_password_from_yubikey;
      $self->decrypt_private($pw);
   }
}

=method encrypt_private

Encrypt the private key using a password derived from YubiKey challenge/response.

  $pkey->encrypt_private;
  $pkey->encrypt_private($serial_number);

If no serial is provided, this picks the first detected key and records its serial.

=cut

sub encrypt_private {
   my ($self, $selector)= @_;
   my $serial;
   if (defined $selector) {
      $selector =~ /^\d+\z/
         or croak "YubiKey selector must be a numeric serial";
      $serial= $selector;
   }
   my $pw= $self->_derive_password_from_yubikey($serial);
   $self->next::method($pw, 0);
}

# If serial / slot / salt are not defined, they will be initialized.
# Subsequent calls will return the same password.
sub _derive_password_from_yubikey {
   my ($self, $serial, $slot)= @_;
   my ($bytes, $salt);
   if (defined $self->kdf_salt) {
      $salt= decode_base64($self->kdf_salt);
   } else {
      secret(append_random => 16)->span->copy_to($salt);
      $self->kdf_salt(encode_base64($salt, ''));
   }
   # ykchalresp challenge is a max of 64 bytes.  The salt ensures a unique
   # challenge per PKey (in case PKey was used for something else).  Including
   # the public key ensures that we aren't just feeding a literal value
   # into the yubikey that may have been tampered with as some sort of attack.
   length($salt) == 16 or croak "Salt must be 16 bytes";
   $self->_export_spki(my $raw_pubkey_bytes);
   $bytes= Crypt::MultiKey::sha256($raw_pubkey_bytes, $salt);
   # Search for the required YubiKey, or if this is the first time, look for a
   # usable slot on a YubiKey.
   $serial //= $self->yubikey_serial;
   $slot //= $self->yubikey_slot;
   for my $device (@{ $self->_update_device_list }) {
      next if defined $serial && $device->serial ne $serial;
      my $response= defined $slot? $device->challenge_response($slot, $bytes)
         : eval { $slot= 1; $device->challenge_response(1, $bytes) }
           // eval { $slot= 2; $device->challenge_response(2, $bytes) }
           // do { carp "Neither slot of YubiKey ".$device->serial." supports OTP chalresp"; next; };
      $self->yubikey_serial($device->serial);
      $self->yubikey_slot($slot);
      my %kdf_params= (
         size => 32,
         kdf_info => 'Crypt::MultiKey::PKey::YKChalResp',
         kdf_salt => $salt,
      );
      return Crypt::MultiKey::hkdf(\%kdf_params, $response);
   }
   croak "Required YubiKey ($serial) is not connected" if defined $serial;
   croak "No YubiKey supporting OTP is connected";
}

# When parent class loads PEM file, capture additional attributes
sub _import_pem_headers {
   my ($self, $pem)= @_;
   $self->next::method($pem);
   $self->yubikey_serial($pem->headers->{cmk_yubikey_serial});
   $self->yubikey_slot($pem->headers->{cmk_yubikey_slot});
   $self->kdf_salt($pem->headers->{cmk_kdf_salt});
}

sub _export_pem_headers {
   my ($self, $pem)= @_;
   croak "Cannot export ::PKey::YKChalResp without selecting yubikey_serial and yubikey_slot"
      unless defined $self->yubikey_serial && defined $self->yubikey_slot;
   croak "Cannot export ::PKey::YKChalResp without first encrypting the private half"
      unless defined $self->private_encrypted;
   $self->next::method($pem);
   $pem->headers->append(cmk_yubikey_serial => $self->yubikey_serial);
   $pem->headers->append(cmk_yubikey_slot => $self->yubikey_slot);
   $pem->headers->append(cmk_kdf_salt => $self->kdf_salt);
}

1;
