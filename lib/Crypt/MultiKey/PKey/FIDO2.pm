package Crypt::MultiKey::PKey::FIDO2;
# VERSION
# ABSTRACT: Use FIDO2 hmac-secret as a password to encrypt/decrypt the private key

=head1 DESCRIPTION

FIDO2 is a protocol for hardware authenticators like YubiKeys, particularly in the cheaper
"Security Key" variety.  FIDO2 is primarily an I<authentication> protocol, not a protocol for
shared secrets or encryption/decryption, but FIDO2 provides an extension called "hmac-secret"
which allows an application to derive deterministic secret bytes from the authenticator.
This can be used as a password, and plugged into the L<PKey encrypt_private|Crypt::MultiKey::PKey/encrypt_private>
method, which is what this subclass does.  In the simplest sense, this module uses a FIDO2
authenticator like a password written on a USB drive, but where the device can't be copied and
the password can't be seen without knowing the credential_id and a physical touch on the device.
This system is not as secure as if the authenticator was implementing the private half of the
PKey internally, but it's a reasonable implementation for the cheaper "Security Key" devices
that only support FIDO2.  It's also fairly convenient compared to some of the other protocols.

Applications "enroll" with the authenticator by creating a "credential", and then can use that
credential to make requests called "assertions".  An application constructs an assertion request
and sends it to the authenticator which may then prompt the user for confirmation (like a button
press or biometric verification) before producing the response.
The response may be a success (containing authenticator data, a signature proving possession of
the credential private key, and optionally extension outputs such as hmac-secret), or various
failure codes such as if the credential didn't exist on that device or the user didn't approve
the request.
This implementation needs to derive cryptographically secure bytes to use as a password to
decrypt the private half of the PKey.  The authenticator generates a per-credential secret
("CredRandom") during enrollment.  During an assertion request the application supplies a salt
value and the authenticator returns C<< HMAC-SHA256(CredRandom, salt) >> which is suitable as a
password.  The CredRandom is unique per credential, so every enrollment essentially generates
a new password and maintains that password unless the enrollment is deleted.  The CredRandom
value never leaves the authenticator, so it cannot be copied.

=head2 Workflow

=over

=item Enroll

The hardware key must be present.  FIDO2 devices cannot be identified by any kind of serial
number, and the only way to differentiate which one the user wants to use is by prompting the
user to touch one.  So, ideally have *only* the key you want to use plugged in, so this module
only has one to choose from.

Call L</encrypt_private>.  This will request creation of a FIDO2 credential from the hardware
key (which requires a button press on the device) and store that in attribute
L</fido2_credential_id>.  There are several options to configure for this process; see the
documentation of that method.

It will then ask the hardware key to perform C<hmac-secret> using that credential (possibly
requiring another button press), passing the result through HKDF to generate the password for
the parent class's C<encrypt_private> method.

Note that authenticators typically have a limited capacity for credentials or credential-related
state.  This may be as small as a few dozen.  You may wish to enroll one PKey object with a
hardware key and then copy the serialized PEM file of the PKey to each environment where that
hardware key will be used with C<Crypt::MultiKey>, rather than enrolling a new PKey object in
each environment.  Of course, if the decrypted private half of that PKey leaks in one
environment then it can be used in all of them, so choose carefully when to copy a PKey and
when to enroll a new one.

=item Check

The method L</can_obtain_private> will return true if I<any> FIDO2 key with matching device type
(the FIDO2 AAGUID) is present in the system.  FIDO2 devices are anonymous, with no type of
serial number that could identify an individual device, so if a similar device is plugged in
this can return true even if the device with the credential is not present.  It is not possible
to check for existence of a credential within a device without possibly triggering a
user-presence or user-validation test (button press, biometric scan) so a passive check method
like C<can_obtain_private> can't attempt that.

=item Decrypt

Call L</obtain_private> to issue an assertion request against each connected authenticator with
an AAGUID matching the one seen during the Enroll step.  If the authenticator possesses the
L</fido2_credential_id>, after a button press (or biometric scan, etc) it will return the HMAC
result and this module will proceed to decrypt the private half of the PKey.

=item Multiple Keys

If you have multiple ::PKey::FIDO2 objects that are candidates for unlocking a Coffer or Vault,
testing them one at a time could potentially require multiple button presses by the holder of
the hardware key as each credential is tested.  To improve the user experience, all of the
C<fido2_credential_id> can be bundled into a single FIDO2 assertion and then a single hardware
key button press can test all of them at once.  To do this, call class method
L</try_all_obtain_private> with a list of all the PKey objects.  If the authenticator contains
one of those credentials it will let us know which one, and the result of the C<hmac-secret>
on that credential's secret.  The method then decrypts the PKey object associated with that
credential_id.

=back

=cut

use v5.10;
use warnings;
use Carp;
use Scalar::Util qw( blessed );
use MIME::Base64 qw( encode_base64 decode_base64 );
use Crypt::SecretBuffer qw( secret );
use Crypt::MultiKey::FIDO2;
use parent 'Crypt::MultiKey::PKey';

sub protection_scheme {
   @_ > 1? $_[0]->_set_protection_scheme($_[1]) : 'FIDO2';
}

=attribute fido2_credential

The credential created by the FIDO2 enrollment process.  The fields must include C<id> (the
raw bytes of the credential ID) and C<pubkey> (the OpenSSL SubjectPublicKeyInfo encoding of the
credential public key) and optionally C<cose_alg> if the algorithm is not C<"ES256">.

=attribute fido2_aaguid

The AAGUID of the authenticator which created the FIDO2 credential.  This is only unique per
device model, but (so long as your devices aren't all the identical model) it can help narrow
the detection of whether the correct key is present.

=over

=item fido2_aaguid_hex

Accessor for the standard GUID hex notation of attribute C<fido2_aaguid>.

=back

=attribute challenge

The sha256 of this string is sent to the authenticator as the value to perform HMAC on.
The default is C<"Crypt::MultiKey::PKey::FIDO2">.
You can change this to something other than the default, but beware that it can limit your
ability to efficiently match a ::PKey::FIDO2 object to the corresponding authenticator.
If you want to issue challenges for multiple ::PKey::FIDO2 objects in a single request to the
authenticator, they all need to have the same value for C<challenge>.

=attribute kdf_salt

Random bytes that get combined with the C<hmac-secret> response from the authenticator before
performing decryption of the private half of the PKey.

=cut

sub fido2_credential {
   @_ > 1? shift->_set_fido2_credential(@_) : $_[0]{fido2_credential};
}
sub _set_fido2_credential {
   my ($self, $val)= @_;
   ref $val eq 'HASH' or croak "fido2_credential must be a hahref";
   defined $val->{id} or croak "fido2_credential must have ->{id}";
   defined $val->{pubkey} or croak "fido2_credential must have ->{pubkey}";
   $self->{fido2_credential}= $val;
}

sub fido2_aaguid {
   @_ > 1? shift->_set_fido2_aaguid(@_) : $_[0]{fido2_aaguid};
}
sub _set_fido2_aaguid {
   my ($self, $val)= @_;
   length $val eq 16 or croak "guid must be 16 bytes (not hex)";
   $self->{fido2_aaguid}= $val;
}

sub fido2_aaguid_hex {
   $_[0]->_set_fido2_aaguid(Crypt::MultiKey::FIDO2::_parse_guid($_[1]))
      if @_ > 1;
   Crypt::MultiKey::FIDO2::_format_guid($_[0]->fido2_aaguid);
}

sub challenge {
   @_ > 1? shift->_set_challenge(@_) : ($_[0]{challenge} // 'Crypt::MultiKey::PKey::FIDO2')
}
sub _set_challenge {
   $_[0]{challenge}= $_[1];
}

sub kdf_salt {
   @_ > 1? shift->_set_kdf_salt(@_) : $_[0]{kdf_salt}
}
sub _set_kdf_salt {
   !defined $_[1] or length $_[1] eq 16
      or croak "kdf_salt must be 16 bytes";
   $_[0]{kdf_salt}= $_[1];
}

=method create_credential

  $pkey->create_credential;            # use first available device
  $pkey->create_credential($device);   # use specified device
  $pkey->create_credential($dev_path); # resolve /dev/ path to device

This performs FIDO2 enrollment on the specified device, storing the results into the attributes
of this object.  This is called automatically by C<encrypt_private> unless the credential was
already created.

=cut

sub _resolve_device {
   my ($self, $device_spec)= @_;
   if (!$device_spec) { # take first available
      my @devs= Crypt::MultiKey::FIDO2::list_devices()
         or croak "No FIDO2 devices found";
      return $devs[0];
   } elsif (blessed($device_spec) && $device_spec->isa('Crypt::MultiKey::FIDO2::Device')) {
      return $device_spec;
   } else {
      return Crypt::MultiKey::FIDO2::Device->new($device_spec);
   }
}

sub create_credential {
   my ($self, $device_spec)= @_;
   my $dev= $self->_resolve_device($device_spec);
   my $cred= $dev->make_hmac_secret_credential(
      user_name => __PACKAGE__,
      user_display_name => __PACKAGE__
   );
   $self->fido2_credential($cred);
   $self->fido2_aaguid($dev->aaguid);
   return $self;
}

=method encrypt_private

  $pkey->encrypt_private;          # new credential, or find device with credential
  $pkey->encrypt_private($device); # specify device to use

Calls L</create_credential> (unless L</fido2_credential> was already defined) then requests
the password from the authenticator, then encrypts the private half of this PKey.  It does not
clear the private half of this PKey.

=cut

sub encrypt_private {
   my ($self, $device_spec)= @_;
   croak "private half of key is not loaded"
      unless $self->has_private;
   my (@devs, $salt_bytes, $pw);
   if (defined $self->fido2_credential) {
      # If user specified a device, try only that one,
      # else try all devices with the right aaguid.
      if ($device_spec) {
         @devs= ( $self->_resolve_device($device_spec) );
      } else {
         @devs= grep $_->aaguid eq $self->fido2_aaguid, Crypt::MultiKey::FIDO2::list_devices()
            or croak "No device present with matching aaguid"
      }
   } else {
      @devs= ( $self->_resolve_device($device_spec) );
      $self->create_credential($devs[0]);
   }
   my $hmac_secret= $self->_get_hmac_secret(\@devs)
      or croak "The fido2_credential was not acknowledged by the device";
   # It worked, so generate fresh salt and then continue with encryption.
   secret(append_random => 16)->span->copy_to($salt_bytes);
   $self->kdf_salt($salt_bytes);
   $pw= $self->_derive_password($hmac_secret);
   $self->next::method($pw, 0);
}

=method can_obtain_private

Returns true if FIDO2 support is available and at least one FIDO2 device with a matching
L</fido_aaguid> is connected to the system.

=cut

sub can_obtain_private {
   my $self= shift;
   Crypt::MultiKey::FIDO2::enabled()
      && defined $self->fido2_aaguid
      && !!grep $_->aaguid eq $self->fido2_aaguid, Crypt::MultiKey::FIDO2::list_devices();
}

=method obtain_private

  $pkey->obtain_private;                          # find device, request hmac-secret
  $pkey->obtain_private(hmac_secret => $secret);  # supply hmac_secret result

This iterates the FIDO2 devices matching the C<fido2_aaguid> looking for one that can answer
the L<< C<hmac-secret> challenge|Crypt::MultiKey::DISO2::Device/assert_hmac_secret >>.
On success, it uses the secret to calculate the password to
L<decrypt_private|Crypt::MultiKey::PKey/decrypt_private>.
Dies on failure.

You can specify the C<hmac_secret> to avoid talking to a device at all.  This is helpful when
you are querying the device directly and then want to apply the results to one or more PKey
objects.

=cut

sub obtain_private {
   my ($self, %opts)= @_;
   return $self if $self->has_private;
   defined $self->private_encrypted
      or croak "Can't decrypt an empty private_encrypted attribute";

   # caller can supply the hmac_secret for the case of checking multiple credentials
   # against a single authenticator device, then unlocking the one that matched.
   my $hmac_secret= $opts{hmac_secret};
   unless (defined $hmac_secret) {
      # If not supplied, need to look for matching devices
      defined $self->fido2_credential && $self->fido2_aaguid
         or croak 'Cannot obtain private key without fido2_credential and fido2_aaguid';
      my @devs= grep $_->aaguid eq $self->fido2_aaguid, Crypt::MultiKey::FIDO2::list_devices()
         or croak 'No matching FIDO2 authenticator found';
      $hmac_secret= $self->_get_hmac_secret(\@devs)
         or croak 'No FIDO2 authenticator accepted the hmac-secret request';
   }
   $self->decrypt_private($self->_derive_password($hmac_secret));
}

sub _get_hmac_secret {
   my ($self, $devices)= @_;
   my @params= ( credential => $self->fido2_credential, challenge => $self->challenge );
   for (@$devices) {
      my ($secret, $cred_used)= $_->assert_hmac_secret(@params);
      return $secret if defined $secret;
   }
   return undef;
}

sub _derive_password {
   my ($self, $hmac_secret)= @_;
   my %kdf_params= (
      size => 32,
      kdf_info => 'Crypt::MultiKey::PKey::FIDO2',
      kdf_salt => $self->kdf_salt,
   );
   return Crypt::MultiKey::hkdf(\%kdf_params, $hmac_secret);
}

# For fields that could be plaintext, but might need base64-encoded
sub _maybe_b64encode {
   my $val= shift;
   # Test for anything that might not parse well in a PEM header value
   if ($val =~ /[^-a-zA-Z0-9_ :+[\]\/{}()<>,.~!@\$\%^&*]/
      or $val =~ /^[=\s]/ or $val =~ /\s\z/
   ) {
      return '='.encode_base64($val, '');
   } else {
      return $val;
   }
}
sub _maybe_b64decode {
   my $val= shift;
   $val =~ /^=/? decode_base64(substr($val, 1)) : $val
}

sub _import_pem_headers {
   my ($self, $pem)= @_;
   $self->next::method($pem);
   $self->fido2_aaguid_hex($pem->headers->get('cmk_fido2_aaguid'));
   $self->fido2_credential({
      id       => decode_base64($pem->headers->get('cmk_fido2_credential_id')),
      pubkey   => decode_base64($pem->headers->get('cmk_fido2_credential_pubkey')),
      cose_alg =>               $pem->headers->get('cmk_fido2_credential_cose_alg'),
   });
   $self->challenge(_maybe_b64decode($pem->headers->get('cmk_challenge')));
   $self->kdf_salt(decode_base64($pem->headers->get('cmk_kdf_salt')));
}

sub _export_pem_headers {
   my ($self, $pem)= @_;
   croak 'Cannot export ::PKey::FIDO2 without first encrypting the private half'
      unless defined $self->private_encrypted;
   my $cred= $self->fido2_credential;
   croak 'Cannot export ::PKey::FIDO2 without fido2_credential, fido2_aaguid, challenge, and kdf_salt'
      unless defined $cred && defined $cred->{id} && defined $cred->{pubkey}
          && defined $self->fido2_aaguid
          && defined $self->challenge
          && defined $self->kdf_salt;
   $self->next::method($pem);
   $pem->headers->append(cmk_fido2_aaguid => $self->fido2_aaguid_hex);
   $pem->headers->append(cmk_fido2_credential_id => encode_base64($cred->{id}, ''));
   $pem->headers->append(cmk_fido2_credential_pubkey => encode_base64($cred->{pubkey}, ''));
   $pem->headers->append(cmk_fido2_credential_cose_alg => $cred->{cose_alg})
      if defined $cred->{cose_alg};
   $pem->headers->append(cmk_challenge => _maybe_b64encode($self->challenge));
   $pem->headers->append(cmk_kdf_salt => encode_base64($self->kdf_salt, ''));
}

1;
