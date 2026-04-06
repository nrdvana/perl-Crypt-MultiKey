package Crypt::MultiKey::FIDO2::Device;
# VERSION
# ABSTRACT: Represent a connected fido_dev_t struct of libfido2

use v5.10;
use warnings;
use Carp 'croak';
use Crypt::MultiKey::FIDO2;

=head1 DESCRIPTION

This class represents a connection to a FIDO2 device (the fido_dev_t struct of libfido2)

This is an incomplete abstraction of the libfido2 API, providing just enough for the
L<Crype::MultiKey::PKey::FIDO2> implementation.

=constructor new

  $dev= Crype::MultiKey::FIDO2::Device->new($dev_path);

=cut

sub new {
   my ($class, $path)= @_;
   croak "libfido2 support not available; install libfido2 and then reinstall Crypt::MultiKey"
      unless Crypt::MultiKey::FIDO2::available();

   my $self= bless {}, $class;
   $self->open($path) or croak "open($path): ".$self->fido_err;
   return $self;
}

=attribute path

The current host device path name for the authenticator, such as C<< '/dev/hidraw1' >>.

=attribute fido_err

The last error code received from the libfido2 API.

=cut

sub path { $_[0]{path} }
sub fido_err { $_[0]{fido_err} }

=attribute aaguid

A hardware identifier for the model/version of the authenticator, formatted in standard GUID
hex notation.

=attributes aaguid_bytes

A hardware identifier for the model/version of the authenticator, as raw 16 bytes.

=attribute algorithms

An arrayref describing public-key algorithms supported by the authenticator.
Each element is a hashref containing fields like C<type> and C<cose>.

=attribute certifications

A hashref of certification identifiers reported by the authenticator.

=attribute extensions

An arrayref of extension names supported by the authenticator.

=attribute fwversion

The firmware version reported by the authenticator.

=attribute maxcredbloblen

Maximum supported size of a credential blob.

=attribute maxcredcntlst

Maximum number of credential IDs accepted in an allow-list.

=attribute maxcredidlen

Maximum supported credential ID length.

=attribute maxlargeblob

Maximum supported size of the large-blob storage area.

=attribute maxmsgsiz

Maximum CTAP message size supported by the authenticator.

=attribute maxrpid_minpinlen

Maximum number of RP IDs tracked for minimum PIN length policy.

=attribute minpinlen

Minimum PIN length currently enforced by the authenticator.

=attribute new_pin_required

True if the authenticator requires a new PIN to be set.

=attribute options

A hashref of authenticator option flags.

=attribute protocols

An arrayref of supported PIN/UV protocol version numbers.

=attribute rk_remaining

The remaining number of discoverable credentials the authenticator reports it can store,
or a negative value if not reported.

=attribute transports

An arrayref of supported transport names.

=attribute uv_attempts

Number of remaining built-in user-verification attempts, if reported.

=attribute uv_modality

A bitmask describing built-in user-verification methods supported by the authenticator.

=attribute versions

An arrayref of supported CTAP/U2F protocol version strings.

=cut

sub aaguid             { shift->_cbor_attrs->{aaguid} }
sub aaguid_hex         { Crypt::MultiKey::FIDO2::_format_guid(shift->_cbor_attrs->{aaguid}) }
sub algorithms         { shift->_cbor_attrs->{algorithms} }
sub certifications     { shift->_cbor_attrs->{certifications} }
sub extensions         { shift->_cbor_attrs->{extensions} }
sub fwversion          { shift->_cbor_attrs->{fwversion} }
sub maxcredbloblen     { shift->_cbor_attrs->{maxcredbloblen} }
sub maxcredcntlst      { shift->_cbor_attrs->{maxcredcntlst} }
sub maxcredidlen       { shift->_cbor_attrs->{maxcredidlen} }
sub maxlargeblob       { shift->_cbor_attrs->{maxlargeblob} }
sub maxmsgsiz          { shift->_cbor_attrs->{maxmsgsiz} }
sub maxrpid_minpinlen  { shift->_cbor_attrs->{maxrpid_minpinlen} }
sub minpinlen          { shift->_cbor_attrs->{minpinlen} }
sub new_pin_required   { shift->_cbor_attrs->{new_pin_required} }
sub options            { shift->_cbor_attrs->{options} }
sub protocols          { shift->_cbor_attrs->{protocols} }
sub rk_remaining       { shift->_cbor_attrs->{rk_remaining} }
sub transports         { shift->_cbor_attrs->{transports} }
sub uv_attempts        { shift->_cbor_attrs->{uv_attempts} }
sub uv_modality        { shift->_cbor_attrs->{uv_modality} }
sub versions           { shift->_cbor_attrs->{versions} }

=attribute is_fido2

True if authenticator supports FIDO2

=attribute supports_pin

True if the authenticator supports a PIN.

=attribute has_pin

True if the authenticator has a PIN set.

=attribute supports_uv

True if the authenticator supports user verification (UV), such as PIN
or biometric authentication, in addition to simple user presence checks
like a button press.

=attribute has_uv

True if the authenticator currently has a usable user verification (UV)
method configured, such as a PIN or biometric. This does not mean UV will
be required, only that it is available if requested.

=method open

  $bool= $device->open($dev_path);

Open a new device path.  On success, any device already open in the current object is closed.
On failure, the error is stored in L</fido_err>.

=method get_touch_begin

  $device->get_touch_begin // croak $device->fido_err;

Begin a "get touch" process.  This tells the device that we want to poll for a touch event.
It signals to the user that a touch is requested, and reports whether this occurs via
L</get_touch_status>.

=method get_touch_status

  $touched= $device->get_touch_status;
  $touched= $device->get_touch_status($wait_seconds);

Check whether this device has received a touch since L</get_touch_begin> was called.  If it
returns true, the touch occurred and the "get touch" process is complete.  If it returns false,
no touch occurred and the "get touch" is ongoing.  If it returns C<undef>, there was an error
and the "get touch" is most likely terminated.

=method cancel

  $device->cancel;

Cancel an ongoing operation on the device, such as a "get touch" process.

=method make_hmac_secret_credential

  my $cred= $device->make_hmac_secret_credential(%options);
  # %options:
  #  discoverable      => $bool,  # whether credential can be seen on device
  #  rp_domain         => $str,   # default "crypt-multikey.local"
  #  rp_name           => $str,   # default "Crypt::MultiKey"
  #  user_name         => $str,   # who or what will be using the credential
  #  user_display_name => $str,
  #  user_icon         => $data,
  #  pin               => $pin_password,

Creates a new credential on the authenticator, for purposes of using the hmac-secret extension.
FIDO devices have a limited space for storing credentials, so use this method sparingly.
The return value is a hashref of attributes about the credential. Devices may or may not require
the C<pin>.

=cut

sub make_hmac_secret_credential {
   my ($self, %options)= @_;
   my ($pin, $discoverable, $rp_domain, $rp_name, $user_name, $user_display_name, $user_icon) =
      delete @options{qw( pin discoverable rp_domain rp_name user_name user_display_name user_icon )};
   croak "Unknown parameter ".join(', ', keys %options)
      if keys %options;
   $self->_make_hmac_secret_credential($pin,
      $discoverable // 1,
      $rp_domain // 'crypt-multikey.local',
      $rp_name // 'Crypt::MultiKey',
      $user_name // 'Crypt::MultiKey::FIDO2::Device',
      $user_display_name // 'Crypt::MultiKey::FIDO2::Device',
      $user_icon);
}

=method assert_hmac_secret

  ($resp, $cred)= $device->assert_hmac_secret(%options);
  # %options:
  #  credential => $cred_or_arrayref,  # one or more credentials to test
  #  challenge  => $message,           # string whose sha256 will become HMAC salt
  #  rp_domain  => $domain_name,       # must match value used during make_credential
  #  pin        => $pin_password,      # only for authenticators that require it

Assert that the device possesses one of the credentials, and compute hmac-secret on 'challenge'
using that credential.  The response (HMAC bytes) and which credential was used are returned as
a list.  This method croaks on errors *unless* the only error was that none of the credentials
exist on the device, in which case it returns an empty list.

This can test a device for multiple credentials in one call, so long as the C<rp_domain> and
C<challenge> is the same for each of them.  Devices may or may not require the C<pin>.

=cut

sub assert_hmac_secret {
   my ($self, %options)= @_;
   my ($pin, $credential, $challenge, $rp_domain) =
      delete @options{qw( pin credential challenge rp_domain )};
   croak "Unknown parameter ".join(', ', keys %options)
      if keys %options;
   $credential= [ $credential ]
      unless ref $credential eq 'ARRAY';
   length $challenge == 32
      or croak "Expected challenge of 32 bytes";
   my ($idx, $resp)= $self->_assert_hmac_secret($pin,
      $rp_domain // 'crypt-multikey.local', $credential, Crypt::MultiKey::sha256($challenge));
   if (defined $idx) {
      return ($resp, $credential->[$idx]);
   } else {
      return;
   }
}

1;
