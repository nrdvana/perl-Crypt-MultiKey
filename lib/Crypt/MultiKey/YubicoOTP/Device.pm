package Crypt::MultiKey::YubicoOTP::Device;
# VERSION
# ABSTRACT: Represents a YubiKey discovered through the OTP interface

use v5.10;
use warnings;
use Crypt::MultiKey::YubicoOTP;

=head1 DESCRIPTION

This class is a simple wrapper around metadata reported by L<ykinfo(1)>, plus a few
implementation-specific attributes used by the XS fallback.  Attributes are exposed
through read-only accessors.

=attribute idx

The numeric index assigned by the C<ykinfo> tool when enumerating attached YubiKeys.
This will usually be C<0> when only one compatible YubiKey is attached.

This attribute is undefined when using the XS implementation, which identifies devices by
their HID raw device node instead.

=attribute path

The path to the HID raw device node, such as C</dev/hidraw0>.  This attribute is only populated
when using the XS implementation.

=attribute serial

The authenticator's serial number, as a decimal string.

=attribute serial_hex

The authenticator's serial number, as a hexadecimal string.

=attribute version

The C<major.minor.patch> firmware version reported by the YubiKey OTP interface.

=attribute touch_level

The touch configuration flags, as an intger.

=attribute programming_sequence

A counter that changes when the OTP configuration is reprogrammed.

=attribute slot1_status

The status bits of slot 1, as an integer.

=attribute slot2_status

The status bits of slot 1, as an integer.

=attribute vendor_id

The USB vendor ID reported by the device, as an integer.

=attribute product_id

The USB product ID reported by the device, as an integer.

=cut

sub idx                  { $_[0]{idx} }
sub path                 { $_[0]{path} }
sub _handle              { $_[0]{_handle} }

sub serial               { $_[0]{serial} }
sub serial_hex           { sprintf "%x", shift->serial }
sub version              { $_[0]{version} }
sub touch_level          { $_[0]{touch_level} }
sub programming_sequence { $_[0]{programming_sequence} }
sub slot1_status         { $_[0]{slot1_status} }
sub slot2_status         { $_[0]{slot2_status} }
sub vendor_id            { $_[0]{vendor_id} }
sub product_id           { $_[0]{product_id} }

=method challenge_response

  $resp= $device->challenge_response($slot, $challenge);

Shortcut for L<Crypt::MultiKey::YubicoOTP/challenge_response>.

=cut

# argument list is identical
*challenge_response= *Crypt::MultiKey::YubicoOTP::challenge_response;

1;
