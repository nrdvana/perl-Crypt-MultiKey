package Crypt::MultiKey::FIDO2;
# VERSION
# ABSTRACT: Access to libfido2, if it was available when Crypt::MultiKey was installed

use Crypt::MultiKey; # XS methods get loaded by Crypt::MultiKey

=head1 SYNOPSIS

  @devices= Crypt::MultiKey::FIDO2::list_devices();
  if (@devices > 1) {
    say "Please touch desired authenticator";
    $dev= Crypt::MultiKey::FIDO2::select_device(@devices);
  }

=head1 DESCRIPTION

FIDO2 support is optional.  You can test whether it was enabled for this build of Crypt::MultiKey
by checking C<< Crypt::MultiKey::FIDO2->can("list_devices") >>.

=head1 FUNCTIONS

=head2 list_devices

Return a list of L<Crypt::MultiKey::FIDO2::Device> objects for each connected authenticator
which can be opened.

=head2 select_device

  # select from list_devices() output.  If only one exists, returns immediately.
  $dev= Crypt::MultiKey::FIDO2::select_device($timeout);
  
  # select from custom list of devices.
  $dev= Crypt::MultiKey::FIDO2::select_device($timeout, \@devices);

If there are multiple authenticators connected to the host, this lets the user select which one
they want to use by touching it.  This starts a touch request on all devices, and then the first
that receives a touch request is returned.  If none are touched, it returns C<undef>.

If there is only one to choose from, it is returned immediately without waiting for a touch.

=cut

use strict;
use warnings;
use Time::HiRes qw( time sleep );
use Carp qw( croak );

sub available {
   defined \&Crypt::MultiKey::FIDO2::_list_devices;
}

sub list_devices {
   defined \&Crypt::MultiKey::FIDO2::_list_devices
      or croak "libfido2 not available; install it and then reinstall Crypt::MultiKey";
   @{ Crypt::MultiKey::FIDO2::_list_devices() }
}

sub select_device {
   my ($timeout, $devices)= @_;
   $devices ||= [ Crypt::MultiKey::FIDO2::list_devices() ];
   my $end_t= time + $timeout;
   return undef if !@$devices;
   return $devices->[0] if @$devices == 1;

   # Start touch request on all devices
   my $winner;
   my @active= grep $_->get_touch_begin, @$devices;
   while (@active > 1 && !defined $winner) {
      sleep .2;
      for (@active) {
         my $touched= $_->get_touch_status(0);
         if ($touched) {
            $winner= $_;
            last;
         }
      }
   }
   # cancel touch request on all devices
   $_->cancel for @active;
   return $winner;
}

require Crypt::MultiKey::FIDO2::Device;
1;
