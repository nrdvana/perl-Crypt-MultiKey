package Crypt::MultiKey::YubicoOTP;
# VERSION
# ABSTRACT: Access to Yubico OTP API, used by older YubiKey authenticator devices

use Crypt::MultiKey; # XS methods get loaded by Crypt::MultiKey

=head1 SYNOPSIS

  @devices= Crypt::MultiKey::YubicoOTP::list_devices();
  my $resp= Crypt::MultiKey::YubicoOTP::challenge_response($devices[0], $slot, $chal_bytes);

=head1 DESCRIPTION

This is a wrapper around the tools L<ykinfo(1)> and L<ykchalresp(1)> from Yubico, maker of
YubiKey hardware authenticators.  They operate on what Yubico calls the "OTP application",
which is a protocol for One Time Passwords.  This protocol also includes a Challenge/Response
feature which is suitable for generating deterministic passwords from a seed value which can
only be computed by the hardware key.  The challenge/response is the only piece needed by
Crypt::MultiKey, so that is all that is implemented here.

In case the C<ykinfo> and C<ykchalresp> tools are not installed, there is an XS fallback for
Linux that can interact directly with /dev/hidraw device nodes.

Note that some cheaper YubiKeys do not support the OTP application.  For those, see
L<Crypt::MultiKey::FIDO2>.

=head1 FUNCTIONS

=head2 available

Return true if either the yubikey-personalization tools (ykinfo, ykchalresp) are available on
this host, or if XS support was compiled when Crypt::MultiKey was built.

=head2 list_devices

  @devices= Crypt::MultiKey::YubicoOTP::list_devices();

Return a list of L<Crypt::MultiKey::YubicoOTP::Device> objects for each available authenticator.

=cut

use v5.10;
use warnings;
use Time::HiRes qw( time sleep );
use Carp qw( carp croak );
use Crypt::SecretBuffer qw( secret HEX ISO8859_1 );

BEGIN { *_xs_available= sub { 0 } unless __PACKAGE__->can('_xs_available') }

our $_ykinfo_in_path;
sub available {
   return $Crypt::MultiKey::command_path{ykinfo} && -e $Crypt::MultiKey::command_path{ykinfo}
      || _xs_available
      || ($_ykinfo_in_path //= eval { ((_ykinfo('-V'))[0] == 0) });
}

sub list_devices {
   my $class= shift;
   my @devs;
   # If user specified a ykinfo path, prefer that over XS implementation
   my $cmd= $Crypt::MultiKey::command_path{ykinfo};
   if (!defined $cmd && _xs_available) {
      # XS implementation currently only works on Linux, and perl-side opens the file handle
      for (</dev/hidraw*>) {
         open my $fh, '+<', $_
            or next;
         my $info= _xs_ykinfo(fileno $fh)
            or next;
         $info->{path}= $_;
         $info->{_handle}= $fh;
         push @devs, bless $info, 'Crypt::MultiKey::YubicoOTP::Device';
      }
   }
   else {
      for (my $i= 0; ; ++$i) {
         my ($wstat, $out, $err, $cmd)= _ykinfo("-n$i", "-a");
         if ($wstat == 0) {
            if ($out =~ /^serial:\s*[0-9]+\s*$/m) {
               my %attrs= ( idx => $i );
               for (split /\s*?\n/, $out) {
                  my ($k, $v)= split /:\s*/, $_, 2;
                  $attrs{$k}= $v if length $k && length $v;
               }
               # these are redundant
               delete @attrs{'serial_hex','serial_modhex'};
               # these are in hex but could look like decimal, so just make them integers
               $attrs{$_}= hex $attrs{$_} for qw( vendor_id product_id );
               push @devs, bless \%attrs, 'Crypt::MultiKey::YubicoOTP::Device';
            } else {
               if (length $err) {
                  $err .= "\n" unless $err =~ /\n\z/;
                  print STDERR $err;
               }
               carp "Missing serial number for $i";
            }
         } else {
            # assume end of available keys.  Could check error message, but those
            # might vary by locale...
            last;
         }
      }
   }
   @devs;
}

=head2 challenge_response

  $resp= Crypt::MultiKey::YubicoOTP::ChallengeResponse($dev, $slot, $chal);

C<$resp> is an instance of L<Crypt::SecretBuffer>.  The device should be one of the values
returned by L</list_devices>.  The YubiKey supports two slots, named '1' and '2' (not '0') and
you need to select which one to perform the challenge against.  That slow also needs to be
configured to allow challenges.  C<$chal> is a scalar of raw bytes, not HEX.

=cut

sub challenge_response {
   my ($device, $slot, $challenge_bytes)= @_;
   if (defined $device->_handle && _xs_available) {
      my $fdnum= fileno $device->_handle // croak "Not a real file handle";
      my $timeout= 5; # ought to be configurable, but can't configure it when shelling-out...
      my @ret= _xs_ykchalresp($fdnum, $slot, $timeout, $challenge_bytes)
         or croak "ykchalresp failed: $!";
      return $ret[0] // croak "ykchalresp timed out waiting for touch";
   } else {
      my $hex= unpack 'H*', $challenge_bytes;
      my ($wstat, $out)= _ykchalresp('-n'.$device->idx, "-$slot", -x => $hex);
      $wstat == 0 && $out->length
         or croak "ykchalresp failed";
      return eval { $out->span(encoding => HEX)->copy(encoding => ISO8859_1) }
         // croak "ykchalresp returned non-hex response $@";
   }
}

sub _ykinfo {
   my $cmd= $Crypt::MultiKey::command_path{ykinfo} // 'ykinfo';
   my @cmd= ($cmd, @_);
   my $pid= IPC::Open3::open3(undef, my $out_fh, my $err_fh=Symbol::gensym(), @cmd);
   # should be safe to asume that all output fits in a pipe buffer, so just reap and then
   # collect the pipe contents.
   waitpid($pid, 0);
   my $wstat= $?;
   local $/= undef;
   chomp(my $out= <$out_fh>);
   chomp(my $err= <$err_fh>);
   # The exit value of ykinfo is unreliable.  It exits 0 on invalid options!
   # The exit code is reliable for '-nX -a' though to detect whether a device was present.
   if (length $err) {
      $wstat= (1<<8) if $err =~ /Usage:/;
   }
   return $wstat, $out, $err, \@cmd;
}

sub _ykchalresp {
   my $cmd= $Crypt::MultiKey::command_path{ykchalresp} // 'ykchalresp';
   my @cmd= ( $cmd, @_ );
   my $pid= IPC::Open3::open3(undef, my $out_fh, my $err_fh=Symbol::gensym(), @cmd);

   # Read stdout into a SecretBuffer, since this is being used as a password.
   my $out= secret;
   while (1) {
      my $n= $out->append_sysread($out_fh, 4096);
      last unless defined $n && $n > 0;
   }
   close $out_fh;

   local $/;
   my $err= <$err_fh> // '';
   close $err_fh;

   waitpid($pid, 0);
   return $?, $out, $err, \@cmd;
}

# avoid dependency on namespace::clean
delete @{Crypt::MultiKey::YubicoOTP::}{qw( carp croak secret HEX ISO8859_1 )};
require Crypt::MultiKey::YubicoOTP::Device;
1;
