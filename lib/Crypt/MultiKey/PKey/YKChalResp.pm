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
use parent 'Crypt::MultiKey::PKey';

=head1 DESCRIPTION

This module uses the YubiKey OTP protocol's challenge/response feature to
generate a password to unlock the private half of a PKey.  Note that the OTP
protocol is older and superseded by the FIDO2 protocol
(see L<Crypt::MultiKey::PKey::FIDO2>) and some newer YubiKeys don't even support
the OTP protocol.  This mechanism of challenge/response basically just takes a
piece of data from the user, a piece of secret data within the YubiKey, runs
them both through SHA-1, and returns a portion of the result.  This mode of
operation is just making use of the YubiKey as an un-copyable string of bytes
which can only be hashed when touching the button of the device.  Anyone who can
see the contents of your PKey PEM file can reconstruct the challenge, and if
they then have access to the YubiKey (including a button press) they can
reconstruct the password and decrypt the PKey.

In order to use this mechanism, you need tools L<ykinfo(1)> and L<ykchalresp(1)>,
which on Debian come from C<< apt install yubikey-personalization >>.

The challenge supplied to C<ykchalresp> is derived from this key's public half
and a random salt.  The salt is saved in attribute L</kdf_salt> and serialized
to the PKey's PEM file (along with the YubiKey serial number and slot number)
so that future C<decrypt_private> calls can re-issue the same challenge to the
same slot of the same key.  Method L</can_obtain_private> will return false
unless C<ykinfo> can find the matching serial number on one of the available
devices.

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
configured challenge/response.  The default is to attempt them both and record
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

sub _enumerate_devices {
   my $class= shift;
   my @devs;
   my $cmd= $Crypt::MultiKey::command_path{ykinfo};
   if (!defined $cmd && Crypt::MultiKey::_have_yubico_otp()) {
      for (</dev/hidraw*>) {
         open my $fh, '+<', $_
            or next;
         my $info= Crypt::MultiKey::_yubico_otp_ykinfo(fileno $fh)
            or next;
         $info->{path}= $_;
         $info->{handle}= $fh;
         push @devs, $info;
      }
   }
   else {
      $cmd //= 'ykinfo';
      for (my $i= 0; ; ++$i) {
         my $pid= IPC::Open3::open3(undef, my $out_fh, my $err_fh=Symbol::gensym(), $cmd, "-n$i", "-a");
         waitpid($pid, 0);
         local $/= undef;
         chomp(my $info= <$out_fh>);
         chomp(my $err= <$err_fh>);
         if ($? == 0) {
            if ($info =~ /^serial:\s*[0-9]+\s*$/m) {
               my %attrs= ( idx => $i );
               for (split /\s*?\n/, $info) {
                  my ($k, $v)= split /:\s*/;
                  $attrs{$k}= $v if length $k && length $v;
               }
               # these are redundant
               delete @attrs{'serial_hex','serial_modhex'};
               # these are in hex but could look like decimal, so just make them integers
               $attrs{$_}= hex $attrs{$_} for qw( vendor_id product_id );
               push @devs, \%attrs;
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
   \@devs;
}

sub _update_device_list {
   my $self= shift;
   $self->{_device_list}= $self->_enumerate_devices;
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
   defined $want && grep $_->{serial} eq $want, $self->list_yubikeys
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
      next if defined $serial && $device->{serial} ne $serial;
      my $response= defined $slot? $self->_run_chalresp($device, $slot, $bytes)
         : eval { $slot= 1; $self->_run_chalresp($device, 1, $bytes) }
           // eval { $slot= 2; $self->_run_chalresp($device, 2, $bytes) }
           // do { carp "Neither slot of $device->{serial} supports OTP chalresp"; next; };
      $self->yubikey_serial($device->{serial});
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

sub _run_chalresp {
   my ($self, $device, $slot, $challenge_bytes)= @_;
   if (defined $device->{handle} && Crypt::MultiKey::_have_yubico_otp()) {
      my (@ret)= Crypt::MultiKey::_yubico_otp_ykchalresp(fileno $device->{handle}, $slot, 5, $challenge_bytes);
      @ret or croak "ykchalresp failed: $!";
      return $ret[0] // croak "ykchalresp timed out waiting for touch";
   } else {
      my $out= $self->_run_ykchalresp('-n'.$device->{idx}, "-$slot",
         '-x', unpack('H*', $challenge_bytes));
      $out->unmask_to(sub {print "# out='$_[0]'\n" });
      return eval { $out->span(encoding => HEX)->copy(encoding => ISO8859_1) }
         // croak "ykchalresp returned non-hex response $@";
   }
}

sub _run_ykchalresp {
   my ($self, @args)= @_;
   my $cmd= $Crypt::MultiKey::command_path{ykchalresp} // 'ykchalresp';
   my $out= secret;
   my $err= '';
   my $pid= IPC::Open3::open3(undef, my $out_fh, my $err_fh, $cmd, @args);

   # Read stdout into a SecretBuffer, since this is being used as a password.
   while (1) {
      my $n= $out->append_sysread($out_fh, 4096);
      last unless defined $n && $n > 0;
   }
   close $out_fh;

   if (defined $err_fh) {
      local $/;
      $err= <$err_fh> // '';
      close $err_fh;
   }

   waitpid($pid, 0);
   $? == 0
      or croak join(' ', $cmd, @args, "failed ($?):", $err);
   return $out;
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

=head1 CONFIGURATION

You can specify the paths to the exeutables used by this module with the
C<< %Crypt::MultiKey::command_path >> global variable:

=over

=item ykinfo

C<< $Crypt::MultiKey::command_path{ykinfo} >>

=item ykchalresp

C<< $Crypt::MultiKey::command_path{ykchalresp} >>.

=back

For security, these are not configurable from an environment variable.

=cut


1;
