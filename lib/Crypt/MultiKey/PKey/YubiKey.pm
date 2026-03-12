package Crypt::MultiKey::PKey::YubiKey;
# VERSION
# ABSTRACT: use challenge/response from ykchalresp to unlock a private key

use strict;
use warnings;
use Carp;
use MIME::Base64 qw( encode_base64 decode_base64 );
use IPC::Open3 ();
use Crypt::SecretBuffer qw( secret span HEX ISO8859_1 );
use parent 'Crypt::MultiKey::PKey';

=head1 DESCRIPTION

This mechanism computes a deterministic challenge/response from a configured
YubiKey slot/challenge-response secret, and then derives a password from that response
to encrypt/decrypt the private half of a PKey.

This class always uses C<ykchalresp> for challenge-response so output semantics match
the YubiKey OTP applet behavior (HMAC-SHA1 challenge-response).  When available,
libfido2 is only used for optional device discovery metadata.

The challenge supplied to C<ykchalresp> is derived from this key's public half and a random
salt.  The challenge must be reproduced exactly in order to get the same YubiKey response.

=cut

sub mechanism { 'YubiKey' }

=attribute yubikey_serial

Optional YubiKey serial number to require for this key.  If defined, both encryption and
password recovery require this serial to be present in the list returned by
C<< ykman list --serials >>.

=cut

sub yubikey_serial {
   @_ > 1? shift->_set_yubikey_serial(@_) : $_[0]{yubikey_serial};
}
sub _set_yubikey_serial {
   my ($self, $value)= @_;
   if (defined $value) {
      $value =~ /^\d+\z/
         or croak "yubikey_serial must be numeric";
   }
   $self->{yubikey_serial}= $value;
}

=attribute kdf_salt

Random salt (base64) used to build the YubiKey challenge and as HKDF salt.

=cut

sub kdf_salt { @_ > 1? shift->_set_kdf_salt(@_) : $_[0]{kdf_salt} }
sub _set_kdf_salt { $_[0]{kdf_salt}= $_[1] }

=attribute ykchalresp

Path to the C<ykchalresp> executable.  Defaults to C<ykchalresp> in PATH.

=cut

sub ykchalresp {
   @_ > 1? $_[0]{ykchalresp}= $_[1] : ($_[0]{ykchalresp} || 'ykchalresp');
}

=attribute ykman

Path to the C<ykman> executable.  Defaults to C<ykman> in PATH.

=cut

sub ykman {
   @_ > 1? $_[0]{ykman}= $_[1] : ($_[0]{ykman} || 'ykman');
}

sub _have_fido2 {
   return Crypt::MultiKey::_have_fido2()? 1 : 0;
}

sub _fido2_list_devices {
   my $devices= Crypt::MultiKey::_fido2_list_devices();
   return [] unless ref $devices eq 'ARRAY';
   return $devices;
}

sub _update_device_list {
   my $self= shift;
   my %devices;
   my @order;

   # When fido2 can identify serials, prefer it and keep its per-device metadata.
   if ($self->_have_fido2) {
      my $fido_devices= eval { $self->_fido2_list_devices };
      if ($fido_devices && @$fido_devices) {
         for my $dev (@$fido_devices) {
            my $serial= $dev->{serial};
            next unless defined $serial && $serial =~ /^\d+\z/;
            $devices{$serial}= { %$dev };
            push @order, $serial;
         }
      }
   }

   # Fall back to ykman when fido2 enumeration doesn't provide serial numbers.
   if (!@order) {
      my $out= $self->_run_ykman('list', '--serials');
      for my $serial (grep /^\d+\z/, split /\s+/, $out) {
         next if $devices{$serial};
         $devices{$serial}= { serial => $serial };
         push @order, $serial;
      }
   }

   $self->{_devices_by_serial}= \%devices;
   $self->{_device_serial_order}= \@order;
   return \%devices;
}

=method list_yubikey_serials

Return an arrayref of serial numbers detected by C<< ykman list --serials >>.

=cut

sub list_yubikey_serials {
   my $self= shift;
   $self->_update_device_list;
   return [ @{ $self->{_device_serial_order} || [] } ];
}

=method can_obtain_private

Returns true when the configured YubiKey serial is currently present.

=cut

sub can_obtain_private {
   my $self= shift;
   my $want= $self->yubikey_serial;
   return 0 unless defined $want;
   my $serials= eval { $self->list_yubikey_serials };
   return 0 unless $serials && @$serials;
   return $self->_serial_is_present($want, $serials)? 1 : 0;
}

=method obtain_private

Recompute challenge/response from the configured YubiKey and decrypt the private half.

=cut

sub obtain_private {
   my $self= shift;
   return $self if $self->has_private;

   defined $self->private_encrypted
      or croak "Can't decrypt an empty private_encrypted attribute";
   defined $self->yubikey_serial
      or croak "Cannot obtain private key without yubikey_serial";
   $self->_assert_serial_available;

   my $pw= $self->_derive_password_from_yubikey;
   $self->decrypt_private($pw);
}

=method encrypt_private

Encrypt the private key using a password derived from YubiKey challenge/response.

  $pkey->encrypt_private;
  $pkey->encrypt_private($serial_number);

If no serial is provided, this picks the first detected key and records its serial.

=cut

sub encrypt_private {
   my ($self, $selector)= @_;
   my $serials= $self->list_yubikey_serials;
   croak "No YubiKeys detected by ykman list --serials"
      unless @$serials;

   my $serial;
   if (defined $selector) {
      $selector =~ /^\d+\z/
         or croak "YubiKey selector must be a numeric serial";
      $serial= $selector;
   }
   elsif (defined $self->yubikey_serial) {
      $serial= $self->yubikey_serial;
   }
   else {
      $serial= $serials->[0];
   }

   $self->_assert_serial_present($serial, $serials);

   $self->yubikey_serial($serial);
   secret(append_random => 16)->span->copy_to(my $salt_bytes);
   $self->kdf_salt(encode_base64($salt_bytes, ''));

   my $pw= $self->_derive_password_from_yubikey;
   $self->next::method($pw, 0);
}

sub _derive_password_from_yubikey {
   my $self= shift;
   my $challenge_bytes= $self->_challenge_bytes;
   my $response= $self->_run_chalresp($challenge_bytes);

   my %kdf_params= (
      size => 32,
      kdf_info => 'Crypt::MultiKey::PKey::YubiKey',
      kdf_salt => decode_base64($self->kdf_salt),
   );
   return Crypt::MultiKey::hkdf(\%kdf_params, $response);
}

sub _challenge_bytes {
   my $self= shift;
   defined $self->kdf_salt
      or croak "Missing kdf_salt";
   $self->_export_spki(my $raw_pubkey_bytes);
   my $salt_bytes= decode_base64($self->kdf_salt);
   return $salt_bytes . $raw_pubkey_bytes;
}

sub _assert_serial_available {
   my $self= shift;
   my $serial= $self->yubikey_serial;
   defined $serial
      or croak "Cannot obtain private key without yubikey_serial";
   my $serials= $self->list_yubikey_serials;
   $self->_assert_serial_present($serial, $serials);
   return 1;
}

sub _serial_is_present {
   my ($self, $serial, $serials)= @_;
   return scalar grep $_ eq $serial, @$serials;
}

sub _assert_serial_present {
   my ($self, $serial, $serials)= @_;
   $self->_serial_is_present($serial, $serials)
      or croak "YubiKey serial $serial is not currently connected";
   return 1;
}

sub _run_chalresp {
   my ($self, $challenge_bytes)= @_;

   # Always use ykchalresp here so password derivation is identical to OTP applet C/R mode.
   return $self->_run_ykchalresp('-x', unpack('H*', $challenge_bytes));
}

sub _run_ykchalresp {
   my ($self, @args)= @_;
   my $cmd= $self->ykchalresp;
   my $full= join(' ', $cmd, @args);
   my $pid= IPC::Open3::open3(undef, my $out_fh, my $err_fh, $cmd, @args);

   my $out= secret;
   my $err= '';

   # Read stdout into a SecretBuffer so challenge-response material avoids plain scalars.
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
   my $exit= $? >> 8;
   $exit == 0
      or croak "$full failed: $err";

   my $response_hex= '';
   $out->span->copy_to($response_hex);
   $response_hex =~ s/\s+//g;
   my $decoded= eval { span($response_hex, encoding => HEX)->copy(encoding => ISO8859_1) };
   $@ and croak "Challenge-response command returned non-hex response";
   return $decoded;
}

sub _run_ykman {
   my ($self, @args)= @_;
   my $cmd= $self->ykman;
   my $full= join(' ', $cmd, @args);
   my $out= qx{$cmd @args 2>&1};
   my $exit= $? >> 8;
   $exit == 0
      or croak "$full failed: $out";
   return $out;
}

# When parent class loads PEM file, capture additional attributes
sub _import_pem_headers {
   my ($self, $pem)= @_;
   $self->next::method($pem);
   $self->yubikey_serial($pem->headers->{cmk_yubikey_serial});
   $self->kdf_salt($pem->headers->{cmk_kdf_salt});
}

sub _export_pem_headers {
   my ($self, $pem)= @_;
   croak "Cannot export ::PKey::YubiKey without selecting yubikey_serial"
      unless defined $self->yubikey_serial;
   croak "Cannot export ::PKey::YubiKey without first encrypting the private half"
      unless defined $self->private_encrypted;
   $self->next::method($pem);
   $pem->headers->append(cmk_yubikey_serial => $self->yubikey_serial);
   $pem->headers->append(cmk_kdf_salt => $self->kdf_salt)
      if defined $self->kdf_salt;
}

1;
