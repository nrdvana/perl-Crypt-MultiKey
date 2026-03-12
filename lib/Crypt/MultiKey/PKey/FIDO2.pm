package Crypt::MultiKey::PKey::FIDO2;
# VERSION
# ABSTRACT: use libfido2 hmac-secret to unlock a private key

use strict;
use warnings;
use Carp;
use MIME::Base64 qw( encode_base64 decode_base64 );
use Crypt::SecretBuffer qw( secret );
use parent 'Crypt::MultiKey::PKey';

sub mechanism { 'FIDO2' }

sub credential_name {
   @_ > 1? $_[0]{credential_name}= $_[1] : ($_[0]{credential_name} || 'crypt-multikey');
}

sub fido2_path {
   @_ > 1? $_[0]{fido2_path}= $_[1] : $_[0]{fido2_path};
}

sub fido2_cred_id {
   @_ > 1? $_[0]{fido2_cred_id}= $_[1] : $_[0]{fido2_cred_id};
}

sub kdf_salt { @_ > 1? $_[0]{kdf_salt}= $_[1] : $_[0]{kdf_salt} }

sub _have_fido2 {
   return Crypt::MultiKey::_have_fido2()? 1 : 0;
}

sub list_fido2_paths {
   my $self= shift;
   my $devices= Crypt::MultiKey::_fido2_list_devices();
   return [] unless ref $devices eq 'ARRAY';
   my @paths;
   for my $dev (@$devices) {
      next unless ref $dev eq 'HASH';
      next unless defined $dev->{path};
      push @paths, $dev->{path};
   }
   return \@paths;
}

sub create_credential {
   my ($self, $path)= @_;
   $self->_have_fido2
      or croak 'FIDO2 support not available in this build';

   my $paths= $self->list_fido2_paths;
   @$paths or croak 'No FIDO2 devices detected';

   $path= defined $path? $path
      : defined $self->fido2_path? $self->fido2_path
      : $paths->[0];

   my %seen= map +($_ => 1), @$paths;
   $seen{$path}
      or croak "FIDO2 device path $path is not currently connected";

   my $cred_id= Crypt::MultiKey::_fido2_make_credential($path, $self->credential_name);
   ref($cred_id) && eval { $cred_id->can('span') }
      or croak 'FIDO2 make-credential returned unexpected value';

   $cred_id->span->copy_to(my $cred_bytes);
   $self->fido2_path($path);
   $self->fido2_cred_id(encode_base64($cred_bytes, ''));
   return $self;
}

sub can_obtain_private {
   my $self= shift;
   return 0 unless $self->_have_fido2;
   return 0 unless defined $self->fido2_path && defined $self->fido2_cred_id;
   my $paths= eval { $self->list_fido2_paths };
   return 0 unless $paths && @$paths;
   return scalar grep $_ eq $self->fido2_path, @$paths;
}

sub encrypt_private {
   my ($self, $path)= @_;
   $self->create_credential($path)
      unless defined $self->fido2_cred_id && defined $self->fido2_path;

   secret(append_random => 16)->span->copy_to(my $salt_bytes);
   $self->kdf_salt(encode_base64($salt_bytes, ''));

   my $pw= $self->_derive_password_from_fido2;
   $self->next::method($pw, 0);
}

sub obtain_private {
   my $self= shift;
   return $self if $self->has_private;

   defined $self->private_encrypted
      or croak "Can't decrypt an empty private_encrypted attribute";
   defined $self->fido2_path
      or croak 'Cannot obtain private key without fido2_path';
   defined $self->fido2_cred_id
      or croak 'Cannot obtain private key without fido2_cred_id';

   $self->can_obtain_private
      or croak 'Configured FIDO2 device is not currently connected';

   my $pw= $self->_derive_password_from_fido2;
   $self->decrypt_private($pw);
}

sub _derive_password_from_fido2 {
   my $self= shift;
   defined $self->kdf_salt
      or croak 'Missing kdf_salt';

   my $challenge_bytes= $self->_challenge_bytes;
   my $cred_id_bytes= decode_base64($self->fido2_cred_id);
   my $resp= Crypt::MultiKey::_fido2_chalresp(
      $self->fido2_path,
      secret($challenge_bytes),
      secret($cred_id_bytes),
   );

   my %kdf_params= (
      size => 32,
      kdf_info => 'Crypt::MultiKey::PKey::FIDO2',
      kdf_salt => decode_base64($self->kdf_salt),
   );
   return Crypt::MultiKey::hkdf(\%kdf_params, $resp);
}

sub _challenge_bytes {
   my $self= shift;
   $self->_export_spki(my $raw_pubkey_bytes);
   my $salt_bytes= decode_base64($self->kdf_salt);
   return $salt_bytes . $raw_pubkey_bytes;
}

sub _import_pem_headers {
   my ($self, $pem)= @_;
   $self->next::method($pem);
   $self->fido2_path($pem->headers->{cmk_fido2_path});
   $self->fido2_cred_id($pem->headers->{cmk_fido2_cred_id});
   $self->kdf_salt($pem->headers->{cmk_kdf_salt});
   $self->credential_name($pem->headers->{cmk_fido2_credential_name})
      if defined $pem->headers->{cmk_fido2_credential_name};
}

sub _export_pem_headers {
   my ($self, $pem)= @_;
   croak 'Cannot export ::PKey::FIDO2 without fido2_path'
      unless defined $self->fido2_path;
   croak 'Cannot export ::PKey::FIDO2 without fido2_cred_id'
      unless defined $self->fido2_cred_id;
   croak 'Cannot export ::PKey::FIDO2 without first encrypting the private half'
      unless defined $self->private_encrypted;

   $self->next::method($pem);
   $pem->headers->append(cmk_fido2_path => $self->fido2_path);
   $pem->headers->append(cmk_fido2_cred_id => $self->fido2_cred_id);
   $pem->headers->append(cmk_fido2_credential_name => $self->credential_name);
   $pem->headers->append(cmk_kdf_salt => $self->kdf_salt)
      if defined $self->kdf_salt;
}

1;
