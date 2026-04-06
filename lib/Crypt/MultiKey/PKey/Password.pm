package Crypt::MultiKey::PKey::Password;
# VERSION
# ABSTRACT: Default PKey protection scheme - encrypt private half with a password

use v5.10;
use warnings;
use Carp;
use parent 'Crypt::MultiKey::PKey';

=head1 DESCRIPTION

This is the default PKey protection scheme that you get when you call C<encrypt_private> on a
previously unprotected PKey object.  In order to interactively read the password, it expects
STDIN to be a terminal.  You can bypass this requirement using  C<decrypt_private> directly.

=cut

sub protection_scheme {
   @_ > 1? $_[0]->_set_protection_scheme($_[1]) : 'Password';
}

=method can_obtain_private

This returns true if STDIN is a console, meaning that it can display a password prompt to the
user.

=cut

sub can_obtain_private {
   return -t *main::STDIN;
}

=method obtain_private

Prompt the user for a password and pass that to L</decrypt_private>.  This is a no-op if the
private half is already loaded.

=cut

sub obtain_private {
   my $self= shift;
   # private already loaded? nothing to do.
   return if $self->has_private;
   croak "Can't decrypt an empty private_encrypted attribute"
      unless defined $self->private_encrypted;
   my $pw= secret(stringify_mask => '[PASSWORD]');
   my $name= $self->path // $self->fingerprint;
   $pw->append_console_line(\*main::STDIN, prompt => "Private key $name is encrypted.\nEnter password: ")
      or croak "Canceled password prompt";
   $pw->length
      or croak "Empty password";
   $self->decrypt_private($pw);
}

1;
