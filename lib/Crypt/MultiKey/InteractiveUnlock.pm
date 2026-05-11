package Crypt::MultiKey::InteractiveUnlock;
# VERSION
# ABSTRACT: Prompt user for passwords, authenticator PINs, etc

=head1 DESCRIPTION

Unlocking a L<LockMechanism|Crypt::MultiKey::LockMechanism> involves a surprising number of
special cases:

=over

=item *

Checking for newly-plugged-in hardware authenticators needs to happen frequently, and might
need to interupt password entry, and might need to collect a PIN from the user.

=item *

If one of the locks has a single tumbler that can't be unlocked, we shouldn't prompt the user
for any of the other tumbers in that lock.

=item *

If one of the locks can be opened without interaction, we should use it immediately without
probing hardware authenticators.

=item *

Multiple PKey objects might refer to the same private key, in which case we should only decrypt
one of them and then copy the private key instead of trying to unlock the rest.

=back

Also, this process is implemented for the console, but users might want to apply the same
algorithm to a graphical interface.  Rather than trying to make one massive customizable
function, the unlock sequence is implemented as a class so that its behavior can be re-used
and overridden as needed.

=cut

use v5.12;
use warnings;
use Carp;
use Scalar::Util qw( blessed refaddr );
use MIME::Base64 qw( encode_base64 decode_base64 );
use Crypt::SecretBuffer qw( secret );
use Time::HiRes qw( time sleep );

=head1 CONSTRUCTOR

=head2 new

  $un= Crypt::MultiKey::InteractiveUnlock->new($target, %attributes);
  $un= Crypt::MultiKey::InteractiveUnlock->new(%attributes);

Return a new InteractiveUnlock object.  No action is taken until you call L</run>.


  For Coffer and
Vault, the C<locks> are inspected to determine the sets of PKey objects to process.  If the
Coffer or Vault are not already associated with PKey objects (they may only serialize the
fingerprint) you need to specify those with the C<keys> option.


  $bool= interactive_unlock($thing_to_unlock, %options);
  # where $thing_to_unlock may be a Coffer, Vault, or arrayref of arrayrefs of PKey objects:
=cut

our %_attr_priority= ( pkeys => -1, goals => 1 );
sub new {
   my $class= shift;
   my %attrs= !(@_ & 1)? @_
            : @_ == 1 && ref $_[0] eq 'HASH'? %{$_[0]}
            # automatic recognition of 'target' attribute
            : blessed($_[0]) && ($_[0]->can('lock_mechanism') || $_[0]->can('insert_keys'))?
               ( target => @_ )
            : croak "Expected hashref, or even-length list of attribute key/values";

   my $self= bless { pkeys => {} }, $class;
   for (sort { ($_attr_priority{$a}||0) <=> ($_attr_priority{$b}||0) } keys %attrs) {
      my $setter= $self->can('_set_'.$_) or croak "No attribute '$_'";
      $setter->($self, $attrs{$_});
   }
   if (!$self->{goals}) {
      $self->target? $self->_set_goals($self->_goals_from_target($self->target))
                   : croak "attribute 'goals' is required";
   }
   $self;
}

sub _lock_mech_from_target {
   my $target= shift;
   return $target->can('lock_mechanism')? $target->lock_mechanism
        : $target->isa('Crypt::MultiKey::LockMechanism')? $target
        : croak("Attribute 'target' must be a LockMechanism, or object with ->lock_mechanism");
}

sub _goals_from_target {
   my ($class, $target)= @_;
   my $mech= _lock_mech_from_target($target);
   return [ map [ map $_->{key} || $_->{key_fingerprint}, @{$_->{tumblers}} ], @{$mech->locks} ];
}

=head1 ATTRIBUTES

=head2 target

An instance of L<Crypt::MultiKey::LockMechanism> or object with C<< ->lock_mechanism >>
attribute.  If supplied, L</goals> will be derived from the C<LockMechanism> and a successful
L</run> will call C<unlock> on the C<LockMechanism>.

If not specified, you can supply the L</goals> directly and a successful L</run> just leaves you
with a usable set of PKey objects.

=head2 goals

  [
    [ $pkey1, $pkey2 ],
    [ $pkey1_fingerprint, $pkey3_fingerprint ],
    [ $pkey2, $pkey3, $pkey4 ],
  ]

This is an arrayref where each element represents a possible set of PKeys that constitute a
successful "unlock".  In other words, the goal of this algorithm is to find all the private keys
for one of these sets, and then stop.  Each goal is represented as an arrayref of PKey objects
or PKey fingerprints.  You may assign new goals, but do not modify the existing arrayref.

=head2 pkeys

This is a set of PKey objects which the algorithm is attempting to obtain private halves for.
You can supply this to the constructor as an arrayref or hashref, but it is returned from this
attribute accessor as a de-duplicated arrayref.  You may add additional PKey objects with
L</add_pkeys> or exclude existing ones with L</exclude_pkey>, but modifying the arrayref has
no effect.

=over

=item pkeys_by_fingerprint

  @pkeys= $iun->pkeys_by_fingerprint($pkey->fingerprint);

Returns a list of pkeys by their 'fingerprint' attribute.

=item pkeys_by_public

  @pkeys= $iun->pkeys_by_public($pkey->public);

Returns a list of pkeys by their 'public' attribute.

=back

=cut

sub target { @_ > 1? shift->_set_target(@_) : $_[0]{target} }
sub _set_target {
   my ($self, $val)= @_;
   _lock_mech_from_target($val); # just for validation
   $self->{target}= $val;
}

sub goals { @_ > 1? shift->_set_goals(@_) : $_[0]{goals} }

sub _set_goals {
   my ($self, $val)= @_;
   delete $self->{_achievable_goals};

   ref $val eq 'ARRAY' or croak "Expected arrayref of goals";
   for my $set (@$val) {
      # elements of each set may be PKey objects or fingerprint strings
      ref $set eq 'ARRAY' or croak "Each element of 'goals' must be an arrayref";
      for (@$set) {
         if (blessed($_) && $_->isa('Crypt::MultiKey::PKey')) {
            $self->add_pkey($_);
         } elsif (!(!ref && /^sha256:/)) {
            croak "Expected PKey object or fingerprint scalar";
         }
      }
   }
   $self->{goals}= $val;
   $self;
}

sub pkeys { @_ > 1? shift->_set_pkeys(@_) : [ values %{$_[0]{pkeys}} ] }

sub pkeys_by_fingerprint {
   my ($self, $fingerprint)= @_;
   my $list= $self->{pkeys_by_fingerprint}{$fingerprint};
   return $list? @$list : ();
}

sub pkeys_by_public {
   my ($self, $public)= @_;
   my $list= $self->{pkeys_by_public}{$public};
   return $list? @$list : ();
}

sub _set_pkeys { my $self= shift; $self->add_pkey(@_); $self }

# the goals which are obtainable with the current available set of PKey objects
sub _achievable_goals { $_[0]{_achievable_goals} ||= $_[0]->_build_achievable_goals }

sub _build_achievable_goals {
   my $self= shift;
   my @achievable;
   my $pks= $self->{pkeys} || {};
   goal: for my $goal (@{ $self->goals }) {
      my %goal= ( origin => $goal );
      for (@$goal) {
         # baseline "achievable" is if we have all the PKey objects available
         # and they haven't been excluded.
         my @pkeys= blessed($_)? $self->pkeys_by_public($_->public) : $self->pkeys_by_fingerprint($_);
         next goal
            unless grep exists $pks->{refaddr($_)}, @pkeys;
         # set of PKeys is keyed by raw public key.  It is possible for two PKey objects
         # to have the same public key, in which case we succeed when we can retrieve
         # the private key via any of their protection schemes.
         $goal{$pkeys[0]->public}= 0;
      }
      push @achievable, \%goal;
   }
   return \@achievable;
}

=head2 unlocked

This holds the first successfully unlocked element of L</goals> (but with each element replaced
by a PKey object, if they were fingerprint strings), or C<undef> if none have been unlocked yet.
The algorithm is considered complete once this attribute is set.

=cut

sub unlocked { @_ > 1? shift->_set_unlocked(@_) : $_[0]{unlocked} }

sub _set_unlocked {
   my ($self, $goal)= @_;
   if (defined $goal) {
      croak "Expected goal arrayref"
         unless ref $goal eq 'ARRAY';
      croak "Expected arrayref of PKey objects"
         if grep !(blessed($_) && $_->isa('Crypt::MultiKey::PKey')), @$goal;
      croak "PKey in solution lacks private half"
         if grep !$_->has_private, @$goal;
   }
   $self->{unlocked}= $goal;
   $self;
}

=head2 input_fh

A file handle to use for reading passwords from the user.  The default is to open
C<< /dev/tty >> on Unix or C<< CONIN$ >> on MSWin32.

=head2 prompt_fh

A file handle to use for writing prompts and status messages.  The default is to open
C<< /dev/tty >> on Unix or C<< CONOUT$ >> on MSWin32.

=cut

sub input_fh { $_[0]{input_fh} ||= shift->_build_input_fh }
sub prompt_fh { $_[0]{prompt_fh} ||= shift->_build_prompt_fh }

sub _build_input_fh {
   my $self= shift;
   my $input_fh;
   if ($^O eq 'MSWin32') {
      open($input_fh, '+<', 'CONIN$') or croak 'open(CONIN$): '.$!;
   } else {
      open($input_fh, '+<', '/dev/tty') or croak "open(/dev/tty): $!";
      # if prompt not defined, use the same handle
      $self->{prompt_fh} //= $input_fh;
   }
   return $input_fh;
}

sub _build_prompt_fh {
   my $self= shift;
   my $prompt_fh;
   if ($^O eq 'MSWIn32') {
      open($prompt_fh, '>', 'CONOUT$') or croak 'open(CONOUT$): '.$!
   } else {
      open($prompt_fh, '+<', '/dev/tty') or croak "open(/dev/tty): $!";
      # if input not defined, use the same handle
      $self->{input_fh} //= $prompt_fh;
   }
   return $prompt_fh;
}

=head2 prompt_state

The L</run> method can be executed iteratively so that the loop doesn't block the rest of
your script's execution.  To that end, this hashref holds the state of the console if a user
happens to be mid-password-entry.  Subclasses could also use it to hold state for something
other than a console, like window handles etc.  When the user is I<not> being prompted for a
password, this hashref should be empty.

=cut

sub prompt_state { $_[0]{prompt_state} ||= {} }

=head2 password_buffer

An instance of L<Crypt::SecretBuffer> that receives passwords.

=cut

sub password_buffer {
   $_[0]{password_buffer} ||= Crypt::SecretBuffer->new(stringify_mask => '[PASSWORD]')
}

=head2 ssh_agent

An instance of L<Crypt::MultiKey::SSHAgentClient>.  It will be created on demand if you don't
initialize it.

=cut

sub ssh_agent { $_[0]{ssh_agent} }

=head1 METHODS

=head2 add_pkey

  my $added= $iun->add_pkey($PKey_obj, ...);

Add (or re-add) one or more PKey objects for consideration.  If the PKey object has the private
half available, it triggers a check for whether this key object can provide the solution to one
of the L</goals>.  Any time you obtain the private half of a key object, pass it to this method
again to check for a solution.

Returns the number of PKey objects which were added.  Check the L</unlocked> attribute to see if
one of them completed a goal.  Note that you still need to call L</run> to trigger a call to
C<< ->target->unlock(@keys) >> even if this method sets C<unlocked>.

=cut

sub add_pkey {
   my $self= shift;
   my @pkeys= @_ == 1 && ref $_[0] eq 'ARRAY'? @{$_[0]}
            : @_ == 1 && ref $_[0] eq 'HASH'? values %{$_[0]}
            : @_;
   my $added= 0;
   for my $pkey (@pkeys) {
      blessed($pkey) && $pkey->isa('Crypt::MultiKey::PKey')
         or croak "Not a PKey";
      if (!exists $self->{pkeys}{refaddr($pkey)}) {
         $self->{pkeys}{refaddr($pkey)}= $_;
         push @{$self->{pkeys_by_fingerprint}{$pkey->fingerprint} ||= []}, $pkey;
         push @{$self->{pkeys_by_public}{$pkey->public} ||= []}, $pkey;
         ++$added;
      }
      $self->_check_complete($pkey) if $pkey->has_private && defined $self->{goals};
   }
   return $added;
}

# Given a newly-complete PKey, see if any goals are resolved.
sub _check_complete {
   my ($self, $pkey)= @_;
   # First, if this PKey shares a public key with any others, copy the private key to them.
   my @same_pub= $self->pkeys_by_public($pkey->public);
   if (@same_pub > 1) {
      $_->private($pkey->private) for grep !$_->has_private, @same_pub;
   }
   # Check whether any goal is met
   my $solved;
   for my $g (@{ $self->_achievable_goals }) {
      if (exists $g->{$pkey->public}) {
         $g->{$pkey->public}= 1;
         # If there are no false values left in this set, it is the solution.
         $solved ||= $g unless grep !$_, values %$g;
      }
   }
   if ($solved && !$self->unlocked) {
      # convert from the original goal record to an arrayref of PKey objects
      my @solution= @{ $solved->{origin} };
      for (@solution) {
         # Either a PKey object or fingerprint string
         if (!ref) {
            ($_)= $self->pkeys_by_fingerprint($_)
               or croak "BUG: fingerprint in solution lacks PKey object";
         }
      }
      $self->unlocked(\@solution);
   }
   return defined $self->unlocked;
}

=head2 exclude_pkey

  $iun->exclude_pkey($PKey_obj, ...);

Flag a PKey object as impossible to obtain the private half via this algorithm.  For example,
if there is no console available and the PKey requires a password, then L</run> can't obtain
the private half.  Likewise if the PKey is encrypted with FIDO2 but libfido2 wasn't available
when Crypt::MultiKey was built, then all FIDO2 keys get excluded.

This removes the PKey object from L</pkeys> but not from L</pkeys_by_public> or
L</pkeys_by_fingerprint>.

=cut

sub exclude_pkey {
   my $self= shift;
   my $pks= $self->{pkeys};
   my $removed= 0;
   for my $pkey (@_) {
      # delete from pkeys, but don't delete from pkeys_by_fingerprint or pkeys_by_public
      # in case there is another PKey of the same public key which isn't excluded which
      # we are later able to copy the private key from.
      if (delete $pks->{refaddr($pkey)}) {
         # Do we have more PKeys of the same public key which haven't been excluded?
         my $pub= $pkey->public;
         unless (grep exists $pks->{refaddr($_)}, $self->pkeys_by_public($pub)) {
            # last one of this public key has been excluded, so exclude all goals that
            # rely on this public key.
            my $achievable= $self->_achievable_goals;
            @$achievable= grep !exists $_->{$pub}, @$achievable;
         }
         ++$removed;
      }
   }
   return $removed;
}

# destructive-backspace over the prompt line, then flag append_console_line that it will need
# to re-render the prompt.
sub _clear_prompt_line {
   my $self= shift;
   my $pst= $self->prompt_state;
   if (keys %$pst) { # empty state means no password prompt in progress
      my $out= $pst->{prompt_fh};
      my $mask_len= length $pst->{char_mask} || 0;
      if ($out && (length $pst->{prompt} || $mask_len)) {
         my $pw_buf= $self->password_buffer;
         # determine how many characters we need to erase
         my $n= (length $pst->{prompt} || 0)
              + ($pw_buf? $pw_buf->length * $mask_len : 0);
         $out->print("\b \b"x$n);
         $out->flush;
         $self->prompt_state->{re_prompt}= 1;
      }
   }
}

# emit a message to the user, either printing on the console or some other form of
# notification that a subclass could implement.
sub _emit_msg {
   my ($self, $msg)= @_;
   $msg .= "\n" unless $msg =~ /\n\z/;
   my $pst= $self->prompt_state;
   my $out;
   if (keys %$pst) {
      $self->_clear_prompt_line;
      $out= $pst->{prompt_fh}
   }
   $out ||= $self->prompt_fh;
   $out->print($msg);
   $out->flush;
}

=head2 run

  my $bool= $iun->run(%options);

Run the interactive unlock algorithm.
This begins a console/tty interactive process to call C<obtain_private> on one or more sets
of PKey objects, succeeding as soon as one of the sets is fully assembled.

The PKey objects may already have the private halves loaded, in which case some sets may already
be complete, and this function returns success immediately.  Otherwise, it groups the
private-lacking PKey objects by mechanism:

=over

=item Password

If any PKey can be decrypted by a plain password, the interactive loop will prompt for passwords
and then test each remaining password-encrypted key to see if the password can decrypt it.

=item SSHAgentSignature

If an SSH Agent is available, it will check for any PKey that can be decrypted by a signature
from any of the keys in your agent.  It will re-check that list once per second, allowing you
to add them to your agent on the fly.

=item YKChalResp

If any PKey requires the YubiKey OTP Chal/Resp protocol, it scans for attached YubiKeys of a
matching serial number.  If found, it starts a "ykchalresp" in a background thread/process
which succeeds as soon as you touch the button on the YubiKey.  It re-checks for matching
devices every second.

=item FIDO2

If any PKey requires the FIDO2 protocol, it scans for attached FIDO2 devices of a matching
C<aaguid>.  If found, it requests an assertion from the device in a background thread/process
which succeeds as soon as you touch the button, unless the credentials aren't on that device
in which case the device is ignored.  If the assertion fails due to lack of a PIN, it prompts
for the PIN and tries again.  It re-scans for new devices once a second.

=back

In addition to the password prompt, it prints status messages about the remaining number and
type of PKeys it is attempting to obtain private halves for.

This function may return false if the user presses ^C or hits enter on a blank line.

=cut

sub run {
   my ($self, %options)= @_;
   $options{poll_period} //= 0.2;
   # If the _achievable_goals attribute is not built it means that the 'goals' have changed.
   unless (defined $self->{_achievable_goals}) {
      # Do the initial handling of pkeys that already have private half loaded.
      for (@{$self->pkeys}) {
         $self->_check_complete($_) if $_->has_private;
      }
      # avoid probing resources if already unlocked
      unless (defined $self->unlocked) {
         # Weed out PKeys that can't obtain private half due to missing external resources
         for my $pkey (@{ $self->pkeys }) {
            # test the cached value for this key's protection scheme
            # else test the key itself, which will return undef on a permanent failure
            my $avail= $self->_protection_scheme_available($pkey);
            $avail //= defined $pkey->can_obtain_private;
            if (!$avail) {
               $self->_emit_msg("Discarding key ".$pkey->fingerprint." (".$pkey->protection_scheme."); permanent error");
               $self->exclude_pkey($pkey);
            }
         }
      }
   }
   while (@{ $self->_achievable_goals } && !defined $self->unlocked) {
      my $start_t= time;
      $self->_run_iteration(\%options);
      last if $options{one_iteration};
      # sleep at least .2 sec each iteration
      my $dT= time - $start_t;
      sleep($options{poll_period} - $dT) if $options{poll_period} > $dT;
   }
   # apply the solution to the target
   if (defined $self->unlocked) {
      _lock_mech_from_target($self->target)->unlock(@{ $self->unlocked })
         if $self->target;
      return 1; # success
   } elsif (@{ $self->_achievable_goals } && $options{one_iteration}) {
      return undef; # try again
   } else {
      return 0; # failure
   }
}

our %try_scheme_priority= (
   # Test all the ssh-agent ones first because they likely don't need any interaction
   SSHAgentSignature => -4,
   # Check for newly inserted hardware keys, next
   FIDO2 => -3,
   YKChalResp => -2,
   Password => -1,
);
sub _run_iteration {
   my ($self, $options)= @_;
   # Group keys by protection scheme
   my %per_scheme;
   for my $pkey (@{ $self->pkeys }) {
      push @{ $per_scheme{$pkey->protection_scheme} }, $pkey
         unless $pkey->has_private;
   }
   for (sort { ($try_scheme_priority{$a}||0) <=> ($try_scheme_priority{$b}||0) } %per_scheme) {
      my $method= $self->can('_try_pkeys_'.$_);
      if ($method) {
         return if $method->($self, $per_scheme{$_}, $options);
      } else {
         # Unknown types of keys will just have to intelligently handle frequent requests
         # as we loop.
         for (@{$per_scheme{$_}}) {
            my $ready= $_->can_obtain_private;
            if ($ready) {
               if (eval { $_->obtain_private; 1 }) {
                  return if $self->check_complete($_);
               }
            } elsif (!defined $ready) {
               # permanent failure
               $self->_emit_msg("Discarding key ".$_->fingerprint." (".$_->protection_scheme."); permanent error");
               $self->exclude_pkey($_);
            }
         }
      }
   }
}

sub _protection_scheme_available {
   my ($self, $pkey)= @_;
   my $scheme= $pkey->protection_scheme
      or return 0;
   # cache results for known schemes
   unless (exists $self->{_scheme_avail}{$scheme}) {
      $self->{_scheme_avail}{$scheme}= $self->_test_protection_scheme_available($pkey);
   }
   return $self->{_scheme_avail}{$scheme};
}

sub _test_protection_scheme_available {
   my ($self, $pkey)= @_;
   my $scheme= $pkey->protection_scheme || '';
   my $avail;
   if ($scheme eq 'SSHAgentSignature') {
      # This can't succeed unless we have access to an agent
      $self->{ssh_agent} ||= $pkey->agent;
      $avail= !!eval { $self->{ssh_agent}->list_keys; 1; };
      $self->_emit_msg("No SSH Agent available") unless $avail;
   } elsif ($scheme eq 'FIDO2') {
      # Can't succeed unless fido2 support compiled
      $avail= !!Crypt::MultiKey::FIDO2->available;
      $self->_emit_msg("FIDO2 support is not available") unless $avail;
   } elsif ($scheme eq 'YKChalResp') {
      # Can't succeed unless Yubico OTP tools installed, or on Linux with HIDRAW.
      $avail= !!Crypt::MultiKey::YubicoOTP->available;
      $self->_emit_msg("Yubico OTP support is not available") unless $avail;
   }
   # else assume scheme is available, but not conclusive (undef)
   return $avail;
}

sub _try_pkeys_SSHAgentSignature {
   my ($self, $pkeys, $options)= @_;
   my $ssh_agent= ($self->{ssh_agent} ||= $pkeys->[0]->agent);
   my @agent_keys= $ssh_agent->list_keys;
   my @ready= grep $_->can_obtain_private(ssh_agent_keys => \@agent_keys), @$pkeys;
   if (@ready) {
      $self->_emit_msg("Requesting SSH Agent signature");
      for (@ready) {
         if (eval { $_->obtain_private }) {
            return if $self->_check_complete($_);
         } else {
            # We already checked 'can_obtain_private', so failure here means the signing
            # request failed.  That probably means this key won't ever work.
            $self->_emit_msg("SSH Agent Signature failed: $@");
            $self->exclude_pkey($_);
         }
      }
   }
}

sub _try_pkeys_FIDO2 {
   my ($self, $pkeys, $options)= @_;
   my @fido_devs= Crypt::MultiKey::FIDO2::list_devices();
   my $prev= $self->{_prev_fido2_devices} || [];
   $self->{_prev_fido2_devices}= \@fido_devs;
   # FIDO devices aren't uniquely identifiable, so we just have to poll fast enough to
   # detect differences in the length of the list and then test them all.
   return unless @$prev != @fido_devs && @fido_devs;

   # we can issue all challenges to a device at once if they have the same challenge
   my %per_aaguid_challenge;
   for (@$pkeys) {
      push @{ $per_aaguid_challenge{$_->fido2_aaguid . $_->challenge} }, $_;
   }
   for my $pkey_group (values %per_aaguid_challenge) {
      my @devs= grep $_->aaguid eq $pkey_group->[0]->fido2_aaguid, @fido_devs;
      if (@devs) {
         $self->_emit_msg("Making request to attached FIDO2 device");
         for (@devs) {
            if (my ($secret, $cred_used)= eval {
               $_->assert_hmac_secret(
                  credential => [ map $_->fido2_credential, @$pkey_group ],
                  challenge => $pkey_group->[0]->challenge
               );
            }) {
               for (grep $_->fido2_credential == $cred_used, @$pkey_group) {
                  if (eval { $_->obtain_private(hmac_secret => $secret); 1 }) {
                     return if $self->_check_complete($_);
                  } else {
                     # If the credential succeeded but the password did not, that's
                     # a fatal failure.
                     $self->_emit_msg("FIDO2 HMAC failed to decrypt the private key: $@");
                     $self->exclude_pkey($_);
                  }
               }
            } else {
               # TODO: handle requesting PIN from user
               #if ($@ =~ /\bPIN\b/i) {
               $self->_emit_msg("$@");
            }
         }
      }
   }
}

sub _try_pkeys_YKChalResp {
   my ($self, $pkeys, $options)= @_;
   # has list of devices changed since last iteration?
   my $prev= join ',', map $_->serial, @{ $self->{_prev_yubico_otp_devices} || [] };
   my @yk_devs= Crypt::MultiKey::YubicoOTP::list_devices();
   $self->{_prev_yubico_otp_devices}= \@yk_devs;
   return unless $prev ne join(',', map $_->serial, @yk_devs);

   # check each PKey which has its key present.
   for my $pkey (grep $_->can_obtain_private(yubico_otp_devices => \@yk_devs), @$pkeys) {
      $self->_emit_msg("Making request to YubiKey");
      if (eval { $pkey->obtain_private(yubico_otp_devices => \@yk_devs); 1 }) {
         return if $self->_check_complete($pkey);
      } else {
         $self->_emit_msg("$@");
         # might fail because user didn't press button in time.  Keep trying it
         # after a remove/insert is observed.
      }
   }
}

sub _try_pkeys_Password {
   my ($self, $pkeys, $options)= @_;
   # prompt for password.  This can delay for up to .2 seconds waiting for user input.
   my $pw_buf= $self->password_buffer;
   my $result= $pw_buf->append_console_line(
      input_fh => $self->inpuit_fh,
      prompt_fh => $self->prompt_fh,
      utf8 => 1,
      prompt => "Enter password (^C to cancel): ",
      char_mask => '*',
      timeout => $options->{poll_period} // 0.2,
      state => $self->prompt_state,
   );
   if ($result) {
      my $used= 0;
      # Try password against all keys
      for my $pkey (@$pkeys) {
         if (eval { $pkey->decrypt_private($pw_buf); 1 }) {
            $used++;
            $self->_check_complete($pkey);
         }
         else {
            $self->_emit_msg("$@")
               unless $@ =~ /^password/; # no harm in incorrect passwords
         }
      }
      $self->_emit_msg("Password does not match any PKey")
         unless $used;
      $pw_buf->length(0);
   }
   elsif (defined $result) {
      $pw_buf->length(0);
      # defined-false means got ^C, so abort
      return 0;
   }
}

1;
