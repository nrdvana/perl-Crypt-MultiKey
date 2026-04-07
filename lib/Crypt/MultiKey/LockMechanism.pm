package Crypt::MultiKey::LockMechanism;
# VERSION
# ABSTRACT: Implementation of a key-wrapping-scheme used by Coffer and Vault

=head1 DESCRIPTION

This class implements the "Multi Key" behavior of L<Coffer|Crypt::MultiKey::Coffer> and
L<Vault|Crypt::MultiKey::Vault>.  The basic structure of the C<LockMechanism> is an array of
"locks", each of which has an array of "tumblers".

  # conceptually:
  [
    [ $key1, $key2 ],        # lock 0
    [ $key3 ],               # lock 1
    [ $key4, $key5, $key6 ]  # lock 2
  ]

Each lock independently provides access to the primary symmetric key secret.  A lock can be
opened by inserting one L<PKey|Crypt::MultiKey::PKey> (with private key available) into each of
its tumblers, and calling L</unlock>.

Since each key is a public/private keypair, you can also encrypt a new primary symmetric key
secret when only the public halves of the PKeys are available.  You can also take an existing
C<LockMechanism> and add new locks to it so long as you have the primary symmetric key
decrypted.

This class is only the lock mechanism, and does not handle serialization.

=cut

use v5.10;
use warnings;
use Carp;
use Scalar::Util qw( blessed );
use Crypt::SecretBuffer qw( secret );
sub _isa_secret { blessed($_[0]) && $_[0]->isa('Crypt::SecretBuffer') }

=constructor new

Basic constructor.  Attributes C<locks> and C<primary_skey> can be provided.

=cut

our %_attr_pri;
sub new {
   my $class= shift;
   my %attrs= @_ == 1? %{$_[0]} : @_;
   my $self= bless { locks => [] }, $class;
   # Hook for subclasses to process attributes
   $self->_init(\%attrs) if $self->can('_init');
   # Every remaining attribute must have a setter accessor
   for (sort { ($_attr_pri{$a}||0) <=> ($_attr_pri{$b}||0) } keys %attrs) {
      my $setter= "_set_$_";
      $self->$setter($attrs{$_})
   }
   return $self;
}

=attribute primary_skey

A L<Crypt::SecretBuffer> holding the symmetric key used to derive L</cipher_skey> and
L</hmac_skey>.  This is the main secret that is encrypted and decrypted by the locks.

The C<LockMechanism> is logically "unlocked" when the C<primary_skey> is defined, and "locked"
(or uninitialized) when it isn't.

=over

=item unlocked

Convenience accessor that returns true if C<primary_skey> is defined.

=item initialized

Convenience accessor that returns true if C<primary_skey> is defined, or if any L</locks> are
defined.

=back

=attribute cipher_skey

A L<Crypt::SecretBuffer> holding the symmetric key to be used for AES encryption of content.

=attribute hmac_skey

A L<Crypt::SecretBuffer> holding the symmetric key to be used for authenticating metadata.

=cut

sub primary_skey { @_ > 1? shift->_set_primary_skey(@_) : $_[0]{primary_skey} }

sub unlocked { defined $_[0]{primary_skey} }

sub initialized { defined $_[0]{primary_skey} || $_[0]{locks} && @{$_[0]{locks}} }

sub _set_primary_skey {
   my ($self, $val)= @_;
   croak "Not a SecretBuffer"
      unless _isa_secret($val);
   $self->{primary_skey}= $val;
   $self;
}

sub cipher_skey {
   my $skey= $_[0]->primary_skey || croak "Coffer is locked";
   return Crypt::MultiKey::hkdf(
      { size => 32, kdf_info => 'Crypt::MultiKey/cipher_skey', kdf_salt => '' },
      $skey
   );
}
sub hmac_skey {
   my $skey= $_[0]->primary_skey || croak "Coffer is locked";
   return Crypt::MultiKey::hkdf(
      { size => 32, kdf_info => 'Crypt::MultiKey/hmac_skey', kdf_salt => '' },
      $skey
   );
}

=method generate_primary_skey

Generate a new L</primary_skey>.  This can only be done when all locks (if any) have at least
their public keys L<inserted|/insert_keys>.

=cut

sub generate_primary_skey {
   my $self= shift;
   my ($old_locks, $empty_locks)= $self->insert_keys;
   croak "Generating a new primary_skey requires all existing locks to have public keys inserted"
      if @$empty_locks;
   my $new_skey= secret(append_random => 64);
   my @new_locks;
   # If any locks exist, need to create new tumblers
   if (@$old_locks) {
      local $self->{primary_skey}= $new_skey;
      local $self->{locks}= \@new_locks;
      for (@$old_locks) {
         $self->add_access(map $_->{key}, @{ $_->{tumblers} });
      }
   }
   # Nothing crashed, so probably safe to proceeed.
   $self->{primary_skey}= $new_skey;
   @{$self->{locks}}= @new_locks;
   # Likewise for ciphertext fields, but the subclasses manage that.
   $self;
}

=attribute locks

An arrayref of lock definitions, B<each> of which is sufficient to open the C<LockMechanism>.
Locks are created with L</add_access> method to emphasize that each one I<adds> access to the
secret rather than restricting it.

Each lock is a key-wrapping-scheme that contains an encryption of the L</primary_skey> using a
symmetric key derived from the public half of a list of component public/private keypairs.
During the creation process, one "tumbler" L<is generated|Crypt::MultiKey::PKey/generate_key_material>
for each public/private keypair such that the original symmetric key can only be
L<recreated|Crypt::MultiKey::PKey/recreate_key_material> by engaging the tumbler with the
private half of its key.

  locks => [
    { cipher        => 'AES-256-GCM',
      ciphertext    => $encrypted_bytes,
      tumblers      => [
        { key_fingerprint    => $hashname_and_base64,
          ephemeral_pubkey   => $pubkey_bytes,
          rsa_key_ciphertext => $encrypted_bytes,
        },
        ...
      ],
    },
    ...
  ]

The private half must be present to open the tumbler, but only the public half is needed to
create the tumbler.  This means the C<primary_skey> can be updated even when the private half
of the keys are not available.

=cut

sub locks { @_ > 1? shift->_set_locks(@_) : $_[0]{locks} }
sub _set_locks {
   my ($self, $val)= @_;
   $self->_validate_locks($val);
   $self->{locks}= $val;
   $self;
}

=method add_access

  $coffer->add_access($key1, ... $keyN);

This creates a new L</locks> entry, which provides a new way to access the Coffer independent of
other locks.  The new lock can be opened when the private half of all N keys are passed to the
L</unlock> method (or L</insert_keys> method).

=cut

sub add_access {
   my ($self, @keys)= @_;
   @keys= @{$keys[0]} if @keys == 1 && ref $keys[0] eq 'ARRAY';
   croak "Require one or more PKey objects"
      unless @keys > 0;
   # No existing encrypted data, so create a new key
   $self->generate_primary_skey
      unless $self->initialized;
   # Ensure we have the key now
   croak "Coffer must be unlocked in order to ->add_access"
      unless $self->unlocked;
   my @tumblers= map +{ key => $_, key_fingerprint => $_->fingerprint }, @keys;
   my $key_material= secret;
   $_->{key}->generate_key_material($_, $key_material)
      for @tumblers;
   my %lock= ( tumblers => \@tumblers );
   my $symmetric_key= $self->_hkdf_for_lock(\%lock, $key_material);
   # Use the keyslot's aes key to encrypt the primary key
   $lock{ciphertext}= Crypt::MultiKey::symmetric_encrypt(\%lock, $symmetric_key, $self->primary_skey);
   push @{$self->locks}, \%lock;
   return \%lock;
}

=method insert_keys

  (\@complete_locks, \@incomplete_locks)= $coffer->insert_keys(@pkeys);

When deserialized from a PEM file, the tumblers of the L</locks> attribute reference keys by
their C<SHA-256> fingerprint.  Those need upgraded to L<PKey objects|Crypt::MultiKey::PKey>
before the C<Coffer> can be unlocked.
This method adds references to PKey objects based on a matching fingerprint.
The references persist in the L</locks> attribute, allowing you to call C<insert_keys> multiple
times if desired to populate additional tumblers.
If a tumbler already contains a C<PKey> object, it will be replaced by the new object in this
list unless the previous included the private half and the new one lacks the private half.

The return value is a pair of arrayrefs, one with the locks which have all PKeys inserted, and
the other of any locks still lacking a PKey object.  This is unrelated to whether the PKey
objects include their private half, needed for L</unlock>.

=cut

sub insert_keys {
   my ($self, @keys)= @_;
   my %by_fingerprint= map +($_->fingerprint => $_), @keys;
   my (@complete, @incomplete);
   for (@{ $self->locks }) {
      my $dest= \@complete;
      for (@{ $_->{tumblers} }) {
         if (my $k= $by_fingerprint{$_->{key_fingerprint}}) {
            # prefer an existing key if it has a private half and the new one does not
            next if $_->{key} && !$k->has_private && $_->{key}->has_private;
            $_->{key}= $k;
         }
         elsif (!$_->{key}) {
            $dest= \@incomplete;
         }
      }
      push @$dest, $_;
   }
   return (\@complete, \@incomplete);
}

=method unlock

  
  $coffer->unlock($key1, ... $keyN);

This attempts to find a lock which can be unlocked by this list of keys, or a subset of them.
If found, the L</primary_skey> attribute is set, after which decryption and encryption methods
can be used.

=cut

sub unlock {
   my ($self, @keys)= @_;
   return if defined $self->{primary_skey};
   @keys= @{$keys[0]} if @keys == 1 && ref $keys[0] eq 'ARRAY';
   for my $pkey (@keys) {
      croak "Expected PKey object"
         unless blessed($pkey) && $pkey->can('has_private');
      croak "key ".$pkey->fingerprint." does not have the private half loaded"
         unless $pkey->has_private;
   }
   my ($complete, $incomplete)= $self->insert_keys(@keys);
   # "complete" is a list of all locks where all keys are present, but might just be the
   # public keys.  Further filter that by which ones have all private keys present.
   my ($primary_skey, @failures);
   for my $lock (@$complete) {
      my $tumblers= $lock->{tumblers};
      next if grep !$_->{key}->has_private, @$tumblers;
      # All private keys are present.  Reconstruct the shared secret key material from
      # the private key and the tumbler of each key in order.
      last if defined eval {
            my $key_material= secret();
            $_->{key}->recreate_key_material($_, $key_material)
               for @$tumblers;
            my $aes_key= $self->_hkdf_for_lock($lock, $key_material);
            $primary_skey= Crypt::MultiKey::symmetric_decrypt($lock, $aes_key, $lock->{ciphertext});
         };
      push @failures, $@;
   }
   if (@failures) {
      if (defined $primary_skey) {
         # If this lock succeeded but others failed, the user should know about that.
         # A lock with all keys present should always succeed, unless perhaps a subclass
         # adds an interactive feature to recreate_key_material...
         carp scalar(@failures)." locks failed to decrypt even though the supplied keys matched";
      } else {
         chomp(@failures);
         croak join "\n  ", map scalar(@failures)." matching locks failed to open using the supplied keys:",
            @failures;
      }
   }
   croak "No lock can be opened using the available keys"
      unless defined $primary_skey;
   $self->primary_skey($primary_skey);
   $self;
}

sub _hkdf_for_lock {
   my ($self, $lock, $key_material)= @_;
   # Use local to set defaults temporarily so they don't get exported.
   local $lock->{kdf_info}= 'Crypt::MultiKey/lock' unless defined $lock->{kdf_info};
   # Salt isn't very useful when the tumbers are made from nonces and single-use ephemeral keys
   local $lock->{kdf_salt}= '' unless defined $lock->{kdf_salt};
   return Crypt::MultiKey::hkdf($lock, $key_material);
}

=method lock

Delete the L</primary_skey> attribute and any attributes holding unencrypted secrets.

=cut

sub lock {
   my $self= shift;
   # Make sure there is a way to unlock it!
   croak "Can't lock() when no locks are defined!  (you would lose your data)"
      unless @{ $self->locks };
   delete $self->{primary_skey};
   $self;
}

our %_known_lock_fields= map +($_ => 1),
   qw( cipher kdf_salt ciphertext tumblers );
our %_known_tumbler_fields= map +($_ => 1),
   qw( key key_fingerprint ephemeral_pubkey rsa_key_ciphertext kem_ciphertext );
sub _validate_locks {
   my ($self, $locks)= @_;
   croak "locks must be an arrayref"
      unless ref $locks eq 'ARRAY';
   my @unknown;
   for my $lock_i (0..$#$locks) {
      my $lock= $locks->[$lock_i];
      for (qw( cipher ciphertext )) {
         croak "Missing '$_' in lock $lock_i"
            unless defined $lock->{$_};
      }
      croak "lock[$lock_i]{tumblers} must be an arrayref"
         unless ref $lock->{tumblers} eq 'ARRAY';
      for my $tmbl_i (0..$#{$lock->{tumblers}}) {
         my $tmbl= $lock->{tumblers}[$tmbl_i];
         # Need to be able to identify the key
         croak "No key details for tumbler $tmbl_i"
            unless defined $tmbl->{key} || defined $tmbl->{key_fingerprint};
         # Need either ephemeral_pubkey or rsa_key_ciphertext
         croak "tumbler $tmbl_i must have rsa_key_ciphertext or ephemeral_pubkey or kem_ciphertext"
            unless 1 == defined($tmbl->{rsa_key_ciphertext})
                      + defined($tmbl->{ephemeral_pubkey})
                      + defined($tmbl->{kem_ciphertext});
         @unknown= grep !$_known_tumbler_fields{$_}, keys %$tmbl;
         carp "Unknown tumbler[$tmbl_i] attributes: ".join(', ', @unknown)
            if @unknown;
      }
      @unknown= grep !$_known_lock_fields{$_}, keys %$lock;
      carp "Unknown lock[$lock_i] attributes: ".join(', ', @unknown)
         if @unknown;
   }
   return 1;
}

1;
