use FindBin;
use lib "$FindBin::Bin/lib";
use Test2AndUtils;
use Crypt::MultiKey qw( pkey );
use Crypt::MultiKey::LockMechanism;
use Crypt::MultiKey::InteractiveUnlock;

my $user_entered_pw;
no warnings 'redefine';
local *Crypt::MultiKey::InteractiveUnlock::_try_pkeys_Password= sub {
   my ($self, $pkeys, $options)= @_;
   note 'trying to collect password for '.@$pkeys.' PKeys';
   # Try password against all keys
   for my $pkey (@$pkeys) {
      if (eval { $pkey->decrypt_private($user_entered_pw); 1 }) {
         $self->_check_complete($pkey);
      }
      else {
         $self->_emit_msg("$@")
            unless $@ =~ /^password/; # no harm in incorrect passwords
      }
   }
};

my $pk1= pkey(generate => 'RSA1024', password => "hunter2");
my $pk2= pkey(generate => 'x25519', password => "*****");
my $pk3= pkey(generate => 'x25519', password => "qwerty");
my $lm= Crypt::MultiKey::LockMechanism->new;
$lm->add_access($pk1, $pk2);
$lm->add_access($pk2, $pk3);

ok( my $iu= Crypt::MultiKey::InteractiveUnlock->new(target => $lm), 'constructor' );
ok( $iu->run, 'succeeds, because keys already have private half' );
ok( $iu->unlocked, 'unlocked' );

$pk1->clear_private;

ok( $iu= Crypt::MultiKey::InteractiveUnlock->new(target => $lm), 'constructor' );
ok( $iu->run, 'succeeds, because keys 2+3 already have private half' );
ok( $iu->unlocked, 'unlocked' );

$pk3->clear_private;

ok( $iu= Crypt::MultiKey::InteractiveUnlock->new(target => $lm), 'constructor' );

$user_entered_pw= 'test';
ok( !$iu->run(one_iteration => 1), 'run fails, wrong password' );
ok( !$iu->unlocked, 'not unlocked' );

$user_entered_pw= 'qwerty';
ok( $iu->run(one_iteration => 1), 'run succeeds' );
ok( $iu->unlocked, 'unlocked' );

done_testing;
