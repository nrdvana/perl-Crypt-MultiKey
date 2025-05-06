#! perl
use Test2::V0;
use strict;
use warnings;
use Crypt::MultiKey::Mechanism::SSHAgentSignature;
my $class= 'Crypt::MultiKey::Mechanism::SSHAgentSignature';

unless ($class->check_dependencies(\my %details)) {
   diag "$_: $details{$_}" for sort keys %details;
   skip_all "missing dependencies";
}

done_testing;
