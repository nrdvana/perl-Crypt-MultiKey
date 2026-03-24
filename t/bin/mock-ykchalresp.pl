# Simulate having 3 YubiKeys where the first has serial number disabled,
# the second uses slot 2 for chalresp, and the third uses slot 1.
use strict;
use warnings;
use Digest::SHA "sha1";

my $serial= 0;
my %secret= (
   '0,1' => "112233445566778899aabbccddeeff0011223344",
   '0,2' => "2233445566778899aabbccddeeff001122334455",
   '10000001,2' => "33445566778899aabbccddeeff00112233445566",
   '20000002,1' => "445566778899aabbccddeeff0011223344556677",
);
my %opts;
my $challenge= pop @ARGV;
for (@ARGV) {
   if (/^-n(\d+)\z/) {
      $serial += $1 * 10000000 + $1;
      if ($1 > 2) {
         print STDERR "Yubikey core error: no yubikey present\n";
         exit 1;
      }
   }
   elsif (/^-([12HYxt])\z/) {
      $opts{$1}++;
   }
   else {
      print STDERR "unsupported option $_\n";
      exit 1;
   }
}
my $slot= $opts{2}? 2 : 1;
my $secret= $secret{"$serial,$slot"};
if ($secret) {
   $challenge= pack("H*", $challenge) if $opts{x};
   print unpack('H*', sha1($secret . $challenge))."\n";
   exit 0;
} else {
   print STDERR "Yubikey core error: timeout $serial $slot\n";
   exit 1;
}
