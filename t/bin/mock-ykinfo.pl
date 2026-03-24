# Simulate having 3 YubiKeys where the first has serial number disabled,
# the second uses slot 2 for chalresp, and the third uses slot 1.
use strict;
use warnings;

my $serial = 0;
my %opts;
#print STDERR "mock-ykinfo.pl: ".join(' ', map "'$_'", @ARGV)."\n";

for (@ARGV) {
   if (/^-n(\d+)\z/) {
      $serial += $1 * 10000000 + $1;
      if ($1 > 2) {
         print STDERR "Yubikey core error: no yubikey present\n";
         exit 1;
      }
   }
   elsif (/^-([asHmvtp12iI])\z/) {
      $opts{$1}++;
   }
   else {
      print STDERR "unsupported option\n";
      exit 1;
   }
}

printf "serial: %08d\n", $serial     if $opts{a} || $opts{s};
printf "serial_hex: %06x\n", $serial if $opts{a} || $opts{H};
printf "serial_modhex: xxxxxx\n"     if $opts{a} || $opts{m};
printf "version: 5.4.3\n"            if $opts{a} || $opts{v};
printf "touch_level: 775\n"          if $opts{a} || $opts{t};
printf "programming_sequence: 3\n"   if $opts{a} || $opts{p};
printf "slot1_status: 1\n"           if $opts{a} || $opts{1};
printf "slot2_status: 1\n"           if $opts{a} || $opts{2};
printf "vendor_id: 1050\n"           if $opts{a} || $opts{i};
printf "product_id: 407\n"           if $opts{a} || $opts{I};

exit 0;
