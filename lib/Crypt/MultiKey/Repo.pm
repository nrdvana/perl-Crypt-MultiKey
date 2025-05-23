package Crypt::MultiKey::Repo;
# VERSION
# ABSTRACT: Container object for managing keys and secrets in a directory

=head1 SYNOPSIS

  Crypt::MultiKey::Repo->new(path => $path);
  $key= $repo->key($name_or_uuid);
  $secret= $repo->secret($name_or_uuid);
  $repo->new_key($name, $mechanism, \%options);
  $repo->new_key(\%options);
  $repo->new_secret($name, \%options);

=cut

use strict;
use warnings;