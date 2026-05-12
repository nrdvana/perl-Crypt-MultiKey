Crypt::MultiKey
---------------

### About

This module provides a cryptography metaphor that is hopefully intuitive to
non-cryptographers, while offering a powerful API for encrypting data with
one or more key combinations, such that various key combinations can each
decrypt the secret.  PKey can load public/private keys from OpenSSL and
OpenSSH formats and protect them in various ways, Coffer holds an in-memory
secret locked with PKeys, and Vault handles random-access sector-based
encryption locked with PKeys.

### Installing

This module requires OpenSSL or LibreSSL to be installed, with development
headers.  To enable the full feature set, you should also install libfido2
and its headers before building this module.

When distributed, all you should need to do is run

    perl Makefile.PL
    make install

or better,

    cpanm Crypt-MultiKey-0.xxx.tar.gz

or from CPAN:

    cpanm Crypt::MultiKey

### Developing

However, if you're trying to build from a fresh Git checkout, you'll need
the Dist::Zilla tool (and many plugins) to create the Makefile.PL.

    cpanm Dist::Zilla
    dzil authordeps --missing | cpanm
    dzil build

While Dist::Zilla takes the busywork and mistakes out of module authorship,
it fails to address the need of XS authors to easily compile XS projects
and run single test cases rather than the whole test suite.  For this, you
might find the following script handy:

    ./dzil-prove t/01-ctor.t  # or any other test case

which runs "dzil build" to get a clean dist, then enters the build directory
and runs "perl Makefile.PL" to compile the XS, then "prove -lvb t/01-ctor.t".

### Copyright

This software is copyright (c) 2025-2026 by Michael Conrad

This is free software; you can redistribute it and/or modify it under
the same terms as the Perl 5 programming language system itself.
