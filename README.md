Crypt::MultiKey
---------------

### About

This module facilitates encrypting secrets with one or more public keys or
combinations of public keys, which can then be decrypted by the corresponding
private keys.  It's kind of like an enhanced 'age' tool in library form that
doubles as a password safe.  It also provides various ways of interacting with
public/private keys and decrypting the private half using a variety of means.

### Installing

When distributed, all you should need to do is run

    perl Makefile.PL
    make install

or better,

    cpanm Crypt-MultiKey-x.xxx.tar.gz

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

    ./dzil-prove t/10-keygen.t  # or any other test case

which runs "dzil build" to get a clean dist, then enters the build directory
and runs "perl Makefile.PL" to compile the XS, then "prove -lvb t/01-ctor.t".

### Copyright

This software is copyright (c) 2025 by Michael Conrad

This is free software; you can redistribute it and/or modify it under
the same terms as the Perl 5 programming language system itself.
