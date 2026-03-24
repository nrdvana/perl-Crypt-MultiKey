@echo off
if not defined TEST_PERL_INTERPRETER (
    echo TEST_PERL_INTERPRETER is not set 1>&2
    exit /b 127
)
"%TEST_PERL_INTERPRETER%" "%~dp0mock-ykinfo.pl" %*
