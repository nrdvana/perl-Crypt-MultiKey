#! /bin/sh
if [ -z "${TEST_PERL_INTERPRETER+x}" ] || [ -z "$TEST_PERL_INTERPRETER" ]; then
    echo "TEST_PERL_INTERPRETER is not set" >&2
    exit 127
fi
dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
exec "$TEST_PERL_INTERPRETER" "$dir/mock-ykinfo.pl" "$@"
