#!/bin/bash
# Copyright (C) 2015 Adrien Vergé

rc=0

./tests/lint/eol-at-eof.sh $(git ls-files | grep -v openssl_hostname_validation) || rc=1

./tests/lint/line_length.py $(git ls-files '*.[ch]' | grep -v openssl_hostname_validation) || rc=1

./tests/lint/astyle.sh $(git ls-files '*.[ch]' | grep -v openssl_hostname_validation) || rc=1

exit $rc
