#!/usr/bin/env bash
# Copyright (c) 2015 Adrien Vergé

rc=0

./tests/lint/eol-at-eof.sh $(git ls-files) || rc=1

./tests/lint/line_length.py $(git ls-files '*.[ch]') || rc=1

./tests/lint/astyle.sh $(git ls-files '*.[ch]') || rc=1

./tests/lint/checkpatch.sh $(git ls-files '*.[ch]') || rc=1

exit $rc
