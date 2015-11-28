#!/bin/bash
# Copyright (C) 2015 Adrien Vergé

rc=0

bash tests/lint/eol-at-eof.sh $(git ls-files)
[ $? -ne 0 ] && rc=1

bash tests/lint/line-length.sh $(git ls-files '*.[ch]')
[ $? -ne 0 ] && rc=1

bash tests/lint/astyle.sh $(git ls-files '*.[ch]')
[ $? -ne 0 ] && rc=1

exit $rc
