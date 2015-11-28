#!/bin/bash
# Copyright (C) 2015 Adrien Vergé

# Check that astyle is installed
if ! which astyle &>/dev/null; then
  echo "error: astyle is not installed" >&2
  exit -1
fi

rc=0

for file in "$@"; do
  tmp=$(mktemp)

  astyle \
    --style=linux \
    --indent=tab=8 \
    --pad-header \
    --align-reference=type \
    <"$file" >$tmp

  if ! cmp -s "$file" $tmp; then
    echo "error: $file does not comply with coding style"
    git --no-pager diff --no-index -U0 "$file" $tmp
    rc=1
  fi

  rm $tmp
done

exit $rc
