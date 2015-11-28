#!/bin/bash
# Copyright (C) 2015 Adrien Vergé

rc=0

for file in "$@"; do
  if [ "$(sed -n '$p' "$file")" = "" ]; then
    echo "$file: too many newlines at end of file"
    rc=1
  fi

  if [ "$(tail -c 1 "$file")" != "" ]; then
    echo "$file: no newline at end of file"
    rc=1
  fi
done

exit $rc
