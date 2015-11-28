#!/bin/bash
# Copyright (C) 2015 Adrien Vergé

# Guidelines say 80, let's tolerate a bit more
MAX=90

rc=0

for file in "$@"; do
  tmp=$(mktemp)

  # Replace tabs with 8 spaces
  sed 's/\t/        /g' "$file" >$tmp

  awk "{
         if (length(\$0) > $MAX) {
           print \"$file:\" NR \": line too long (\" length \" char)\"
           rc = 1
         }
       } END { exit rc }" $tmp
  [ $? -ne 0 ] && rc=1

  rm $tmp
done

exit $rc
