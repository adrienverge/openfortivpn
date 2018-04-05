#!/bin/bash
# Copyright (C) 2015 Adrien Vergé

# Guidelines say 80, let's tolerate a bit more
MAX=90

rc=0

for file in "$@"; do
  tmp=$(mktemp)

  # Preprocess source code
  # 1. Replace tabs with 8 spaces
  # 2. Remove strings so that they are not taken into account when
  #    calculating line lengths (this is far from being foolproof
  #    but is probably good enough for now)
  sed 's/\t/        /g; s/"[^"]*"/""/g' "$file" >$tmp

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
