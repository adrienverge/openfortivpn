#!/usr/bin/env bash
# Copyright (c) 2020 Dimitri Papadopoulos

# Path to checkpatch.pl
script_dir=$(dirname "${BASH_SOURCE[0]}")
checkpatch_path=$(realpath "${script_dir}/../ci/checkpatch/checkpatch.pl")

rc=0

for file in "$@"; do
  tmp=$(mktemp)

  "$checkpatch_path" --no-tree --terse \
    --ignore MACRO_ARG_UNUSED,LEADING_SPACE,SPDX_LICENSE_TAG,CODE_INDENT,NAKED_SSCANF,VOLATILE,NEW_TYPEDEFS,LONG_LINE,LONG_LINE_STRING,QUOTED_WHITESPACE_BEFORE_NEWLINE,STRCPY,STRLCPY,STRNCPY \
    -f "$file" | tee "$tmp"
  
  if [ -s "$tmp" ]; then
    echo "error: $file does not comply with Linux kernel coding style" >&2
    rc=1
  fi

  rm "$tmp"
done

exit $rc
