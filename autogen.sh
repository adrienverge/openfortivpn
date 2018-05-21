#!/bin/sh
set -exu

if ! type autoconf >/dev/null 2>&1 ; then
  echo "autoconf not found - please install it" >&2
  exit 1
fi

if ! type automake >/dev/null 2>&1 ; then
  echo "automake not found - please install it" >&2
  exit 1
fi

if type aclocal >/dev/null 2>&1 ; then
  aclocal
fi

autoconf
automake --add-missing

echo "now you can run ./configure && make to build openfortivpn"
