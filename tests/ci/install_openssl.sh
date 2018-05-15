#!/bin/sh

set -e

PREFIX="$1"

[ -x "${PREFIX}/bin/openssl" ] && exit 0

VERSION=1.0.2o
SRC="https://www.openssl.org/source/openssl-${VERSION}.tar.gz"

wget -O openssl.tar.gz "$SRC"
tar -xf openssl.tar.gz -C "$HOME"
cd "${HOME}/openssl-${VERSION}"
./config --prefix="$PREFIX" shared -fPIC
make
make install
