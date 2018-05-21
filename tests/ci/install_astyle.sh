#!/bin/sh

set -e

PREFIX="$1"

ln -fs "${PREFIX}/bin/astyle" "${HOME}/bin/astyle"
[ -x "${PREFIX}/bin/astyle" ] && exit 0

VERSION=3.1
SRC="https://sourceforge.net/projects/astyle/files/astyle/astyle%20${VERSION}/astyle_${VERSION}_linux.tar.gz/download"

wget -O astyle.tar.gz "$SRC"
tar -xf astyle.tar.gz -C "$HOME"
cd "${HOME}/astyle/build/gcc"
make
make prefix="$PREFIX" install
