#!/bin/sh
set -ex

aclocal
autoconf
automake --add-missing
