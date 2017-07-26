#!/bin/sh
set -exu

aclocal
autoconf
automake --add-missing
