# http://mij.oltrelinux.com/devel/autoconf-automake/

bin_PROGRAMS = openfortivpn
openfortivpn_SOURCES = src/config.c src/config.h src/hdlc.c src/hdlc.h \
		       src/http.c src/http.h src/io.c src/io.h src/ipv4.c \
		       src/ipv4.h src/log.c src/log.h src/tunnel.c \
		       src/tunnel.h src/main.c
openfortivpn_CFLAGS = -Wall -std=gnu99

confdir=$(sysconfdir)/openfortivpn
conf_DATA = etc/openfortivpn/config

dist_man_MANS = doc/openfortivpn.1

EXTRA_DIST = LICENSE README.md
