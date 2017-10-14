# http://mij.oltrelinux.com/devel/autoconf-automake/

bin_PROGRAMS = openfortivpn
openfortivpn_SOURCES = src/config.c src/config.h src/hdlc.c src/hdlc.h \
		       src/http.c src/http.h src/io.c src/io.h src/ipv4.c \
		       src/ipv4.h src/log.c src/log.h src/tunnel.c \
		       src/tunnel.h src/main.c src/ssl.h src/xml.c \
		       src/xml.h src/userinput.c src/userinput.h
openfortivpn_CFLAGS = -Wall --pedantic -std=gnu99
openfortivpn_CPPFLAGS = -DSYSCONFDIR=\"$(sysconfdir)\"

openfortivpn_CFLAGS += $(OPENSSL_CFLAGS)
openfortivpn_LDADD = $(OPENSSL_LIBS)

DISTCHECK_CONFIGURE_FLAGS = CFLAGS=-Werror

confdir=$(sysconfdir)/openfortivpn
datadir=$(prefix)/share/openfortivpn
data_DATA=etc/openfortivpn/config.template

install-data-hook:
	chmod 0600 $(DESTDIR)$(datadir)/config.template ; \
	if ! test -e $(DESTDIR)$(sysconfdir)/openfortivpn/config ; then \
		mkdir -p $(DESTDIR)$(sysconfdir)/openfortivpn ; \
		cp -a $(DESTDIR)$(datadir)/config.template \
			 $(DESTDIR)$(sysconfdir)/openfortivpn/config ; \
	fi

dist_man_MANS = doc/openfortivpn.1

doc/openfortivpn.1: $(srcdir)/doc/openfortivpn.1.in
	sed -e 's|[@]SYSCONFDIR[@]|$(sysconfdir)|g;s|[@]DATADIR[@]|$(datadir)|g;' $^ >$@

EXTRA_DIST = LICENSE README.md doc/openfortivpn.1.in $(data_DATA)
