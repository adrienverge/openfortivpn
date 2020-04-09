# http://mij.oltrelinux.com/devel/autoconf-automake/

bin_PROGRAMS = openfortivpn
openfortivpn_SOURCES = src/config.c src/config.h src/hdlc.c src/hdlc.h \
		       src/http.c src/http.h src/io.c src/io.h src/ipv4.c \
		       src/ipv4.h src/log.c src/log.h src/tunnel.c \
		       src/tunnel.h src/main.c src/ssl.h src/xml.c \
		       src/xml.h src/userinput.c src/userinput.h \
		       src/openssl_hostname_validation.c \
		       src/openssl_hostname_validation.h
openfortivpn_CFLAGS = -Wall -pedantic -std=gnu99
openfortivpn_CPPFLAGS = -DSYSCONFDIR=\"$(sysconfdir)\" \
			-DPPP_PATH=\"@PPP_PATH@\" \
			-DNETSTAT_PATH=\"@NETSTAT_PATH@\" \
			-DRESOLVCONF_PATH=\"@RESOLVCONF_PATH@\" \
			-DREVISION=\"@REVISION@\"

openfortivpn_CPPFLAGS += $(OPENSSL_CFLAGS) $(LIBSYSTEMD_CFLAGS)
openfortivpn_LDADD = $(OPENSSL_LIBS) $(LIBSYSTEMD_LIBS)

DISTCHECK_CONFIGURE_FLAGS = CFLAGS=-Werror

confdir=$(sysconfdir)/@PACKAGE@
datadir=$(prefix)/share/@PACKAGE@
data_DATA=etc/openfortivpn/config.template

etc/openfortivpn/config: $(srcdir)/etc/openfortivpn/config.template
	@$(MKDIR_P) etc/openfortivpn
	$(AM_V_GEN)$(SED) -e '3,$$ s/^/# /' $(srcdir)/etc/openfortivpn/config.template >$@

install-data-hook: etc/openfortivpn/config
	if ! test -f $(DESTDIR)$(confdir)/config ; then \
		$(MKDIR_P) $(DESTDIR)$(confdir) ; \
		$(INSTALL) -m 600 etc/openfortivpn/config \
			$(DESTDIR)$(confdir)/config ; \
	fi

dist_man_MANS = doc/openfortivpn.1

doc/openfortivpn.1: $(srcdir)/doc/openfortivpn.1.in
	@$(MKDIR_P) doc
	$(AM_V_GEN)$(SED) -e 's|[@]SYSCONFDIR[@]|$(sysconfdir)|g;s|[@]DATADIR[@]|$(datadir)|g' $(srcdir)/doc/openfortivpn.1.in >$@

all-local: etc/openfortivpn/config

clean-local:
	-rm -f etc/openfortivpn/config
	-rm -f doc/openfortivpn.1

EXTRA_DIST = autogen.sh CHANGELOG.md LICENSE LICENSE.OpenSSL README.md doc/openfortivpn.1.in $(data_DATA)
