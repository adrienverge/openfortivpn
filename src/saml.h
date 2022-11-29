#ifndef OPENFORTIVPN_SAML_H
#define OPENFORTIVPN_SAML_H

int saml_get_cookie(char *vpn_domain, char *realm, char **dst_cookie, char *cert);

#endif
