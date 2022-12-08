#ifndef OPENFORTIVPN_SAML_H
#define OPENFORTIVPN_SAML_H

#include <stdint.h>

int saml_get_cookie(char *gateway_host, uint16_t gateway_port, char *realm, char **dst_cookie, char *cert);

#endif
