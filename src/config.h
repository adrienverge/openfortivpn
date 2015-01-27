/*
 *  Copyright (C) 2015 Adrien Vergé
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _CONFIG_H
#define _CONFIG_H

#include <netinet/in.h>

#define SHA256LEN	(256 / 8)
#define SHA256STRLEN	(2 * SHA256LEN + 1)

struct x509_digest {
	struct x509_digest *next;
	char data[SHA256STRLEN];
};

#define FIELD_SIZE	64
#define COOKIE_SIZE	(12 + 3 * (64 + 3))

struct vpn_config {
	char 		gateway_host[FIELD_SIZE];
	struct in_addr	gateway_ip;
	uint16_t	gateway_port;
	char		username[FIELD_SIZE];
	char		password[FIELD_SIZE];
	char		cookie[COOKIE_SIZE + 1];

	int	set_routes;
	int	set_dns;

	char	*pppd_log;

	int			verify_cert;
	struct x509_digest	*cert_whitelist;
};

#define init_vpn_config(cfg) \
	do { \
		(cfg)->gateway_host[0] = '\0'; \
		(cfg)->gateway_port = 0; \
		(cfg)->username[0] = '\0'; \
		(cfg)->password[0] = '\0'; \
		(cfg)->pppd_log = NULL; \
		(cfg)->cert_whitelist = NULL; \
	} while (0)

#define destroy_vpn_config(cfg) \
	while ((cfg)->cert_whitelist != NULL) { \
		struct x509_digest *tmp = (cfg)->cert_whitelist->next; \
		free((cfg)->cert_whitelist); \
		(cfg)->cert_whitelist = tmp; \
	}

int add_trusted_cert(struct vpn_config *cfg, const char *digest);

int load_config(struct vpn_config *cfg, const char *filename);

#endif
