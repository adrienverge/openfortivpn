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

#include <errno.h>
#include <netinet/in.h>
#include <string.h>

#define ERR_CFG_UNKNOWN		-1
#define ERR_CFG_SEE_ERRNO	-2
#define ERR_CFG_EMPTY_FILE	-3
#define ERR_CFG_NO_MEM		-4
#define ERR_CFG_CANNOT_READ	-4

static inline const char *err_cfg_str(int code)
{
	if (code == ERR_CFG_SEE_ERRNO)
		return strerror(errno);
	else if (code == ERR_CFG_EMPTY_FILE)
		return "Empty file";
	else if (code == ERR_CFG_NO_MEM)
		return "Not enough memory";
	else if (code == ERR_CFG_CANNOT_READ)
		return "Cannot read file";
	return "unknown";
}

#define SHA256LEN	(256 / 8)
#define SHA256STRLEN	(2 * SHA256LEN + 1)

struct x509_digest {
	struct x509_digest *next;
	char data[SHA256STRLEN];
};

#define FIELD_SIZE	64
#define COOKIE_SIZE	300

struct vpn_config {
	char 		gateway_host[FIELD_SIZE + 1];
	struct in_addr	gateway_ip;
	uint16_t	gateway_port;
	char		username[FIELD_SIZE + 1];
	char		password[FIELD_SIZE + 1];
	char		otp[FIELD_SIZE + 1];
	char		cookie[COOKIE_SIZE + 1];
	char            realm[FIELD_SIZE + 1];

	int	set_routes;
	int	set_dns;
	int     pppd_use_peerdns;
	int     use_syslog;

	char	*pppd_log;
	char	*pppd_plugin;
	char	*pppd_ipparam;

	char	                *ca_file;
	char	                *user_cert;
	char	                *user_key;
	int			verify_cert;
	int			insecure_ssl;
	char			*cipher_list;
	struct x509_digest	*cert_whitelist;
};

#define init_vpn_config(cfg) \
	do { \
		(cfg)->gateway_host[0] = '\0'; \
		(cfg)->gateway_port = 0; \
		(cfg)->realm[0] = '\0'; \
		(cfg)->username[0] = '\0'; \
		(cfg)->password[0] = '\0'; \
		(cfg)->otp[0] = '\0'; \
		(cfg)->pppd_log = NULL; \
		(cfg)->pppd_plugin = NULL; \
		(cfg)->pppd_ipparam = NULL; \
		(cfg)->ca_file = NULL; \
		(cfg)->user_cert = NULL; \
		(cfg)->user_key = NULL; \
		(cfg)->cipher_list = NULL; \
		(cfg)->cert_whitelist = NULL; \
		(cfg)->use_syslog = 0; \
	} while (0)

#define destroy_vpn_config(cfg) \
	while ((cfg)->cert_whitelist != NULL) { \
		struct x509_digest *tmp = (cfg)->cert_whitelist->next; \
		free((cfg)->cert_whitelist); \
		(cfg)->cert_whitelist = tmp; \
	} \
	free((cfg)->pppd_log); \
	free((cfg)->pppd_ipparam); \
	free((cfg)->pppd_plugin); \
	free((cfg)->ca_file); \
	free((cfg)->user_cert); \
	free((cfg)->user_key); \
	free((cfg)->cipher_list);

int add_trusted_cert(struct vpn_config *cfg, const char *digest);

int load_config(struct vpn_config *cfg, const char *filename);

#endif
