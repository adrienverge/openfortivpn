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

#ifndef OPENFORTIVPN_CONFIG_H
#define OPENFORTIVPN_CONFIG_H

#include <netinet/in.h>
#include <net/if.h>

#include <errno.h>
#include <stdint.h>
#include <string.h>

#define ERR_CFG_UNKNOWN		-1
#define ERR_CFG_SEE_ERRNO	-2
#define ERR_CFG_EMPTY_FILE	-3
#define ERR_CFG_NO_MEM		-4
#define ERR_CFG_CANNOT_READ	-5

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

#if HAVE_USR_SBIN_PPPD
#define PPP_DAEMON "pppd"
#else
#define PPP_DAEMON "ppp"
#endif

#define SHA256LEN	(256 / 8)
#define SHA256STRLEN	(2 * SHA256LEN + 1)

struct x509_digest {
	struct x509_digest *next;
	char data[SHA256STRLEN];
};

#define GATEWAY_HOST_SIZE	253
#define USERNAME_SIZE	64
#define PASSWORD_SIZE	256
#define OTP_SIZE	64
#define REALM_SIZE	63

/*
 * RFC 6265 does not limit the size of cookies:
 * https://www.rfc-editor.org/info/rfc6265
 *
 * Yet browsers typically limit themselves to ~4K so we are on the safe side:
 * http://browsercookielimits.squawky.net/
 */
#define COOKIE_SIZE	4096

/*
 * GNU libc used to limit the search list to 256 characters:
 * https://unix.stackexchange.com/questions/245849
 *
 * We believe we are on the safe side using this value.
 */
#define MAX_DOMAIN_LENGTH 256

struct vpn_config {
	char		gateway_host[GATEWAY_HOST_SIZE + 1];
	struct in_addr	gateway_ip;
	uint16_t	gateway_port;
	char		username[USERNAME_SIZE + 1];
	char		password[PASSWORD_SIZE + 1];
	int		password_set;
	char		otp[OTP_SIZE + 1];
	char		*otp_prompt;
	unsigned int	otp_delay;
	int		no_ftm_push;
	char		*pinentry;
	char		iface_name[IF_NAMESIZE];
	char		realm[REALM_SIZE + 1];

	int	set_routes;
	int	set_dns;
	int	pppd_use_peerdns;
	int	use_syslog;
#if HAVE_RESOLVCONF
	int	use_resolvconf;
#endif
	int	half_internet_routes;

	unsigned int	persistent;

#if HAVE_USR_SBIN_PPPD
	char	*pppd_log;
	char	*pppd_plugin;
	char	*pppd_ipparam;
	char	*pppd_ifname;
	char	*pppd_call;
#endif
#if HAVE_USR_SBIN_PPP
	char	*ppp_system;
#endif
	char			*ca_file;
	char			*user_cert;
	char			*user_key;
	int			insecure_ssl;
	int			min_tls;
	int			seclevel_1;
	char			*cipher_list;
	struct x509_digest	*cert_whitelist;
	int			use_engine;
	char			*user_agent;
	char			*hostcheck;
	char			*check_virtual_desktop;
	int			daemonize;
};

int add_trusted_cert(struct vpn_config *cfg, const char *digest);
int strtob(const char *str);
int parse_min_tls(const char *str);

int load_config(struct vpn_config *cfg, const char *filename);
void destroy_vpn_config(struct vpn_config *cfg);

/*
 * merge source config into dest
 *
 * memory allocated dynamically is transferred with this function
 * e.g. ownership goes to dest config
 */
void merge_config(struct vpn_config *dest, struct vpn_config *source);

extern const struct vpn_config invalid_cfg;

#endif
