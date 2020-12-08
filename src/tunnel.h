/*
 *  Copyright (c) 2015 Adrien Vergé
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
 *
 *  In addition, as a special exception, the copyright holders give permission
 *  to link the code of portions of this program with the OpenSSL library under
 *  certain conditions as described in each individual source file, and
 *  distribute linked combinations including the two.
 *  You must obey the GNU General Public License in all respects for all of the
 *  code used other than OpenSSL.  If you modify file(s) with this exception,
 *  you may extend this exception to your version of the file(s), but you are
 *  not obligated to do so.  If you do not wish to do so, delete this exception
 *  statement from your version.  If you delete this exception statement from
 *  all source files in the program, then also delete it here.
 */

#ifndef OPENFORTIVPN_TUNNEL_H
#define OPENFORTIVPN_TUNNEL_H

#include "config.h"
#include "io.h"
#include "ipv4.h"

#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include <sys/types.h>

#ifdef __clang__
/*
 * Get rid of Mac OS X 10.7 and greater deprecation warnings
 * see for instance https://wiki.openssl.org/index.php/Hostname_validation
 * this pragma selectively suppresses this type of warnings in clang
 */
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#endif

enum tunnel_state {
	STATE_DOWN,
	STATE_CONNECTING,
	STATE_UP,
	STATE_DISCONNECTING
};

enum tun_ppp_state {
	TUN_PPP_LCP,
	TUN_PPP_IPCP,
	TUN_PPP_SESSION,
};

struct tunnel {
	struct vpn_config *config;

	enum tunnel_state state;
	enum tun_ppp_state tun_state;
	char cookie[COOKIE_SIZE + 1];

	struct ppp_packet_pool ssl_to_pty_pool;
	struct ppp_packet_pool pty_to_ssl_pool;

	pid_t	pppd_pid;
	pid_t	pppd_pty;
	int	use_tun;
	char	tun_iface[ROUTE_IFACE_LEN];
	char	ppp_iface[ROUTE_IFACE_LEN];

	int	ssl_socket;
	SSL_CTX	*ssl_context;
	SSL	*ssl_handle;

	struct ipv4_config ipv4;

	int (*on_ppp_if_up)(struct tunnel *tunnel);
	int (*on_ppp_if_down)(struct tunnel *tunnel);
};

struct token {
	const char *uri;
	X509 *cert;
};

int ppp_interface_is_up(struct tunnel *tunnel);

int ssl_connect(struct tunnel *tunnel);

int run_tunnel(struct vpn_config *config);

#define ARRAY_SIZE(x)	(sizeof(x) / sizeof((x)[0]))

#endif
