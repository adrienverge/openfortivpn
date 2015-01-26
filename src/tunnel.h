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

#ifndef _TUNNEL_H
#define _TUNNEL_H

#include <sys/types.h>
#include <stdint.h>
#include <unistd.h>
#include <pthread.h>
#include <openssl/ssl.h>
#include <netinet/in.h>
#include <semaphore.h>

#include "hdlc.h"
#include "io.h"
#include "ipv4.h"

#define COOKIE_SIZE (12 + 3 * (64 + 3))

struct vpn_config {
	char 		*gateway_host;
	struct in_addr	gateway_ip;
	uint16_t	gateway_port;
	char		*username;
	char		*password;
	char		cookie[COOKIE_SIZE + 1];
	//int		fortigate_version;
	//int		exclusive_routing;
	int		set_routes;
	int		set_dns;
	char		*pppd_log;
};

enum tunnel_state {
	STATE_DOWN,
	STATE_CONNECTING,
	STATE_UP,
	STATE_DISCONNECTING
};

struct tunnel {
	struct vpn_config *config;

	enum tunnel_state state;

	struct ppp_packet_pool ssl_to_pty_pool;
	struct ppp_packet_pool pty_to_ssl_pool;

	pid_t	pppd_pid;
	pid_t	pppd_pty;
	char	ppp_iface[ROUTE_IFACE_LEN];

	int		ssl_socket;
	SSL_CTX		*ssl_context;
	SSL		*ssl_handle;

	struct in_addr ip_addr;
	struct in_addr nameserver1;
	struct in_addr nameserver2;

	struct rtentry default_route;
	struct rtentry gtw_route;
	struct rtentry ppp_route;

	int (*on_ppp_if_up)(struct tunnel *);
	int (*on_ppp_if_down)(struct tunnel *);
};

int ppp_interface_is_up(struct tunnel *tunnel);

int run_tunnel(struct vpn_config *config);

#endif
