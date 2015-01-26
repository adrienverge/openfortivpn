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

#ifndef _IPV4_H
#define _IPV4_H

#include <net/route.h>
#include <string.h>

#define route_dest(route) \
	(((struct sockaddr_in *) &(route)->rt_dst)->sin_addr)
#define route_mask(route) \
	(((struct sockaddr_in *) &(route)->rt_genmask)->sin_addr)
#define route_gtw(route) \
	(((struct sockaddr_in *) &(route)->rt_gateway)->sin_addr)
#define route_iface(route) \
	((route)->rt_dev)

#define ROUTE_IFACE_LEN 32

static inline int route_init(struct rtentry *route)
{
	memset(route, 0, sizeof(*route));

	route_iface(route) = malloc(ROUTE_IFACE_LEN);
	if (route_iface(route) == NULL)
		return 1;
	route_iface(route)[0] = '\0';

	((struct sockaddr_in *) &(route)->rt_dst)->sin_family = AF_INET;
	((struct sockaddr_in *) &(route)->rt_genmask)->sin_family = AF_INET;
	((struct sockaddr_in *) &(route)->rt_gateway)->sin_family = AF_INET;

	return 0;
}

static inline int route_destroy(struct rtentry *route)
{
	free(route_iface(route));
	return 0;
}

int ipv4_get_route(struct rtentry *route);
int ipv4_set_route(struct rtentry *route);
int ipv4_del_route(struct rtentry *route);

struct tunnel;

int ipv4_set_tunnel_routes(struct tunnel *tunnel);
int ipv4_restore_routes(struct tunnel *tunnel);

int ipv4_add_nameservers_to_resolv_conf(struct tunnel *tunnel);
int ipv4_del_nameservers_from_resolv_conf(struct tunnel *tunnel);

#endif
