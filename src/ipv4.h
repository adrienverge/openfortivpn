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
 */

#ifndef OPENFORTIVPN_IPV4_H
#define OPENFORTIVPN_IPV4_H

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/route.h>

#if !HAVE_RT_ENTRY_WITH_RT_DST
/*
 * On Mac OS X and FreeBSD struct rtentry is not directly available.
 * On FreeBSD one could #define _WANT_RTENTRY but the struct does not
 * contain rt_dst for instance. The entries for mask and destination
 * are maintained in a separate radix_tree structure by the routing
 * table instance. We can not simply copy rtentry structures.
 */

/* This structure gets passed by the SIOCADDRT and SIOCDELRT calls. */
struct rtentry {
	unsigned long   rt_hash;        /* hash key for lookups         */
	struct sockaddr rt_dst;         /* target address               */
	struct sockaddr rt_gateway;     /* gateway addr (RTF_GATEWAY)   */
	struct sockaddr rt_genmask;     /* target network mask (IP)     */
	short           rt_flags;
	short           rt_refcnt;
	unsigned long   rt_use;
	struct ifnet    *rt_ifp;
	short           rt_metric;      /* +1 for binary compatibility! */
	char            *rt_dev;        /* forcing the device at add    */
	unsigned long   rt_mss;         /* per route MTU/Window         */
	unsigned long   rt_mtu;         /* compatibility                */
	unsigned long   rt_window;      /* Window clamping              */
	unsigned short  rt_irtt;        /* Initial RTT                  */
};
#endif

#define ROUTE_IFACE_LEN 32
#define MAX_SPLIT_ROUTES 65535
#define STEP_SPLIT_ROUTES 32

struct ipv4_config {
	struct in_addr	ip_addr;
	struct in_addr	peer_addr;

	struct in_addr	ns1_addr;
	struct in_addr	ns2_addr;
	char		*dns_suffix;
	int		ns1_was_there;  // were ns1 already in /etc/resolv.conf?
	int		ns2_was_there;  // were ns2 already in /etc/resolv.conf?
	int		dns_suffix_was_there; // was the dns suffix already there?
	int		split_routes;
	int		route_to_vpn_is_added;

	struct rtentry	def_rt; // default route
	struct rtentry	gtw_rt; // route to access VPN gateway
	struct rtentry	ppp_rt; // new default route through VPN
	struct rtentry	*split_rt; // split VPN routes
};

// Dummy function to make gcc 6 happy
static inline struct sockaddr_in *cast_addr(struct sockaddr *addr)
{
	return (struct sockaddr_in *) addr;
}
#define route_dest(route)  (cast_addr(&(route)->rt_dst)->sin_addr)
#define route_mask(route)  (cast_addr(&(route)->rt_genmask)->sin_addr)
#define route_gtw(route)   (cast_addr(&(route)->rt_gateway)->sin_addr)
#define route_iface(route) ((route)->rt_dev)

struct tunnel;

int ipv4_add_split_vpn_route(struct tunnel *tunnel, char *dest, char *mask,
                             char *gateway);
int ipv4_set_tunnel_routes(struct tunnel *tunnel);
int ipv4_restore_routes(struct tunnel *tunnel);

int ipv4_add_nameservers_to_resolv_conf(struct tunnel *tunnel);
int ipv4_del_nameservers_from_resolv_conf(struct tunnel *tunnel);

#endif
