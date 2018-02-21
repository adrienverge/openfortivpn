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

#include "ipv4.h"
#include "tunnel.h"
#include "config.h"
#include "log.h"

#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>

#define SHOW_ROUTE_BUFFER_SIZE 128

static char show_route_buffer[SHOW_ROUTE_BUFFER_SIZE];

#define ERR_IPV4_SEE_ERRNO	-1
#define ERR_IPV4_NO_MEM		-2
#define ERR_IPV4_PERMISSION	-3
#define ERR_IPV4_NO_SUCH_ROUTE	-4
#define ERR_IPV4_PROC_NET_ROUTE	-5

static inline const char *err_ipv4_str(int code)
{
	if (code == ERR_IPV4_SEE_ERRNO)
		return strerror(errno);
	else if (code == ERR_IPV4_NO_MEM)
		return "Not enough memory";
	else if (code == ERR_IPV4_PERMISSION)
		return "Permission denied";
	else if (code == ERR_IPV4_NO_SUCH_ROUTE)
		return "Route not found";
	else if (code == ERR_IPV4_PROC_NET_ROUTE)
		return "Parsing /proc/net/route failed";
	return "unknown";
}

/*
 * Returns a string representation of the route, such as:
 *   to 192.168.1.0/255.255.255.0 via 172.16.0.1 dev eth0
 *
 * Warning: the returned buffer is static, so multiple calls will overwrite it.
 */
static char *ipv4_show_route(struct rtentry *route)
{
	strcpy(show_route_buffer, "to ");
	strncat(show_route_buffer, inet_ntoa(route_dest(route)), 15);
	strcat(show_route_buffer, "/");
	strncat(show_route_buffer, inet_ntoa(route_mask(route)), 15);
	if (route->rt_flags & RTF_GATEWAY) {
		strcat(show_route_buffer, " via ");
		strncat(show_route_buffer, inet_ntoa(route_gtw(route)), 15);
	}
	if (route_iface(route)[0] != '\0') {
		strcat(show_route_buffer, " dev ");
		strncat(show_route_buffer, route_iface(route), ROUTE_IFACE_LEN - 1);
	}

	return show_route_buffer;
}

static inline int route_init(struct rtentry *route)
{
	memset(route, 0, sizeof(*route));

	route_iface(route) = malloc(ROUTE_IFACE_LEN);
	if (route_iface(route) == NULL)
		return ERR_IPV4_NO_MEM;
	route_iface(route)[0] = '\0';

	cast_addr(&(route)->rt_dst)->sin_family = AF_INET;
	cast_addr(&(route)->rt_genmask)->sin_family = AF_INET;
	cast_addr(&(route)->rt_gateway)->sin_family = AF_INET;

	return 0;
}

static inline void route_destroy(struct rtentry *route)
{
	if (route_iface(route) != NULL) {
		free(route_iface(route));
		route_iface(route) = NULL;
	}
}

/*
 * Finds system IP route to a destination.
 *
 * The passed route must have dest and mask set. If the route is found, the
 * function fills the gtw and iface properties.
 */
static int ipv4_get_route(struct rtentry *route)
{
	size_t size;
	char buffer[0x1000];
	char *start, *line;
	char *saveptr1 = NULL, *saveptr2 = NULL;

	log_debug("ip route show %s\n", ipv4_show_route(route));

#ifdef __APPLE__
	FILE *fp;
	int len = sizeof(buffer) - 1;
	char *saveptr3 = NULL;

	// Open the command for reading
	fp = popen("/usr/sbin/netstat -f inet -rn", "r");
	if (fp == NULL)
		return ERR_IPV4_SEE_ERRNO;

	line = buffer;
	// Read the output a line at a time
	while (fgets(line, len, fp) != NULL) {
		len -= strlen(line);
		line += strlen(line);
	}
	size = sizeof(buffer)-1 - len;
	pclose(fp);

	// reserve enough memory (256 shorts)
	// to make sure not to access out of bounds later,
	// for ipv4 only unsigned short is allowed

	unsigned short flag_table[256] = { 0 };

	// fill the table now (I'm still looking for a more elagant way to do this),
	// also, not all flags might be allowed in the context of ipv4
#ifdef RTF_PROTO1     // Protocol specific routing flag #1
	flag_table['1'] = RTF_PROTO1 & USHRT_MAX;
#endif
#ifdef RTF_PROTO2     // Protocol specific routing flag #2
	flag_table['2'] = RTF_PROTO2 & USHRT_MAX;
#endif
#ifdef RTF_PROTO3     // Protocol specific routing flag #3
	flag_table['3'] = RTF_PROTO3 & USHRT_MAX;
#endif
#ifdef RTF_BLACKHOLE  // Just discard packets (during updates)
	flag_table['B'] = RTF_BLACKHOLE & USHRT_MAX;
#endif
#ifdef RTF_BROADCAST  // The route represents a broadcast address
	flag_table['b'] = RTF_BROADCAST & USHRT_MAX;
#endif
#ifdef RTF_CLONING    // Generate new routes on use
	flag_table['C'] = RTF_CLONING & USHRT_MAX;
#endif
#ifdef RTF_PRCLONING  // Protocol-specified generate new routes on use
	flag_table['c'] = RTF_PRCLONING & USHRT_MAX;
#endif
#ifdef RTF_DYNAMIC    // Created dynamically (by redirect)
	flag_table['D'] = RTF_DYNAMIC & USHRT_MAX;
#endif
#ifdef RTF_GATEWAY    // Destination requires forwarding by intermediary
	flag_table['G'] = RTF_GATEWAY & USHRT_MAX;
#endif
#ifdef RTF_HOST       // Host entry (net otherwise)
	flag_table['H'] = RTF_HOST & USHRT_MAX;
#endif
#ifdef RTF_IFSCOPE    // Route is associated with an interface scope
	flag_table['I'] = RTF_IFSCOPE & USHRT_MAX;
#endif
#ifdef RTF_IFREF      // Route is holding a reference to the interface
	flag_table['i'] = RTF_IFREF & USHRT_MAX;
#endif
#ifdef RTF_LLINFO     // Valid protocol to link address translation
	flag_table['L'] = RTF_LLINFO & USHRT_MAX;
#endif
#ifdef RTF_MODIFIED   // Modified dynamically (by redirect)
	flag_table['M'] = RTF_MODIFIED & USHRT_MAX;
#endif
#ifdef RTF_MULTICAST  // The route represents a multicast address
	flag_table['m'] = RTF_MULTICAST & USHRT_MAX;
#endif
#ifdef RTF_REJECT     // Host or net unreachable
	flag_table['R'] = RTF_REJECT & USHRT_MAX;
#endif
#ifdef RTF_ROUTER     // Host is a default router
	flag_table['r'] = RTF_ROUTER & USHRT_MAX;
#endif
#ifdef RTF_STATIC     // Manually added
	flag_table['S'] = RTF_STATIC & USHRT_MAX;
#endif
#ifdef RTF_UP         // Route usable
	flag_table['U'] = RTF_UP & USHRT_MAX;
#endif
#ifdef RTF_WASCLONED  // Route was generated as a result of cloning
	flag_table['W'] = RTF_WASCLONED & USHRT_MAX;
#endif
#ifdef RTF_XRESOLVE   // External daemon translates proto to link address
	flag_table['X'] = RTF_XRESOLVE & USHRT_MAX;
#endif
#ifdef RTF_PROXY      // Proxying; cloned routes will not be scoped
	flag_table['Y'] = RTF_PROXY & USHRT_MAX;
#endif

#else
	int fd;
	// Cannot stat, mmap not lseek this special /proc file
	fd = open("/proc/net/route", O_RDONLY);
	if (fd == -1)
		return ERR_IPV4_SEE_ERRNO;

	size = read(fd, buffer, sizeof(buffer) - 1);
	if (size == -1) {
		close(fd);
		return ERR_IPV4_SEE_ERRNO;
	}
	close(fd);
#endif

	if (size == 0) {
		log_debug("routing table is empty.\n");
		return ERR_IPV4_PROC_NET_ROUTE;
	}
	buffer[size] = '\0';

	// Skip first line
	start = index(buffer, '\n');
	if (start == NULL) {
		log_debug("routing table is malformed.\n");
		return ERR_IPV4_PROC_NET_ROUTE;
	}
	start++;

#ifdef __APPLE__
	// Skip 3 more line
	start = index(start, '\n');
	start = index(++start, '\n');
	start = index(++start, '\n');
	if (start == NULL) {
		log_debug("routing table is malformed.\n");
		return ERR_IPV4_PROC_NET_ROUTE;
	}

#endif

	// Look for the route
	line = strtok_r(start, "\n", &saveptr1);
	while (line != NULL) {
		char *iface;
		uint32_t dest, mask, gtw;
		unsigned short flags;
#ifdef __APPLE__
		char tmp_ip_string[16];
		struct in_addr dstaddr;
		int pos;
		char *tmpstr;

		log_debug("line: %s\n", line);

		saveptr3 = NULL;
		dest = UINT32_MAX;
		mask = UINT32_MAX;
		// "Destination"
		tmpstr = strtok_r(line, " ", &saveptr2);
		log_debug("- Destination: %s\n", tmpstr);
		// replace literal "default" route by IPV4 numbers-and-dots notation
		if (strncmp(tmpstr, "default", 7) == 0) {
			dest = 0;
			mask = 0;
		} else {
			int is_mask_set = 0;
			char *tmp_position;
			int dot_count = -1;

			if (index(tmpstr, '/') != NULL) {
				// 123.123.123.123/30 style
				// 123.123.123/24 style
				// 123.123/24 style

				// break CIDR up into address and mask part
				strcpy(tmp_ip_string, strtok_r(tmpstr, "/", &saveptr3));
				mask = strtol(saveptr3, NULL, 10);
				// convert from CIDR to ipv4 mask
				mask = 0xffffffff << (32-mask);

				is_mask_set = 1;
			} else if (inet_aton(tmpstr, &dstaddr)) {
				// 123.123.123.123 style
				// 123.123.123 style
				// 123.123 style

				strcpy(tmp_ip_string, tmpstr);
				is_mask_set = 0;
			}

			// Process Destination IP Expression
			tmp_position = tmp_ip_string;
			while (tmp_position != NULL) {
				++dot_count;
				tmp_position = index(++tmp_position, '.');
			}

			for (int i = dot_count; i < 3; i++)
				strcat(tmp_ip_string, ".0");

			if (inet_aton(tmp_ip_string, &dstaddr))
				dest = dstaddr.s_addr;

			if (!is_mask_set) {
				// convert from CIDR to ipv4 mask
				mask = 0xffffffff << (32-((dot_count + 1) * 8));
			}

		}
		log_debug("- Destination IP Hex: %x\n", dest);
		log_debug("- Destination Mask Hex: %x\n", mask);
		// "Gateway"
		gtw = 0;
		if (inet_aton(strtok_r(NULL, " ", &saveptr2), &dstaddr)) {
			gtw = dstaddr.s_addr;
			log_debug("- Gateway Mask Hex: %x\n", gtw);
		}
		// "Flags"
		tmpstr = strtok_r(NULL, " ", &saveptr2);
		flags = 0;
		// this is the reason for the 256 entries mentioned above
		for (pos = 0; pos < strlen(tmpstr); pos++)
			flags |= flag_table[(unsigned char)tmpstr[pos]];
		strtok_r(NULL, " ", &saveptr2); // "Refs"
		strtok_r(NULL, " ", &saveptr2); // "Use"
		iface = strtok_r(NULL, " ", &saveptr2); // "Netif"
		log_debug("- Interface: %s\n", iface);
		log_debug("\n");
#else
		unsigned short irtt;
		short metric;
		unsigned long mtu, window;

		iface = strtok_r(line, "\t", &saveptr2);
		dest = strtol(strtok_r(NULL, "\t", &saveptr2), NULL, 16);
		gtw = strtol(strtok_r(NULL, "\t", &saveptr2), NULL, 16);
		flags = strtol(strtok_r(NULL, "\t", &saveptr2), NULL, 16);
		strtok_r(NULL, "\t", &saveptr2); // "RefCnt"
		strtok_r(NULL, "\t", &saveptr2); // "Use"
		metric = strtol(strtok_r(NULL, "\t", &saveptr2), NULL, 16);
		mask = strtol(strtok_r(NULL, "\t", &saveptr2), NULL, 16);
		mtu = strtol(strtok_r(NULL, "\t", &saveptr2), NULL, 16);
		window = strtol(strtok_r(NULL, "\t", &saveptr2), NULL, 16);
		irtt = strtol(strtok_r(NULL, "\t", &saveptr2), NULL, 16);
#endif

		if (dest == route_dest(route).s_addr &&
		    mask == route_mask(route).s_addr) {
			// Requested route has been found
			route_gtw(route).s_addr = gtw;
			route->rt_flags = flags;
#ifndef __APPLE__
			// we do not have these values from Mac OS X netstat,
			// so stay with defaults denoted by values of 0
			route->rt_metric = metric;
			route->rt_mtu = mtu;
			route->rt_window = window;
			route->rt_irtt = irtt;
#endif
			strncpy(route_iface(route), iface,
			        ROUTE_IFACE_LEN - 1);
			return 0;
		}
		line = strtok_r(NULL, "\n", &saveptr1);
	}
	log_debug("Route not found.\n");

	return ERR_IPV4_NO_SUCH_ROUTE;
}

static int ipv4_set_route(struct rtentry *route)
{
#ifdef __APPLE__
	char cmd[SHOW_ROUTE_BUFFER_SIZE];

	strcpy(cmd, "route -n add -net ");
	strncat(cmd, inet_ntoa(route_dest(route)), 15);
	strcat(cmd, " -netmask ");
	strncat(cmd, inet_ntoa(route_mask(route)), 15);
	if (route->rt_flags & RTF_GATEWAY) {
		strcat(cmd, " ");
		strncat(cmd, inet_ntoa(route_gtw(route)), 15);
	} else {
		strcat(cmd, " -interface ");
		strcat(cmd, route_iface(route));
	}

	log_debug("%s\n", cmd);

	int res = system(cmd);
	if (res == -1)
		return ERR_IPV4_SEE_ERRNO;
#else
	log_debug("ip route add %s\n", ipv4_show_route(route));

	int sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);

	if (sockfd < 0)
		return ERR_IPV4_SEE_ERRNO;
	if (ioctl(sockfd, SIOCADDRT, route) == -1) {
		close(sockfd);
		return ERR_IPV4_SEE_ERRNO;
	}
	close(sockfd);
#endif

	return 0;
}

static int ipv4_del_route(struct rtentry *route)
{
#ifdef __APPLE__
	char cmd[SHOW_ROUTE_BUFFER_SIZE];

	strcpy(cmd, "route -n delete ");
	strncat(cmd, inet_ntoa(route_dest(route)), 15);
	strcat(cmd, " -netmask ");
	strncat(cmd, inet_ntoa(route_mask(route)), 15);

	log_debug("%s\n", cmd);

	int res = system(cmd);
	if (res == -1)
		return ERR_IPV4_SEE_ERRNO;
#else
	struct rtentry tmp;
	int sockfd;

	log_debug("ip route del %s\n", ipv4_show_route(route));

	// Copy route to a temp variable to clear some of its properties
	memcpy(&tmp, route, sizeof(tmp));
	tmp.rt_metric = 0;
	tmp.rt_mtu = 0;
	tmp.rt_window = 0;
	tmp.rt_irtt = 0;

	sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
	if (sockfd < 0)
		return ERR_IPV4_SEE_ERRNO;
	if (ioctl(sockfd, SIOCDELRT, &tmp) == -1) {
		close(sockfd);
		return ERR_IPV4_SEE_ERRNO;
	}
	close(sockfd);
#endif
	return 0;
}

int ipv4_protect_tunnel_route(struct tunnel *tunnel)
{
	struct rtentry *gtw_rt = &tunnel->ipv4.gtw_rt;
	struct rtentry *def_rt = &tunnel->ipv4.def_rt;
	int ret;

	route_init(def_rt);
	route_init(gtw_rt);

	// Back up default route
	route_dest(def_rt).s_addr = inet_addr("0.0.0.0");
	route_mask(def_rt).s_addr = inet_addr("0.0.0.0");

	ret = ipv4_get_route(def_rt);
	if (ret != 0) {
		log_warn("Could not get current default route (%s).\n",
		         err_ipv4_str(ret));
		log_warn("Protecting tunnel route has failed. "
		         "But this can be working except for some cases.\n");
		goto err_destroy;
	}


	// Set the default route as the route to the tunnel gateway
	char *iface = route_iface(gtw_rt);
	memcpy(gtw_rt, def_rt, sizeof(*gtw_rt));
	route_iface(gtw_rt) = iface;
	strncpy(route_iface(gtw_rt), route_iface(def_rt), ROUTE_IFACE_LEN - 1);
	route_dest(gtw_rt).s_addr = tunnel->config->gateway_ip.s_addr;
	route_mask(gtw_rt).s_addr = inet_addr("255.255.255.255");
	gtw_rt->rt_flags |= RTF_HOST;
	gtw_rt->rt_metric = 0;

	tunnel->ipv4.route_to_vpn_is_added = 1;
	log_debug("Setting route to vpn server...\n");
	ret = ipv4_set_route(gtw_rt);
	if (ret == ERR_IPV4_SEE_ERRNO && errno == EEXIST) {
		log_warn("Route to vpn server exists already.\n");

		tunnel->ipv4.route_to_vpn_is_added = 0;
	} else if (ret != 0)
		log_warn("Could not set route to vpn server (%s).\n",
		         err_ipv4_str(ret));

	return 0;

err_destroy:
	route_destroy(def_rt);
	tunnel->ipv4.route_to_vpn_is_added = 0;
	return ret;
}

int ipv4_add_split_vpn_route(struct tunnel *tunnel, char *dest, char *mask,
                             char *gateway)
{
	struct rtentry *route;
	char env_var[24];

	if (tunnel->ipv4.split_routes == MAX_SPLIT_ROUTES)
		return ERR_IPV4_NO_MEM;
	if ((tunnel->ipv4.split_rt == NULL)
	    || ((tunnel->ipv4.split_routes % STEP_SPLIT_ROUTES) == 0)) {
		void *new_ptr
		        = realloc(
		                  tunnel->ipv4.split_rt,
		                  (size_t) (tunnel->ipv4.split_routes + STEP_SPLIT_ROUTES)
		                  * sizeof(*(tunnel->ipv4.split_rt))
		          );
		if (new_ptr == NULL)
			return ERR_IPV4_NO_MEM;
		tunnel->ipv4.split_rt = new_ptr;
	}

	sprintf(env_var, "VPN_ROUTE_DEST_%d", tunnel->ipv4.split_routes);
	setenv(env_var, dest, 0);
	sprintf(env_var, "VPN_ROUTE_MASK_%d", tunnel->ipv4.split_routes);
	setenv(env_var, mask, 0);
	if (gateway != NULL) {
		sprintf(env_var, "VPN_ROUTE_GATEWAY_%d",
		        tunnel->ipv4.split_routes);
		setenv(env_var, gateway, 0);
	}

	route = &tunnel->ipv4.split_rt[tunnel->ipv4.split_routes++];

	route_init(route);
	route_dest(route).s_addr = inet_addr(dest);
	route_mask(route).s_addr = inet_addr(mask);
	if (gateway != NULL) {
		route_gtw(route).s_addr = inet_addr(gateway);
		route->rt_flags |= RTF_GATEWAY;
	} else {
		strncpy(route_iface(route), tunnel->ppp_iface, ROUTE_IFACE_LEN - 1);
	}

	return 0;
}

static int ipv4_set_split_routes(struct tunnel *tunnel)
{
	int i;

	for (i = 0; i < tunnel->ipv4.split_routes; i++) {
		struct rtentry *route;
		int ret;
		route = &tunnel->ipv4.split_rt[i];
		strncpy(route_iface(route), tunnel->ppp_iface,
		        ROUTE_IFACE_LEN - 1);
		if (route_gtw(route).s_addr == 0)
			route_gtw(route).s_addr = tunnel->ipv4.ip_addr.s_addr;
		route->rt_flags |= RTF_GATEWAY;
		ret = ipv4_set_route(route);
		if (ret == ERR_IPV4_SEE_ERRNO && errno == EEXIST)
			log_warn("Route to gateway exists already.\n");
		else if (ret != 0)
			log_warn("Could not set route to tunnel gateway (%s).\n",
			         err_ipv4_str(ret));
	}
	return 0;
}

static int ipv4_set_default_routes(struct tunnel *tunnel)
{
	int ret;
	struct rtentry *def_rt = &tunnel->ipv4.def_rt;
	struct rtentry *ppp_rt = &tunnel->ipv4.ppp_rt;
	struct vpn_config *cfg = tunnel->config;

	route_init(ppp_rt);

	if (cfg->half_internet_routes == 0) {
		// Delete the current default route
		log_debug("Deleting the current default route...\n");
		ret = ipv4_del_route(def_rt);
		if (ret != 0)
			log_warn("Could not delete the current default route (%s).\n",
			         err_ipv4_str(ret));

		// Set the new default route
		// ip route add to 0/0 dev ppp0
		route_dest(ppp_rt).s_addr = inet_addr("0.0.0.0");
		route_mask(ppp_rt).s_addr = inet_addr("0.0.0.0");
		route_gtw(ppp_rt).s_addr = inet_addr("0.0.0.0");
		log_debug("Setting new default route...\n");

		strncpy(route_iface(ppp_rt), tunnel->ppp_iface, ROUTE_IFACE_LEN - 1);

		ret = ipv4_set_route(ppp_rt);
		if (ret == ERR_IPV4_SEE_ERRNO && errno == EEXIST) {
			log_warn("Default route exists already.\n");
		} else if (ret != 0) {
			log_warn("Could not set the new default route (%s).\n",
			         err_ipv4_str(ret));
		}

	} else {
		// Emulate default routes as two "half internet" routes
		// This allows for e.g. DHCP renewing default routes without
		// breaking the tunnel
		log_debug("Setting new half-internet routes...\n");
		route_dest(ppp_rt).s_addr = inet_addr("0.0.0.0");
		route_mask(ppp_rt).s_addr = inet_addr("128.0.0.0");

		strncpy(route_iface(ppp_rt), tunnel->ppp_iface, ROUTE_IFACE_LEN - 1);

		ret = ipv4_set_route(ppp_rt);
		if (ret == ERR_IPV4_SEE_ERRNO && errno == EEXIST) {
			log_warn("0.0.0.0/1 route exists already.\n");
		} else if (ret != 0) {
			log_warn("Could not set the new 0.0.0.0/1 route (%s).\n",
			         err_ipv4_str(ret));
		}

		route_dest(ppp_rt).s_addr = inet_addr("128.0.0.0");
		ret = ipv4_set_route(ppp_rt);
		if (ret == ERR_IPV4_SEE_ERRNO && errno == EEXIST) {
			log_warn("128.0.0.0/1 route exists already.\n");
		} else if (ret != 0) {
			log_warn("Could not set the new 128.0.0.0/1 route (%s).\n",
			         err_ipv4_str(ret));
		}
	}

	return 0;
}

int ipv4_set_tunnel_routes(struct tunnel *tunnel)
{
	int ret = ipv4_protect_tunnel_route(tunnel);

	if (tunnel->ipv4.split_routes)
		// try even if ipv4_protect_tunnel_route has failed
		return ipv4_set_split_routes(tunnel);
	else if (ret == 0) {
		return ipv4_set_default_routes(tunnel);
	} else {
		return ret;
	}
}

int ipv4_restore_routes(struct tunnel *tunnel)
{
	struct rtentry *def_rt = &tunnel->ipv4.def_rt;
	struct rtentry *gtw_rt = &tunnel->ipv4.gtw_rt;
	struct rtentry *ppp_rt = &tunnel->ipv4.ppp_rt;
	struct vpn_config *cfg = tunnel->config;

	if (tunnel->ipv4.route_to_vpn_is_added) {
		int ret;
		ret = ipv4_del_route(gtw_rt);
		if (ret != 0)
			log_warn("Could not delete route to vpn server (%s).\n",
			         err_ipv4_str(ret));
		if ((cfg->half_internet_routes == 0) &&
		    (tunnel->ipv4.split_routes == 0)) {
			ret = ipv4_del_route(ppp_rt);
			if (ret != 0)
				log_warn("Could not delete route through tunnel (%s).\n",
				         err_ipv4_str(ret));

			// Restore the default route. It seems not to be
			// automatically restored on all linux distributions
			ret = ipv4_set_route(def_rt);
			if (ret != 0) {
				log_warn("Could not restore default route (%s). "
				         "Already restored?\n",
				         err_ipv4_str(ret));
			}

		}
	} else {
		log_debug("Route to vpn server was not added\n");
	}
	route_destroy(ppp_rt);
	route_destroy(def_rt);
	route_destroy(gtw_rt);

	return 0;
}

int ipv4_add_nameservers_to_resolv_conf(struct tunnel *tunnel)
{
	int ret = -1;
	FILE *file;
	struct stat stat;
	char ns1[28], ns2[28]; // 11 + 15 + 1 + 1
	char *buffer, *line;

	tunnel->ipv4.ns_are_new = 1;

	if (tunnel->ipv4.ns1_addr.s_addr == 0)
		return 1;

	file = fopen("/etc/resolv.conf", "r+");
	if (file == NULL) {
		log_warn("Could not open /etc/resolv.conf (%s).\n",
		         strerror(errno));
		return 1;
	}

	if (fstat(fileno(file), &stat) == -1) {
		log_warn("Could not stat /etc/resolv.conf (%s).\n",
		         strerror(errno));
		goto err_close;
	}

	if (stat.st_size == 0) {
		log_warn("Could not read /etc/resolv.conf (%s).\n",
		         "Empty file");
		goto err_close;
	}

	buffer = malloc(stat.st_size + 1);
	if (buffer == NULL) {
		log_warn("Could not read /etc/resolv.conf (%s).\n",
		         strerror(errno));
		goto err_close;
	}

	// Copy all file contents at once
	if (fread(buffer, stat.st_size, 1, file) != 1) {
		log_warn("Could not read /etc/resolv.conf.\n");
		goto err_free;
	}

	buffer[stat.st_size] = '\0';

	strcpy(ns1, "nameserver ");
	strncat(ns1, inet_ntoa(tunnel->ipv4.ns1_addr), 15);
	if (tunnel->ipv4.ns2_addr.s_addr != 0) {
		strcpy(ns2, "nameserver ");
		strncat(ns2, inet_ntoa(tunnel->ipv4.ns2_addr), 15);
	} else {
		ns2[0] = '\0';
	}

	for (line = strtok(buffer, "\n"); line != NULL;
	     line = strtok(NULL, "\n")) {
		if (strcmp(line, ns1) == 0) {
			tunnel->ipv4.ns_are_new = 0;
			log_debug("Nameservers already present in "
			          "/etc/resolv.conf.\n");
			ret = 0;
			goto err_free;
		}
	}

	log_debug("Adding \"%s\" and \"%s\" to /etc/resolv.conf.\n", ns1, ns2);

	rewind(file);
	if (fread(buffer, stat.st_size, 1, file) != 1) {
		log_warn("Could not read /etc/resolv.conf.\n");
		goto err_free;
	}

	buffer[stat.st_size] = '\0';

	rewind(file);
	strcat(ns1, "\n");
	fputs(ns1, file);
	if (tunnel->ipv4.ns2_addr.s_addr != 0) {
		strcat(ns2, "\n");
		fputs(ns2, file);
	}
	fwrite(buffer, stat.st_size, 1, file);

	ret = 0;

err_free:
	free(buffer);
err_close:
	fclose(file);

	return ret;
}

int ipv4_del_nameservers_from_resolv_conf(struct tunnel *tunnel)
{
	int ret = -1;
	FILE *file;
	struct stat stat;
	char ns1[27], ns2[27]; // 11 + 15 + 1
	char *buffer, *line;

	// If nameservers were already there before setting up tunnel,
	// don't delete them from /etc/resolv.conf
	if (!tunnel->ipv4.ns_are_new)
		return 0;

	if (tunnel->ipv4.ns1_addr.s_addr == 0)
		return 1;

	file = fopen("/etc/resolv.conf", "r+");
	if (file == NULL) {
		log_warn("Could not open /etc/resolv.conf (%s).\n",
		         strerror(errno));
		return 1;
	}

	if (fstat(fileno(file), &stat) == -1) {
		log_warn("Could not stat /etc/resolv.conf (%s).\n",
		         strerror(errno));
		goto err_close;
	}

	buffer = malloc(stat.st_size + 1);
	if (buffer == NULL) {
		log_warn("Could not read /etc/resolv.conf (%s).\n",
		         strerror(errno));
		goto err_close;
	}

	// Copy all file contents at once
	if (fread(buffer, stat.st_size, 1, file) != 1) {
		log_warn("Could not read /etc/resolv.conf.\n");
		goto err_free;
	}

	buffer[stat.st_size] = '\0';

	strcpy(ns1, "nameserver ");
	strncat(ns1, inet_ntoa(tunnel->ipv4.ns1_addr), 15);
	strcpy(ns2, "nameserver ");
	strncat(ns2, inet_ntoa(tunnel->ipv4.ns2_addr), 15);

	file = freopen("/etc/resolv.conf", "w", file);
	if (file == NULL) {
		log_warn("Could not reopen /etc/resolv.conf (%s).\n",
		         strerror(errno));
		goto err_free;
	}

	for (line = strtok(buffer, "\n"); line != NULL; line = strtok(NULL, "\n")) {
		if (strcmp(line, ns1) == 0) {
			log_debug("Deleting \"%s\" from /etc/resolv.conf.\n", ns1);
		} else if (strcmp(line, ns2) == 0) {
			log_debug("Deleting \"%s\" from /etc/resolv.conf.\n", ns1);
		} else {
			fputs(line, file);
			fputs("\n", file);
		}
	}

	ret = 0;

err_free:
	free(buffer);
err_close:
	if (file)
		fclose(file);

	return ret;
}
