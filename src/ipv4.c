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

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>

#include "log.h"
#include "tunnel.h"

#define SHOW_ROUTE_BUFFER_SIZE 128

static char show_route_buffer[SHOW_ROUTE_BUFFER_SIZE];

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

static inline int route_destroy(struct rtentry *route)
{
	free(route_iface(route));
	return 0;
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
	int fd;
	char buffer[0x1000];
	char *start, *line;
	char *saveptr1 = NULL, *saveptr2 = NULL;

	log_debug("ip route show %s\n", ipv4_show_route(route));

	// Cannot stat, mmap not lseek this special /proc file
	fd = open("/proc/net/route", O_RDONLY);
	if (fd == -1) {
		return ERR_IPV4_SEE_ERRNO;
	}

	if ((size = read(fd, buffer, 0x1000 - 1)) == -1) {
		close(fd);
		return ERR_IPV4_SEE_ERRNO;
	}
	close(fd);
	if (size == 0) {
		log_debug("/proc/net/route is empty.\n");
		return ERR_IPV4_PROC_NET_ROUTE;
	}
	buffer[size] = '\0';

	// Skip first line
	start = index(buffer, '\n');
	if (start == NULL) {
		log_debug("/proc/net/route is malformed.\n");
		return ERR_IPV4_PROC_NET_ROUTE;
	}
	start++;

	// Look for the route
	line = strtok_r(start, "\n", &saveptr1);
	while (line != NULL) {
		char *iface;
		uint32_t dest, mask, gtw;
		unsigned short flags, irtt;
		short metric;
		unsigned long mtu, window;
		iface = strtok_r(line, "\t", &saveptr2);
		dest = strtol(strtok_r(NULL, "\t", &saveptr2), NULL, 16);
		gtw = strtol(strtok_r(NULL, "\t", &saveptr2), NULL, 16);
		flags = strtol(strtok_r(NULL, "\t", &saveptr2), NULL, 16);
		strtok_r(NULL, "\t", &saveptr2);
		strtok_r(NULL, "\t", &saveptr2);
		metric = strtol(strtok_r(NULL, "\t", &saveptr2), NULL, 16);
		mask = strtol(strtok_r(NULL, "\t", &saveptr2), NULL, 16);
		mtu = strtol(strtok_r(NULL, "\t", &saveptr2), NULL, 16);
		window = strtol(strtok_r(NULL, "\t", &saveptr2), NULL, 16);
		irtt = strtol(strtok_r(NULL, "\t", &saveptr2), NULL, 16);

		if (dest == route_dest(route).s_addr &&
		    mask == route_mask(route).s_addr) {
			// Requested route has been found
			route_gtw(route).s_addr = gtw;
			route->rt_flags = flags;
			route->rt_metric = metric;
			route->rt_mtu = mtu;
			route->rt_window = window;
			route->rt_irtt = irtt;
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
#ifndef __APPLE__
	int sockfd;

	log_debug("ip route add %s\n", ipv4_show_route(route));

	if ((sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP)) < 0)
		return ERR_IPV4_SEE_ERRNO;
	if (ioctl(sockfd, SIOCADDRT, route) == -1) {
		close(sockfd);
		return ERR_IPV4_SEE_ERRNO;
	}
	close(sockfd);
#else
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
	if (res == -1) {
		return ERR_IPV4_SEE_ERRNO;
	}
#endif

	return 0;
}

static int ipv4_del_route(struct rtentry *route)
{
#ifndef __APPLE__
	struct rtentry tmp;
	int sockfd;

	log_debug("ip route del %s\n", ipv4_show_route(route));

	// Copy route to a temp variable to clear some of its properties
	memcpy(&tmp, route, sizeof(tmp));
	tmp.rt_metric = 0;
	tmp.rt_mtu = 0;
	tmp.rt_window = 0;
	tmp.rt_irtt = 0;

	if ((sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP)) < 0)
		return ERR_IPV4_SEE_ERRNO;
	if (ioctl(sockfd, SIOCDELRT, &tmp) == -1) {
		close(sockfd);
		return ERR_IPV4_SEE_ERRNO;
	}
	close(sockfd);
#else
	char cmd[SHOW_ROUTE_BUFFER_SIZE];

	strcpy(cmd, "route -n delete ");
	strncat(cmd, inet_ntoa(route_dest(route)), 15);
	strcat(cmd, " -netmask ");
	strncat(cmd, inet_ntoa(route_mask(route)), 15);

	log_debug("%s\n", cmd);

	int res = system(cmd);
	if (res == -1) {
		return ERR_IPV4_SEE_ERRNO;
	}
#endif
	return 0;
}

int ipv4_add_split_vpn_route(struct tunnel *tunnel, char *dest, char *mask,
                             char *gateway)
{
	struct rtentry *route;
	char env_var[21];

	if (tunnel->ipv4.split_routes == MAX_SPLIT_ROUTES)
		return ERR_IPV4_NO_MEM;

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
	struct rtentry *route;
	struct rtentry *gtw_rt = &tunnel->ipv4.gtw_rt;
	struct rtentry *def_rt = &tunnel->ipv4.def_rt;
	int ret;

	route_init(def_rt);

	// Back up default route
	route_dest(def_rt).s_addr = inet_addr("0.0.0.0");
	route_mask(def_rt).s_addr = inet_addr("0.0.0.0");

	ret = ipv4_get_route(def_rt);
	if (ret != 0) {
		log_warn("Could not get current default route (%s).\n",
		         err_ipv4_str(ret));
		goto err_destroy;
	}


	// Set the default route as the route to the tunnel gateway
	memcpy(gtw_rt, def_rt, sizeof(*gtw_rt));
	route_dest(gtw_rt).s_addr = tunnel->config->gateway_ip.s_addr;
	route_mask(gtw_rt).s_addr = inet_addr("255.255.255.255");
	gtw_rt->rt_flags |= RTF_HOST;
	gtw_rt->rt_metric = 0;

	log_debug("Setting route to tunnel gateway...\n");
	ret = ipv4_set_route(gtw_rt);
	if (ret == ERR_IPV4_SEE_ERRNO && errno == EEXIST)
		log_warn("Route to gateway exists already.\n");
	else if (ret != 0)
		log_warn("Could not set route to tunnel gateway (%s).\n",
		         err_ipv4_str(ret));

	for (i = 0; i < tunnel->ipv4.split_routes; i++) {
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

err_destroy:
	route_destroy(def_rt);

	return ret;
}

static int ipv4_set_default_routes(struct tunnel *tunnel)
{
	int ret;
	struct rtentry *def_rt = &tunnel->ipv4.def_rt;
	struct rtentry *gtw_rt = &tunnel->ipv4.gtw_rt;
	struct rtentry *ppp_rt = &tunnel->ipv4.ppp_rt;

	route_init(def_rt);
	route_init(ppp_rt);

	// Back up default route
	route_dest(def_rt).s_addr = inet_addr("0.0.0.0");
	route_mask(def_rt).s_addr = inet_addr("0.0.0.0");

	ret = ipv4_get_route(def_rt);
	if (ret != 0) {
		log_warn("Could not get current default route (%s).\n",
		         err_ipv4_str(ret));
		goto err_destroy;
	}

	// Set the default route as the route to the tunnel gateway
	memcpy(gtw_rt, def_rt, sizeof(*gtw_rt));
	route_dest(gtw_rt).s_addr = tunnel->config->gateway_ip.s_addr;
	route_mask(gtw_rt).s_addr = inet_addr("255.255.255.255");
	gtw_rt->rt_flags |= RTF_HOST;
	gtw_rt->rt_metric = 0;

	log_debug("Setting route to tunnel gateway...\n");
	ret = ipv4_set_route(gtw_rt);
	if (ret == ERR_IPV4_SEE_ERRNO && errno == EEXIST)
		log_warn("Route to gateway exists already.\n");
	else if (ret != 0)
		log_warn("Could not set route to tunnel gateway (%s).\n",
		         err_ipv4_str(ret));

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
	strncpy(route_iface(ppp_rt), tunnel->ppp_iface, ROUTE_IFACE_LEN - 1);

	log_debug("Setting new default route...\n");
	ret = ipv4_set_route(ppp_rt);
	if (ret == ERR_IPV4_SEE_ERRNO && errno == EEXIST)
		log_warn("Default route exists already.\n");
	else if (ret != 0)
		log_warn("Could not set the new default route (%s).\n",
		         err_ipv4_str(ret));

	return 0;

err_destroy:
	route_destroy(ppp_rt);
	route_destroy(def_rt);

	return ret;
}

int ipv4_set_tunnel_routes(struct tunnel *tunnel)
{
	if (tunnel->ipv4.split_routes)
		return ipv4_set_split_routes (tunnel);
	else
		return ipv4_set_default_routes (tunnel);
}

int ipv4_restore_routes(struct tunnel *tunnel)
{
	int ret;
	struct rtentry *def_rt = &tunnel->ipv4.def_rt;
	struct rtentry *gtw_rt = &tunnel->ipv4.gtw_rt;
	struct rtentry *ppp_rt = &tunnel->ipv4.ppp_rt;

	ret = ipv4_del_route(gtw_rt);
	if (ret != 0)
		log_warn("Could not delete route to gateway (%s).\n",
		         err_ipv4_str(ret));

	if (tunnel->ipv4.split_routes)
		goto out;

	ret = ipv4_del_route(ppp_rt);
	if (ret != 0)
		log_warn("Could not delete route through tunnel (%s).\n",
		         err_ipv4_str(ret));

	// Restore the default route
	// It seems to not be automatically restored on all linux distributions
	ret = ipv4_set_route(def_rt);
	if (ret != 0)
		log_warn("Could not restore default route (%s). Already restored?\n",
		         err_ipv4_str(ret));

	route_destroy(ppp_rt);
out:
	route_destroy(def_rt);

	return 0;
}

int ipv4_add_nameservers_to_resolv_conf(struct tunnel *tunnel)
{
	int ret = -1;
	FILE *file;
	struct stat stat;
	char ns1[27], ns2[27]; // 11 + 15 + 1
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
	// TODO
	//if (stat.st_size == 0)

	buffer = malloc(stat.st_size);
	if (buffer == NULL) {
		log_warn("Could not read /etc/resolv.conf (%s).\n",
		         "Not enough memory");
		goto err_close;
	}

	// Copy all file contents at once
	if (fread(buffer, stat.st_size, 1, file) != 1) {
		log_warn("Could not read /etc/resolv.conf.\n");
		goto err_free;
	}

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

	buffer = malloc(stat.st_size);
	if (buffer == NULL) {
		log_warn("Could not read /etc/resolv.conf (%s).\n",
		         "Not enough memory");
		goto err_close;
	}

	// Copy all file contents at once
	if (fread(buffer, stat.st_size, 1, file) != 1) {
		log_warn("Could not read /etc/resolv.conf.\n");
		goto err_free;
	}

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
	fclose(file);

	return ret;
}
