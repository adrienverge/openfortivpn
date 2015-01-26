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

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "ipv4.h"
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
char *ipv4_show_route(struct rtentry *route)
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

/*
 * Takes a struct rtentry pointer with dest and mask set, and fills gtw and iface.
 */
int ipv4_get_route(struct rtentry *route)
{
	int ret = 1;
	size_t size;
	int fd;
	char buffer[0x1000];
	char *start, *line;
	char *saveptr1 = NULL, *saveptr2 = NULL;

	// Cannot stat, mmap not lseek this special /proc file
	fd = open("/proc/net/route", O_RDONLY);
	if (fd == -1) {
		log_error("open: %s\n", strerror(errno));
		return 1;
	}

	if ((size = read(fd, buffer, 0x1000 - 1)) == -1) {
		log_error("read: %s\n", strerror(errno));
		return 1;
	} else if (size == 0) {
		log_error("/proc/net/route is empty.\n");
		goto err_close;
	}
	buffer[size] = '\0';

	// Skip first line
	start = index(buffer, '\n');
	if (start == NULL) {
		log_error("/proc/net/route is malformed.\n");
		goto err_close;
	}
	start++;

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
			strncpy(route_iface(route), iface, ROUTE_IFACE_LEN - 1);
			ret = 0;
			break;
		}
		line = strtok_r(NULL, "\n", &saveptr1);
	}

	if (ret != 0)
		log_error("Route not found: %s\n", ipv4_show_route(route));

err_close:
	close(fd);

	return ret;
}

int ipv4_set_route(struct rtentry *route)
{
	int sockfd;

	log_debug("ip route add %s\n", ipv4_show_route(route));

	if ((sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP)) < 0) {
		log_error("socket: %s\n", strerror(errno));
		return 1;
	}
	if (ioctl(sockfd, SIOCADDRT, route) == -1) {
		log_error("ioctl(SIOCADDRT): %s\n", strerror(errno));
		return 1;
	}
	close(sockfd);

	return 0;
}

int ipv4_del_route(struct rtentry *route)
{
	struct rtentry tmp;
	int sockfd;

	log_debug("ip route del %s\n", ipv4_show_route(route));

	// Copy route to a temp variable to clear some of its properties
	memcpy(&tmp, route, sizeof(tmp));
	tmp.rt_metric = 0;
	tmp.rt_mtu = 0;
	tmp.rt_window = 0;
	tmp.rt_irtt = 0;

	if ((sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP)) < 0) {
		log_error("socket: %s\n", strerror(errno));
		return 1;
	}
	if (ioctl(sockfd, SIOCDELRT, &tmp) == -1) {
		log_error("ioctl(SIOCDELRT): %s\n", strerror(errno));
		return 1;
	}
	close(sockfd);

	return 0;
}

int ipv4_set_tunnel_routes(struct tunnel *tunnel)
{
	struct rtentry *def_rt = &tunnel->default_route;
	struct rtentry *gtw_rt = &tunnel->gtw_route;
	struct rtentry *ppp_rt = &tunnel->ppp_route;

	log_info("Setting new routes...\n");

	// Back up default route
	route_init(def_rt);
	route_init(ppp_rt);

	route_dest(def_rt).s_addr = inet_addr("0.0.0.0");
	route_mask(def_rt).s_addr = inet_addr("0.0.0.0");

	if (ipv4_get_route(def_rt))
		goto err_destroy;

	// Set the default route as the route to the tunnel gateway
	memcpy(gtw_rt, def_rt, sizeof(*gtw_rt));
	route_dest(gtw_rt).s_addr = tunnel->config->gateway_ip.s_addr;
	route_mask(gtw_rt).s_addr = inet_addr("255.255.255.255");
	gtw_rt->rt_flags |= RTF_GATEWAY;
	gtw_rt->rt_metric = 0;

	log_debug("Setting route to tunnel gateway...\n");
	if (ipv4_set_route(gtw_rt))
		log_warn("Could not set route to tunnel gateway.\n");
		//goto err_destroy;

	// Delete the current default route
	log_debug("Deleting the current default route...\n");
	if (ipv4_del_route(def_rt))
		log_warn("Could not delete the current default route.\n");
		//goto err_del_gtw_rt;

	// Set the new default route
	// ip route add to 0/0 dev ppp0
	route_dest(ppp_rt).s_addr = inet_addr("0.0.0.0");
	route_mask(ppp_rt).s_addr = inet_addr("0.0.0.0");
	route_gtw(ppp_rt).s_addr = inet_addr("0.0.0.0");
	strncpy(route_iface(ppp_rt), tunnel->ppp_iface, ROUTE_IFACE_LEN - 1);

	log_debug("Setting new default route...\n");
	if (ipv4_set_route(ppp_rt))
		log_warn("Could not set the new default route.\n");
		//goto err_reset_def_rt;

	return 0;

//err_reset_def_rt:
//	ipv4_set_route(def_rt);
//err_del_gtw_rt:
//	ipv4_del_route(gtw_rt);
err_destroy:
	route_destroy(ppp_rt);
	route_destroy(def_rt);

	return 1;
}

int ipv4_restore_routes(struct tunnel *tunnel)
{
	struct rtentry *def_rt = &tunnel->default_route;
	struct rtentry *gtw_rt = &tunnel->gtw_route;
	struct rtentry *ppp_rt = &tunnel->ppp_route;

	log_info("Restoring routes...\n");

	ipv4_del_route(ppp_rt);
	// Apparently the default route is automaticallly restored
	//ipv4_set_route(def_rt);
	ipv4_del_route(gtw_rt);

	route_destroy(ppp_rt);
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

	if (tunnel->nameserver1.s_addr == 0)
		return 1;

	file = fopen("/etc/resolv.conf", "r+");
	if (file == NULL) {
		log_error("fopen: %s\n", strerror(errno));
		return 1;
	}

	if (fstat(fileno(file), &stat) == -1) {
		log_error("fstat: %s\n", strerror(errno));
		goto err_close;
	}

	buffer = malloc(stat.st_size);
	if (buffer == NULL) {
		log_error("malloc failed.\n");
		goto err_close;
	}

	// Copy all file contents at once
	if (fread(buffer, stat.st_size, 1, file) != 1) {
		log_error("fread failed\n");
		goto err_free;
	}

	strcpy(ns1, "nameserver ");
	strncat(ns1, inet_ntoa(tunnel->nameserver1), 15);
	if (tunnel->nameserver2.s_addr != 0) {
		strcpy(ns2, "nameserver ");
		strncat(ns2, inet_ntoa(tunnel->nameserver2), 15);
	} else {
		ns2[0] = '\0';
	}

	for (line = strtok(buffer, "\n"); line != NULL; line = strtok(NULL, "\n")) {
		if (strcmp(line, ns1) == 0) {
			log_warn("Nameserver already present in /etc/resolv.conf.\n");
			ret = 0;
			goto err_free;
		}
	}

	log_debug("Adding \"%s\" and \"%s\" to /etc/resolv.conf.\n", ns1, ns2);

	rewind(file);
	if (fread(buffer, stat.st_size, 1, file) != 1) {
		log_error("fread failed\n");
		goto err_free;
	}

	rewind(file);
	strcat(ns1, "\n");
	fputs(ns1, file);
	if (tunnel->nameserver2.s_addr != 0) {
		strcat(ns2, "\n");
		fputs(ns2, file);
	}
	fputs(buffer, file);

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

	if (tunnel->nameserver1.s_addr == 0)
		return 1;

	file = fopen("/etc/resolv.conf", "r+");
	if (file == NULL) {
		log_error("fopen: %s\n", strerror(errno));
		return 1;
	}

	if (fstat(fileno(file), &stat) == -1) {
		log_error("fstat: %s\n", strerror(errno));
		goto err_close;
	}

	buffer = malloc(stat.st_size);
	if (buffer == NULL) {
		log_error("malloc failed.\n");
		goto err_close;
	}

	// Copy all file contents at once
	if (fread(buffer, stat.st_size, 1, file) != 1) {
		log_error("fread failed\n");
		goto err_free;
	}

	strcpy(ns1, "nameserver ");
	strncat(ns1, inet_ntoa(tunnel->nameserver1), 15);
	strcpy(ns2, "nameserver ");
	strncat(ns2, inet_ntoa(tunnel->nameserver2), 15);

	fclose(file);
	file = fopen("/etc/resolv.conf", "w");
	if (file == NULL) {
		log_error("fopen: %s\n", strerror(errno));
		free(buffer);
		return 1;
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
