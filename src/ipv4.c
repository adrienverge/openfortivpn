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

#include "ipv4.h"
#include "tunnel.h"
#include "config.h"
#include "log.h"
#include "xml.h"

#include <unistd.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/stat.h>

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>

#define IPV4_GET_ROUTE_BUFFER_CHUNK_SIZE 65536
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
	if (route_iface(route) != NULL) {
		strcat(show_route_buffer, " dev ");
		strncat(show_route_buffer, route_iface(route),
		        SHOW_ROUTE_BUFFER_SIZE - strlen(show_route_buffer) - 1);
	}

	return show_route_buffer;
}

static inline int route_init(struct rtentry *route)
{
	memset(route, 0, sizeof(*route));

	cast_addr(&(route)->rt_dst)->sin_family = AF_INET;
	cast_addr(&(route)->rt_genmask)->sin_family = AF_INET;
	cast_addr(&(route)->rt_gateway)->sin_family = AF_INET;

	return 0;
}

static inline void route_destroy(struct rtentry *route)
{
	free(route_iface(route));
	route_iface(route) = NULL;
}

/*
 * Finds system IP route to a destination.
 *
 * The passed route must have dest and mask set. If the route is found,
 * the function searches for a match in the routing table and returns
 * that one. Note that dest and mask contain the network address and
 * the mask of the corresponding routing table entry after calling.
 * After calling ipv4_get_route it might be necessary to set dest
 * and mask again to the desired values for further processing.
 */
static int ipv4_get_route(struct rtentry *route)
{
	size_t buffer_size = IPV4_GET_ROUTE_BUFFER_CHUNK_SIZE;
	char *buffer;
	char *realloc_buffer;
	int err = 0;
	char *start, *line;
	char *saveptr1 = NULL, *saveptr2 = NULL;
	uint32_t rtdest, rtmask, rtgtw;
	int rtfound = 0;

	/*
	 * initialize the buffer with zeroes, aiming to address the
	 * coverity issue "TAINTED_SCALAR passed to a tainted sink"
	 *
	 * Later on, the routing table is read into this buffer using
	 * read() and therefore the content of the buffer is considered
	 * tainted. strtok_r internally uses it in a loop boundary.
	 * The theoretical problem is that the loop could iterate forever,
	 * if the buffer contains a huge string which doesn't contain
	 * the token character, which we are parsing for.
	 *
	 * We can declare this as a false positive, because
	 * - the routing table is to some extent trusted input,
	 * - it's not that large,
	 * - and the loop in strtok_r increments the pointer in each
	 *   iteration until it reaches the area where we have ensured
	 *   that there is a delimiting '\0' character by proper
	 *   initialization. We ensure this also when growing the buffer.
	 */
	buffer = calloc(1, buffer_size);
	if (!buffer) {
		err = ERR_IPV4_SEE_ERRNO;
		goto end;
	}

	log_debug("ip route show %s\n", ipv4_show_route(route));

	// store what we are looking for
	rtdest = route_dest(route).s_addr;
	rtmask = route_mask(route).s_addr;
	rtgtw = route_gtw(route).s_addr;

	// initialize the output record
	route_dest(route).s_addr = inet_addr("0.0.0.0");
	route_mask(route).s_addr = inet_addr("0.0.0.0");
	route_gtw(route).s_addr = inet_addr("0.0.0.0");

#if HAVE_PROC_NET_ROUTE
	/* this is not present on Mac OS X and FreeBSD */
	int fd;
	uint32_t total_bytes_read = 0;

	// Cannot stat, mmap not lseek this special /proc file
	fd = open("/proc/net/route", O_RDONLY);
	if (fd == -1) {
		err = ERR_IPV4_SEE_ERRNO;
		goto end;
	}

	int bytes_read;

	while ((bytes_read = read(fd, buffer + total_bytes_read,
	                          buffer_size - total_bytes_read - 1)) > 0) {
		total_bytes_read += bytes_read;

		if ((buffer_size - total_bytes_read) < 1) {
			buffer_size += IPV4_GET_ROUTE_BUFFER_CHUNK_SIZE;

			realloc_buffer = realloc(buffer, buffer_size);
			if (realloc_buffer) {
				buffer = realloc_buffer;
			} else {
				err = ERR_IPV4_SEE_ERRNO;
				goto cleanup;
			}
			buffer[buffer_size-1] = '\0';
		}
	}

cleanup:
	if (close(fd))
		log_warn("Could not close /proc/net/route (%s).\n", strerror(errno));
	if (err)
		goto end;

	if (bytes_read < 0) {
		err = ERR_IPV4_SEE_ERRNO;
		goto end;
	}

#else
	FILE *fp;
	uint32_t total_bytes_read = 0;

	char *saveptr3 = NULL;
	int have_ref = 0;
	int have_use = 0;

	static const char netstat_path[] = NETSTAT_PATH;

	if (access(netstat_path, F_OK) != 0) {
		log_error("%s: %s.\n", netstat_path, strerror(errno));
		return 1;
	}
	log_debug("netstat_path: %s\n", netstat_path);

	// Open the command for reading
	fp = popen(NETSTAT_PATH " -f inet -rn", "r");
	if (fp == NULL) {
		err = ERR_IPV4_SEE_ERRNO;
		goto end;
	}

	line = buffer;
	// Read the output a line at a time
	while (fgets(line, buffer_size - total_bytes_read - 1, fp) != NULL) {
		uint32_t bytes_read = strlen(line);

		total_bytes_read += bytes_read;

		if (bytes_read > 0 && line[bytes_read - 1] != '\n') {
			buffer_size += IPV4_GET_ROUTE_BUFFER_CHUNK_SIZE;

			realloc_buffer = realloc(buffer, buffer_size);
			if (realloc_buffer) {
				buffer = realloc_buffer;
			} else {
				err = ERR_IPV4_SEE_ERRNO;
				goto cleanup;
			}
		}

		line = buffer + total_bytes_read;
	}

cleanup:
	if (pclose(fp))
		log_warn("Could not close netstat pipe (%s).\n", strerror(errno));
	if (err)
		goto end;

	// reserve enough memory (256 shorts)
	// to make sure not to access out of bounds later,
	// for ipv4 only unsigned short is allowed

	unsigned short flag_table[256] = { 0 };

	/*
	 * Fill the flag_table now. Unfortunately it is not easy
	 * to do this in a more elegant way. The problem here
	 * is that these are already preprocessor macros and
	 * we can't use them as arguments for another macro which
	 * would include the #ifdef statements.
	 *
	 * Also, not all flags might be allowed in the context
	 * of ipv4, and the code depends on which ones are
	 * actually implemented on the target platform, which
	 * might also be varying between Mac OS X versions.
	 *
	 */

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
#ifdef RTF_UP	 // Route usable
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

#endif

	if (total_bytes_read == 0) {
		log_debug("Routing table is empty.\n");
		err = ERR_IPV4_PROC_NET_ROUTE;
		goto end;
	}
	buffer[total_bytes_read] = '\0';

	// Skip first line
	start = strchr(buffer, '\n');
	if (start == NULL) {
		log_debug("Routing table is malformed.\n");
		err = ERR_IPV4_PROC_NET_ROUTE;
		goto end;
	}
	start++;

#if !HAVE_PROC_NET_ROUTE
	if (strstr(buffer, "Ref") != NULL)
		have_ref = 1;
	if (strstr(buffer, "Use") != NULL)
		have_use = 1;
	// Skip 3 more lines from netstat output on Mac OS X and on FreeBSD
	start = strchr(start, '\n');
	start = strchr(++start, '\n');
	start = strchr(++start, '\n');
	if (start == NULL) {
		log_debug("Routing table is malformed.\n");
		err = ERR_IPV4_PROC_NET_ROUTE;
		goto end;
	}
#endif

	if (strchr(start, '\n') == NULL) {
		log_debug("Routing table is malformed.\n");
		err = ERR_IPV4_PROC_NET_ROUTE;
		goto end;
	}

	// Look for the route
	line = strtok_r(start, "\n", &saveptr1);
	while (line != NULL) {
		char *iface;
		uint32_t dest, mask, gtw;
		unsigned short flags;
#if HAVE_PROC_NET_ROUTE
		unsigned short irtt;
		short metric;
		unsigned long mtu, window;

		iface = strtok_r(line, "\t", &saveptr2);
		dest = strtoul(strtok_r(NULL, "\t", &saveptr2), NULL, 16);
		gtw = strtoul(strtok_r(NULL, "\t", &saveptr2), NULL, 16);
		flags = strtoul(strtok_r(NULL, "\t", &saveptr2), NULL, 16);
		strtok_r(NULL, "\t", &saveptr2); // "RefCnt"
		strtok_r(NULL, "\t", &saveptr2); // "Use"
		metric = strtoul(strtok_r(NULL, "\t", &saveptr2), NULL, 16);
		mask = strtoul(strtok_r(NULL, "\t", &saveptr2), NULL, 16);
		mtu = strtoul(strtok_r(NULL, "\t", &saveptr2), NULL, 16);
		window = strtoul(strtok_r(NULL, "\t", &saveptr2), NULL, 16);
		irtt = strtoul(strtok_r(NULL, "\t", &saveptr2), NULL, 16);
#else
		/* parse netstat output on Mac OS X and BSD */
		char tmp_ip_string[16];
		struct in_addr dstaddr;
		int pos;
		char *tmpstr;

		log_debug_details("\n");
		log_debug_details("line: %s\n", line);

		saveptr3 = NULL;
		dest = UINT32_MAX;
		mask = UINT32_MAX;
		// "Destination"
		tmpstr = strtok_r(line, " ", &saveptr2);
		if (strncmp(tmpstr, "Internet6", 9) == 0) {
			// we have arrived at the end of ipv4 output
			goto end;
		}
		log_debug_details("- Destination: %s\n", tmpstr);
		// replace literal "default" route by IPV4 numbers-and-dots notation
		if (strncmp(tmpstr, "default", 7) == 0) {
			dest = 0;
			mask = 0;
		} else {
			int is_mask_set = 0;
			char *tmp_position;
			int dot_count = -1;

			if (strchr(tmpstr, '/') != NULL) {
				// 123.123.123.123/30 style
				// 123.123.123/24 style
				// 123.123/24 style

				// break CIDR up into address and mask part
				strcpy(tmp_ip_string, strtok_r(tmpstr, "/", &saveptr3));
				mask = strtoul(saveptr3, NULL, 10);
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
				tmp_position = strchr(++tmp_position, '.');
			}

			for (int i = dot_count; i < 3; i++)
				strcat(tmp_ip_string, ".0");

			if (inet_aton(tmp_ip_string, &dstaddr))
				dest = dstaddr.s_addr;

			if (!is_mask_set) {
				// convert from CIDR to ipv4 mask
				mask = 0xffffffff << (32-((dot_count + 1) * 8));
			}
			// convert mask to reversed byte order
			mask = ((mask & 0xff000000) >> 24)
			       | ((mask & 0xff0000) >> 8)
			       | ((mask & 0xff00) << 8)
			       | ((mask & 0xff) << 24);
		}
		log_debug_details("- Destination IP Hex: %x\n", dest);
		log_debug_details("- Destination Mask Hex: %x\n", mask);
		// "Gateway"
		gtw = 0;
		if (inet_aton(strtok_r(NULL, " ", &saveptr2), &dstaddr)) {
			gtw = dstaddr.s_addr;
			log_debug_details("- Gateway Mask Hex: %x\n", gtw);
		}
		// "Flags"
		tmpstr = strtok_r(NULL, " ", &saveptr2);
		flags = 0;
		// this is the reason for the 256 entries mentioned above
		for (pos = 0; pos < strlen(tmpstr); pos++)
			flags |= flag_table[(unsigned char)tmpstr[pos]];

		if (have_ref)
			strtok_r(NULL, " ", &saveptr2); // "Ref"
		if (have_use)
			strtok_r(NULL, " ", &saveptr2); // "Use"

		iface = strtok_r(NULL, " ", &saveptr2); // "Netif"
		log_debug_details("- Interface: %s\n", iface);
#endif
		/*
		 * Now that we have parsed a routing entry, check if it
		 * matches the current argument to the function call.
		 * In rtentry we have integer representation, i.e.
		 * the most significant byte corresponds to the last
		 * number of dotted-number representation and vice versa.
		 * In this representation ( address & mask ) is the network
		 * address.
		 * The routing algorithm does the following:
		 * First, check if the network address we are looking for
		 * falls into the network for the current route.
		 * Therefore, calculate the network address for both, the
		 * current route and for the destination we are searching.
		 * If the destination is a smaller network (for instance a
		 * single host), we have to mask again with the netmask of
		 * the routing entry that we are checking in order to obtain
		 * the network address in the context of the current route.
		 * If both network addresses match, we have found a candidate
		 * for a route.
		 * However, there might be another route for a smaller network,
		 * therefore repeat this and only store the resulting route
		 * when the mask is at least as large as the one we may
		 * have already found in a previous iteration (a larger
		 * netmask corresponds to a smaller network in this
		 * representation, and has a higher priority by default).
		 * Also, only consider routing entries for which the
		 * netmask is not larger than the netmask used in the
		 * argument when calling the function - so that we can
		 * distinguish between different routing entries for subnets
		 * of different size but with the same network address.
		 * For routing entries with the same destination and
		 * the same netmask the metric can be used for adjusting
		 * the priority (this is not supported on mac).
		 * If the metric is larger than one found for this network
		 * size, skip the current route (smaller numbers denote
		 * less hops and therefore have a higher priority).
		 */

		if (((dest & mask) == (rtdest & rtmask & mask))
		    && (mask >= route_mask(route).s_addr)
		    && (mask <= rtmask)
		    && ((route_iface(route) == NULL)
		        || (strcmp(iface, route_iface(route)) == 0)
		        || (strlen(route_iface(route)) > 0
		            && route_iface(route)[0] == '!'
		            && strcmp(iface, &route_iface(route)[1]) != 0)
		       )) {
#if HAVE_PROC_NET_ROUTE
			if (((mask == route_mask(route).s_addr)
			     && (metric <= route->rt_metric))
			    || (rtfound == 0)
			    || (mask > route_mask(route).s_addr)) {
#endif
				rtfound = 1;
				// Requested route has been found
				route_dest(route).s_addr = dest;
				route_mask(route).s_addr = mask;
				route_gtw(route).s_addr = gtw;
				route->rt_flags = flags;

				free(route_iface(route));
				route_iface(route) = strdup(iface);
				if (!route_iface(route)) {
					err = ERR_IPV4_NO_MEM;
					goto end;
				}

#if HAVE_PROC_NET_ROUTE
				// we do not have these values from Mac OS X netstat,
				// so stay with defaults denoted by values of 0
				route->rt_metric = metric;
				route->rt_mtu = mtu;
				route->rt_window = window;
				route->rt_irtt = irtt;
			}
#else
				log_debug_details("- route matches\n");
#endif
		}
		line = strtok_r(NULL, "\n", &saveptr1);
	}

end:
	free(buffer);
	if (err)
		return err;

	if (rtfound == 0) {
		// should not occur anymore unless there is no default route
		log_debug("Route not found.\n");
		// at least restore input values
		route_dest(route).s_addr = rtdest;
		route_mask(route).s_addr = rtmask;
		route_gtw(route).s_addr = rtgtw;

		return ERR_IPV4_NO_SUCH_ROUTE;
	}

	return 0;
}

static int ipv4_set_route(struct rtentry *route)
{
#ifdef HAVE_RT_ENTRY_WITH_RT_DST
	/* we can copy rtentry struct directly between openfortivpn and kernel */
	log_debug("ip route add %s\n", ipv4_show_route(route));

	int sockfd = socket(AF_INET, SOCK_DGRAM, 0);

	if (sockfd < 0)
		return ERR_IPV4_SEE_ERRNO;
	if (ioctl(sockfd, SIOCADDRT, route) == -1) {
		if (close(sockfd))
			log_warn("Could not close socket for setting route (%s).\n",
			         strerror(errno));
		return ERR_IPV4_SEE_ERRNO;
	}
	if (close(sockfd))
		log_warn("Could not close socket for setting route: %s\n",
		         strerror(errno));
#else
	/* we have to use the route command as tool for route manipulation */
	char cmd[SHOW_ROUTE_BUFFER_SIZE];

	if (access("/sbin/route", F_OK) != 0) {
		log_error("/sbin/route: %s.\n", strerror(errno));
		return 1;
	}

	strcpy(cmd, "/sbin/route -n add ");
	if (route->rt_flags & RTF_HOST)
		strcat(cmd, "-host ");
	else
		strcat(cmd, "-net ");

	strncat(cmd, inet_ntoa(route_dest(route)), 15);
	if (!(route->rt_flags & RTF_HOST)) {
		strcat(cmd, " -netmask ");
		strncat(cmd, inet_ntoa(route_mask(route)), 15);
	}
	if (route->rt_flags & RTF_GATEWAY) {
		strcat(cmd, " ");
		strncat(cmd, inet_ntoa(route_gtw(route)), 15);
	} else {
		strcat(cmd, " -interface ");
		strncat(cmd, route_iface(route),
		        SHOW_ROUTE_BUFFER_SIZE - strlen(cmd) - 1);
	}

	log_debug("%s\n", cmd);

	int res = system(cmd);

	if (res == -1)
		return ERR_IPV4_SEE_ERRNO;
#endif

	return 0;
}

static int ipv4_del_route(struct rtentry *route)
{
#ifdef HAVE_RT_ENTRY_WITH_RT_DST
	/* we can copy rtentry struct directly between openfortivpn and kernel */
	struct rtentry tmp;
	int sockfd;

	log_debug("ip route del %s\n", ipv4_show_route(route));

	// Copy route to a temp variable to clear some of its properties
	memcpy(&tmp, route, sizeof(tmp));
	tmp.rt_metric = 0;
	tmp.rt_mtu = 0;
	tmp.rt_window = 0;
	tmp.rt_irtt = 0;

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0)
		return ERR_IPV4_SEE_ERRNO;
	if (ioctl(sockfd, SIOCDELRT, &tmp) == -1) {
		if (close(sockfd))
			log_warn("Could not close socket for deleting route (%s).\n",
			         strerror(errno));
		return ERR_IPV4_SEE_ERRNO;
	}
	if (close(sockfd))
		log_warn("Could not close socket for deleting route (%s).\n",
		         strerror(errno));
#else
	char cmd[SHOW_ROUTE_BUFFER_SIZE];

	if (access("/sbin/route", F_OK) != 0) {
		log_error("/sbin/route: %s.\n", strerror(errno));
		return 1;
	}

	strcpy(cmd, "/sbin/route -n delete ");
	if (route->rt_flags & RTF_HOST)
		strcat(cmd, "-host ");
	else
		strcat(cmd, "-net ");

	strncat(cmd, inet_ntoa(route_dest(route)), 15);
	if (!(route->rt_flags & RTF_HOST)) {
		strcat(cmd, " -netmask ");
		strncat(cmd, inet_ntoa(route_mask(route)), 15);
	}
	if (route->rt_flags & RTF_GATEWAY) {
		strcat(cmd, " ");
		strncat(cmd, inet_ntoa(route_gtw(route)), 15);
	} else {
		strcat(cmd, " -interface ");
		strncat(cmd, route_iface(route),
		        SHOW_ROUTE_BUFFER_SIZE - strlen(cmd) - 1);
	}

	log_debug("%s\n", cmd);

	int res = system(cmd);

	if (res == -1)
		return ERR_IPV4_SEE_ERRNO;
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
	route_iface(def_rt) = malloc(strlen(tunnel->ppp_iface) + 2);
	if (!route_iface(def_rt)) {
		log_error("malloc: %s\n", strerror(errno));
		return ERR_IPV4_SEE_ERRNO;
	}
	sprintf(route_iface(def_rt), "!%s", tunnel->ppp_iface);

	ret = ipv4_get_route(def_rt);
	if (ret != 0) {
		log_warn("Could not get current default route (%s).\n",
		         err_ipv4_str(ret));
		log_warn("Protecting tunnel route has failed. But this can be working except for some cases.\n");
		goto err_destroy_def_rt;
	}

	// Set the up a route to the tunnel gateway
	route_dest(gtw_rt).s_addr = tunnel->config->gateway_ip.s_addr;
	route_mask(gtw_rt).s_addr = inet_addr("255.255.255.255");
	route_iface(gtw_rt) = malloc(strlen(tunnel->ppp_iface) + 2);
	if (!route_iface(gtw_rt)) {
		log_error("malloc: %s\n", strerror(errno));
		return ERR_IPV4_SEE_ERRNO;
	}
	sprintf(route_iface(gtw_rt), "%s", tunnel->ppp_iface);
	ret = ipv4_get_route(gtw_rt);
	if ((ret == 0)
	    && (route_dest(gtw_rt).s_addr == tunnel->config->gateway_ip.s_addr)
	    && (route_mask(gtw_rt).s_addr == inet_addr("255.255.255.255"))) {
		log_debug("Removing wrong route to vpn server...\n");
		log_debug("ip route show %s\n", ipv4_show_route(gtw_rt));
		ipv4_del_route(gtw_rt);
	}
	sprintf(route_iface(gtw_rt), "!%s", tunnel->ppp_iface);
	ret = ipv4_get_route(gtw_rt);
	if (ret != 0) {
		log_warn("Could not get route to gateway (%s).\n",
		         err_ipv4_str(ret));
		log_warn("Protecting tunnel route has failed. But this can be working except for some cases.\n");
		goto err_destroy_gtw_rt;
	}
	route_dest(gtw_rt).s_addr = tunnel->config->gateway_ip.s_addr;
	route_mask(gtw_rt).s_addr = inet_addr("255.255.255.255");
	gtw_rt->rt_flags |= RTF_HOST;
	gtw_rt->rt_metric = 0;

	tunnel->ipv4.route_to_vpn_is_added = 1;
	log_debug("Setting route to vpn server...\n");
	log_debug("ip route show %s\n", ipv4_show_route(gtw_rt));
	ret = ipv4_set_route(gtw_rt);
	if (ret == ERR_IPV4_SEE_ERRNO && errno == EEXIST) {
		log_warn("Route to vpn server exists already.\n");

		tunnel->ipv4.route_to_vpn_is_added = 0;
	} else if (ret != 0)
		log_warn("Could not set route to vpn server (%s).\n",
		         err_ipv4_str(ret));

	return 0;

err_destroy_gtw_rt:
	route_destroy(gtw_rt);
err_destroy_def_rt:
	route_destroy(def_rt);
	tunnel->ipv4.route_to_vpn_is_added = 0;
	return ret;
}

#if HAVE_USR_SBIN_PPPD
static void add_text_route(struct tunnel *tunnel, const char *dest,
                           const char *mask, const char *gw)
{
	size_t l0, l1;
	static const char fmt[] = ",%s/%s/%s";
	static const char trigger[] = "openfortivpn";
	char **target = &tunnel->config->pppd_ipparam;
	char *ptr;

	if (*target == NULL || strncmp(*target, trigger, strlen(trigger)))
		return;
	if (!dest || !mask || !gw)
		return;
	log_info("Registering route %s/%s via %s\n", dest, mask, gw);
	l0 = strlen(*target);
	l1 = strlen(fmt) + strlen(dest) + strlen(mask) + strlen(gw) + 1;
	ptr = realloc(*target, l0 + l1);
	if (ptr) {
		*target = ptr;
		snprintf(*target + l0, l1, fmt, dest, mask, gw);
	} else {
		log_error("realloc: %s\n", strerror(errno));
	}
}
#endif

int ipv4_add_split_vpn_route(struct tunnel *tunnel, char *dest, char *mask,
                             char *gateway)
{
	struct rtentry *route;
	char env_var[24]; // strlen("VPN_ROUTE_GATEWAY_") + strlen("65535") + 1

#if HAVE_USR_SBIN_PPPD
	add_text_route(tunnel, dest, mask, gateway);
#endif
	if (tunnel->ipv4.split_routes == MAX_SPLIT_ROUTES)
		return ERR_IPV4_NO_MEM;
	if ((tunnel->ipv4.split_rt == NULL)
	    || ((tunnel->ipv4.split_routes % STEP_SPLIT_ROUTES) == 0)) {
		void *new_ptr
		        = realloc(tunnel->ipv4.split_rt,
		                  (size_t) (tunnel->ipv4.split_routes + STEP_SPLIT_ROUTES)
		                  * sizeof(*(tunnel->ipv4.split_rt)));
		if (new_ptr == NULL)
			return ERR_IPV4_NO_MEM;
		tunnel->ipv4.split_rt = new_ptr;
	}

	assert(tunnel->ipv4.split_routes >= 0 &&
	       tunnel->ipv4.split_routes < MAX_SPLIT_ROUTES);
	sprintf(env_var, "VPN_ROUTE_DEST_%d", tunnel->ipv4.split_routes);
	setenv(env_var, dest, 0);
	sprintf(env_var, "VPN_ROUTE_MASK_%d", tunnel->ipv4.split_routes);
	setenv(env_var, mask, 0);
	if (gateway != NULL) {
		sprintf(env_var, "VPN_ROUTE_GATEWAY_%d", tunnel->ipv4.split_routes);
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
		free(route_iface(route));
		route_iface(route) = strdup(tunnel->ppp_iface);
		if (!route_iface(route))
			return ERR_IPV4_NO_MEM;
	}

	return 0;
}

static int ipv4_set_split_routes(struct tunnel *tunnel)
{
	for (int i = 0; i < tunnel->ipv4.split_routes; i++) {
		struct rtentry *route;
		int ret;

		route = &tunnel->ipv4.split_rt[i];
		// check if the route to be added is not the one to the gateway itself
		if (route_dest(route).s_addr == route_dest(&tunnel->ipv4.gtw_rt).s_addr) {
			log_debug("Skipping route to tunnel gateway (%s).\n",
			          ipv4_show_route(route));
			continue;
		}

		free(route_iface(route));
		route_iface(route) = strdup(tunnel->ppp_iface);
		if (!route_iface(route))
			return ERR_IPV4_NO_MEM;
		if (route_gtw(route).s_addr == tunnel->ipv4.ip_addr.s_addr)
			route_gtw(route).s_addr = 0;
		if (route_gtw(route).s_addr == 0)
			route->rt_flags &= ~RTF_GATEWAY;
		if (route_gtw(route).s_addr != 0)
			route->rt_flags |= RTF_GATEWAY;
		ret = ipv4_set_route(route);
		if (ret == ERR_IPV4_SEE_ERRNO && errno == EEXIST)
			log_info("Route to gateway exists already.\n");
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

		free(route_iface(ppp_rt));
		route_iface(ppp_rt) = strdup(tunnel->ppp_iface);
		if (!route_iface(ppp_rt))
			return ERR_IPV4_NO_MEM;
		if (route_gtw(ppp_rt).s_addr == tunnel->ipv4.ip_addr.s_addr)
			route_gtw(ppp_rt).s_addr = 0;
		if (route_gtw(ppp_rt).s_addr == 0)
			ppp_rt->rt_flags &= ~RTF_GATEWAY;
		if (route_gtw(ppp_rt).s_addr != 0)
			ppp_rt->rt_flags |= RTF_GATEWAY;
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

		free(route_iface(ppp_rt));
		route_iface(ppp_rt) = strdup(tunnel->ppp_iface);
		if (!route_iface(ppp_rt))
			return ERR_IPV4_NO_MEM;
		if (route_gtw(ppp_rt).s_addr == tunnel->ipv4.ip_addr.s_addr)
			route_gtw(ppp_rt).s_addr = 0;
		if (route_gtw(ppp_rt).s_addr == 0)
			ppp_rt->rt_flags &= ~RTF_GATEWAY;
		if (route_gtw(ppp_rt).s_addr != 0)
			ppp_rt->rt_flags |= RTF_GATEWAY;
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
	else if (ret == 0)
		return ipv4_set_default_routes(tunnel);
	else
		return ret;
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
				log_warn("Could not restore default route (%s). Already restored?\n",
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

static inline char *replace_char(char *str, char find, char replace)
{
	for (size_t i = 0; i < strlen(str); i++)
		if (str[i] == find)
			str[i] = replace;
	return str;
}

int ipv4_add_nameservers_to_resolv_conf(struct tunnel *tunnel)
{
	int ret = -1;
	FILE *file;
	struct stat stat;
#define NS_SIZE ARRAY_SIZE("nameserver xxx.xxx.xxx.xxx\n")
	char ns1[NS_SIZE], ns2[NS_SIZE];
#undef NS_SIZE
#define DNS_SUFFIX_SIZE (ARRAY_SIZE("search \n") + MAX_DOMAIN_LENGTH)
	char dns_suffix[DNS_SUFFIX_SIZE];
#undef DNS_SUFFIX_SIZE
	char *buffer = NULL;
#if HAVE_RESOLVCONF
	int use_resolvconf = 0;
#endif

	tunnel->ipv4.ns1_was_there = 0;
	tunnel->ipv4.ns2_was_there = 0;
	tunnel->ipv4.dns_suffix_was_there = 0;

	if (tunnel->ipv4.ns1_addr.s_addr == 0)
		tunnel->ipv4.ns1_was_there = -1;

	if (tunnel->ipv4.ns2_addr.s_addr == 0)
		tunnel->ipv4.ns2_was_there = -1;

#if HAVE_RESOLVCONF
	if (tunnel->config->use_resolvconf
	    && (access(RESOLVCONF_PATH, F_OK) == 0)) {
		int resolvconf_call_len;
		char *resolvconf_call;

		log_debug("Attempting to run %s.\n", RESOLVCONF_PATH);
		resolvconf_call_len = strlen(RESOLVCONF_PATH) + 20
		                      + strlen(tunnel->ppp_iface);
		resolvconf_call = malloc(resolvconf_call_len);
		if (resolvconf_call == NULL) {
			log_warn("Could not create command to run resolvconf (%s).\n",
			         strerror(errno));
			return 1;
		}

		snprintf(resolvconf_call, resolvconf_call_len,
		         "%s -a \"%s.openfortivpn\"",
		         RESOLVCONF_PATH,
		         tunnel->ppp_iface);

		use_resolvconf = 1;
		log_debug("resolvconf_call: %s\n", resolvconf_call);
		file = popen(resolvconf_call, "w");
		if (file == NULL) {
			log_warn("Could not open pipe %s (%s).\n",
			         resolvconf_call,
			         strerror(errno));
			free(resolvconf_call);
			return 1;
		}
		free(resolvconf_call);
	} else {
#endif
		log_debug("Attempting to modify /etc/resolv.conf directly.\n");
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
#if HAVE_RESOLVCONF
	}
#endif
	if (tunnel->ipv4.ns1_addr.s_addr != 0) {
		strcpy(ns1, "nameserver ");
		strncat(ns1, inet_ntoa(tunnel->ipv4.ns1_addr), 15);
	} else {
		ns1[0] = '\0';
	}

	if (tunnel->ipv4.ns2_addr.s_addr != 0) {
		strcpy(ns2, "nameserver ");
		strncat(ns2, inet_ntoa(tunnel->ipv4.ns2_addr), 15);
	} else {
		ns2[0] = '\0';
	}

	if (tunnel->ipv4.dns_suffix != NULL) {
		strcpy(dns_suffix, "search ");
		strncat(dns_suffix, tunnel->ipv4.dns_suffix, MAX_DOMAIN_LENGTH);
		replace_char(dns_suffix, ';', ' ');
	} else {
		dns_suffix[0] = '\0';
	}

#if HAVE_RESOLVCONF
	if (use_resolvconf == 0) {
#endif
		char *saveptr = NULL;

		for (const char *line = strtok_r(buffer, "\n", &saveptr);
		     line != NULL;
		     line = strtok_r(NULL, "\n", &saveptr)) {
			if (strcmp(line, ns1) == 0) {
				tunnel->ipv4.ns1_was_there = 1;
				log_debug("ns1 already present in /etc/resolv.conf.\n");
			}
		}

		if (tunnel->ipv4.ns1_was_there == 0)
			log_debug("Adding \"%s\", to /etc/resolv.conf.\n", ns1);

		for (const char *line = strtok_r(buffer, "\n", &saveptr);
		     line != NULL;
		     line = strtok_r(NULL, "\n", &saveptr)) {
			if (strcmp(line, ns2) == 0) {
				tunnel->ipv4.ns2_was_there = 1;
				log_debug("ns2 already present in /etc/resolv.conf.\n");
			}
		}

		if (tunnel->ipv4.ns2_was_there == 0)
			log_debug("Adding \"%s\", to /etc/resolv.conf.\n", ns2);

		if (dns_suffix[0] == '\0') {
			tunnel->ipv4.dns_suffix_was_there = -1;
		} else {
			for (const char *line = strtok_r(buffer, "\n", &saveptr);
			     line != NULL;
			     line = strtok_r(NULL, "\n", &saveptr)) {
				if (dns_suffix[0] != '\0'
				    && strcmp(line, dns_suffix) == 0) {
					tunnel->ipv4.dns_suffix_was_there = 1;
					log_debug("dns_suffix already present in /etc/resolv.conf.\n");
				}
			}
		}

		if (tunnel->ipv4.dns_suffix_was_there == 0)
			log_debug("Adding \"%s\", to /etc/resolv.conf.\n", dns_suffix);

		rewind(file);
		if (fread(buffer, stat.st_size, 1, file) != 1) {
			log_warn("Could not read /etc/resolv.conf.\n");
			goto err_free;
		}

		buffer[stat.st_size] = '\0';

		rewind(file);
#if HAVE_RESOLVCONF
	}
#endif
	if (tunnel->ipv4.ns1_was_there == 0) {
		strcat(ns1, "\n");
		fputs(ns1, file);
	}
	if (tunnel->ipv4.ns2_was_there == 0) {
		strcat(ns2, "\n");
		fputs(ns2, file);
	}
	if (tunnel->ipv4.dns_suffix_was_there == 0) {
		strcat(dns_suffix, "\n");
		fputs(dns_suffix, file);
	}
#if HAVE_RESOLVCONF
	if (use_resolvconf == 0)
#endif
		fwrite(buffer, stat.st_size, 1, file);

	ret = 0;

err_free:
	free(buffer);
err_close:
#if HAVE_RESOLVCONF
	if (use_resolvconf == 0) {
#endif
		if (fclose(file))
			log_warn("Could not close /etc/resolv.conf: %s\n",
			         strerror(errno));
#if HAVE_RESOLVCONF
	} else {
		if (pclose(file) == -1)
			log_warn("Could not close resolvconf pipe: %s\n",
			         strerror(errno));
	}
#endif

	return ret;
}

int ipv4_del_nameservers_from_resolv_conf(struct tunnel *tunnel)
{
	int ret = -1;
	FILE *file;
	struct stat stat;
#define NS_SIZE ARRAY_SIZE("nameserver xxx.xxx.xxx.xxx")
	char ns1[NS_SIZE], ns2[NS_SIZE];
#undef NS_SIZE
#define DNS_SUFFIX_SIZE (ARRAY_SIZE("search ") + MAX_DOMAIN_LENGTH)
	char dns_suffix[DNS_SUFFIX_SIZE];
#undef DNS_SUFFIX_SIZE
	char *buffer = NULL;
	char *saveptr = NULL;

#if HAVE_RESOLVCONF
	if (tunnel->config->use_resolvconf
	    && (access(RESOLVCONF_PATH, F_OK) == 0)) {
		int resolvconf_call_len;
		char *resolvconf_call;

		resolvconf_call_len = strlen(RESOLVCONF_PATH) + 20
		                      + strlen(tunnel->ppp_iface);
		resolvconf_call = malloc(resolvconf_call_len);
		if (resolvconf_call == NULL) {
			log_warn("Could not create command to run resolvconf (%s).\n",
			         strerror(errno));
			return ERR_IPV4_SEE_ERRNO;
		}

		snprintf(resolvconf_call,
		         resolvconf_call_len,
		         "%s -d \"%s.openfortivpn\"",
		         RESOLVCONF_PATH,
		         tunnel->ppp_iface
		        );

		log_debug("resolvconf_call: %s\n", resolvconf_call);
		ret = system(resolvconf_call);
		free(resolvconf_call);
		if (ret == -1)
			return ERR_IPV4_SEE_ERRNO;
		return 0;
	}
#endif

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

	ns1[0] = '\0';
	if (tunnel->ipv4.ns1_addr.s_addr != 0) {
		strcpy(ns1, "nameserver ");
		strncat(ns1, inet_ntoa(tunnel->ipv4.ns1_addr), 15);
	}
	ns2[0] = '\0';
	if (tunnel->ipv4.ns2_addr.s_addr != 0) {
		strcpy(ns2, "nameserver ");
		strncat(ns2, inet_ntoa(tunnel->ipv4.ns2_addr), 15);
	}
	dns_suffix[0] = '\0';
	if (tunnel->ipv4.dns_suffix != NULL && tunnel->ipv4.dns_suffix[0] != '\0') {
		strcpy(dns_suffix, "search ");
		strncat(dns_suffix, tunnel->ipv4.dns_suffix, MAX_DOMAIN_LENGTH);
	}

	file = freopen("/etc/resolv.conf", "w", file);
	if (file == NULL) {
		log_warn("Could not reopen /etc/resolv.conf (%s).\n",
		         strerror(errno));
		goto err_free;
	}

	for (const char *line = strtok_r(buffer, "\n", &saveptr);
	     line != NULL;
	     line = strtok_r(NULL, "\n", &saveptr)) {
		if (ns1[0] != '\0' && strcmp(line, ns1) == 0
		    && (tunnel->ipv4.ns1_was_there == 0)) {
			log_debug("Deleting \"%s\" from /etc/resolv.conf.\n", ns1);
		} else if (ns2[0] != '\0' && strcmp(line, ns2) == 0
		           && (tunnel->ipv4.ns2_was_there == 0)) {
			log_debug("Deleting \"%s\" from /etc/resolv.conf.\n", ns2);
		} else if (dns_suffix[0] != '\0' && strcmp(line, dns_suffix) == 0
		           && (tunnel->ipv4.dns_suffix_was_there == 0)) {
			log_debug("Deleting \"%s\" from /etc/resolv.conf.\n", dns_suffix);
		} else {
			fputs(line, file);
			fputs("\n", file);
		}
	}

	ret = 0;

err_free:
	free(buffer);
err_close:
	if (file && fclose(file))
		log_warn("Could not close /etc/resolv.conf (%s).\n",
		         strerror(errno));
	return ret;
}
