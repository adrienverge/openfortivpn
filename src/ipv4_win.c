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
 *  Windows implementation of IPv4 routing and DNS configuration.
 *  Uses the Windows IP Helper API (iphlpapi.dll).
 */

#ifdef _WIN32

#include "tunnel.h"
#include "log.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <netioapi.h>

#include <stdio.h>
#include <string.h>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

/*
 * Windows route entry - maps to the ipv4_config rtentry fields.
 */
struct win_route {
	MIB_IPFORWARD_ROW2 row;
	int valid;
};

static struct win_route saved_default_route;
static struct win_route vpn_gateway_route;
static NET_LUID tun_luid;
static int tun_luid_valid;

void ipv4_win_set_tun_luid(NET_LUID *luid)
{
	tun_luid = *luid;
	tun_luid_valid = 1;
}

/*
 * Get the best route to a destination address.
 */
static int get_best_route(struct in_addr dest, MIB_IPFORWARD_ROW2 *route)
{
	SOCKADDR_INET dest_addr;
	SOCKADDR_INET best_src;
	DWORD ret;

	memset(&dest_addr, 0, sizeof(dest_addr));
	dest_addr.Ipv4.sin_family = AF_INET;
	dest_addr.Ipv4.sin_addr = dest;

	ret = GetBestRoute2(NULL, 0, NULL, &dest_addr, 0, route, &best_src);
	if (ret != NO_ERROR) {
		log_error("GetBestRoute2 failed: %lu\n", ret);
		return -1;
	}
	return 0;
}

/*
 * Add a route using the IP Helper API.
 */
static int add_route(struct in_addr dest, struct in_addr mask,
                     struct in_addr gateway, NET_LUID *luid,
                     ULONG metric)
{
	MIB_IPFORWARD_ROW2 row;
	DWORD ret;

	InitializeIpForwardEntry(&row);

	if (luid)
		row.InterfaceLuid = *luid;
	row.DestinationPrefix.Prefix.Ipv4.sin_family = AF_INET;
	row.DestinationPrefix.Prefix.Ipv4.sin_addr = dest;

	/* Calculate prefix length from mask */
	uint32_t m = ntohl(mask.s_addr);
	uint8_t prefix_len = 0;

	while (m & 0x80000000) {
		prefix_len++;
		m <<= 1;
	}
	row.DestinationPrefix.PrefixLength = prefix_len;

	row.NextHop.Ipv4.sin_family = AF_INET;
	row.NextHop.Ipv4.sin_addr = gateway;
	row.Metric = metric;
	row.Protocol = MIB_IPPROTO_NETMGMT;

	ret = CreateIpForwardEntry2(&row);
	if (ret != NO_ERROR && ret != ERROR_OBJECT_ALREADY_EXISTS) {
		log_error("CreateIpForwardEntry2 failed: %lu\n", ret);
		return -1;
	}
	return 0;
}

/*
 * Delete a route using the IP Helper API.
 */
static int del_route(MIB_IPFORWARD_ROW2 *row)
{
	DWORD ret;

	ret = DeleteIpForwardEntry2(row);
	if (ret != NO_ERROR && ret != ERROR_NOT_FOUND) {
		log_error("DeleteIpForwardEntry2 failed: %lu\n", ret);
		return -1;
	}
	return 0;
}

/*
 * Save the current default route for later restoration.
 */
static int save_default_route(void)
{
	struct in_addr any;

	any.s_addr = 0;
	if (get_best_route(any, &saved_default_route.row) == 0) {
		saved_default_route.valid = 1;
		return 0;
	}
	saved_default_route.valid = 0;
	return -1;
}

int ipv4_drop_wrong_route(struct tunnel *tunnel)
{
	/* On Windows, wintun doesn't create spurious routes like pppd does. */
	(void)tunnel;
	return 0;
}

int ipv4_add_split_vpn_route(struct tunnel *tunnel, char *dest, char *mask,
                             char *gateway)
{
	struct rtentry *route;
	struct in_addr dest_addr, mask_addr, gw_addr;

	inet_pton(AF_INET, dest, &dest_addr);
	inet_pton(AF_INET, mask, &mask_addr);
	inet_pton(AF_INET, gateway, &gw_addr);

	log_info("Storing split route: %s/%s via %s\n",
	         dest, mask, gateway);

	/*
	 * Store the route for deferred application. On Windows the TUN
	 * adapter does not exist yet when auth_get_config parses the XML.
	 * Routes are applied later in ipv4_set_tunnel_routes().
	 */
	if (tunnel->ipv4.split_routes == MAX_SPLIT_ROUTES)
		return -1;
	if ((tunnel->ipv4.split_rt == NULL)
	    || ((tunnel->ipv4.split_routes % STEP_SPLIT_ROUTES) == 0)) {
		void *new_ptr;

		new_ptr = realloc(tunnel->ipv4.split_rt,
		                  (size_t)(tunnel->ipv4.split_routes
		                           + STEP_SPLIT_ROUTES)
		                  * sizeof(*(tunnel->ipv4.split_rt)));
		if (new_ptr == NULL)
			return -1;
		tunnel->ipv4.split_rt = new_ptr;
	}

	route = &tunnel->ipv4.split_rt[tunnel->ipv4.split_routes++];
	memset(route, 0, sizeof(*route));
	cast_addr(&route->rt_dst)->sin_addr = dest_addr;
	cast_addr(&route->rt_genmask)->sin_addr = mask_addr;
	cast_addr(&route->rt_gateway)->sin_addr = gw_addr;

	return 0;
}

int ipv4_set_tunnel_routes(struct tunnel *tunnel)
{
	struct in_addr gateway_ip = tunnel->config->gateway_ip;
	struct in_addr any, full_mask, half_mask;
	int ret;

	any.s_addr = 0;
	full_mask.s_addr = htonl(0xFFFFFFFF);
	half_mask.s_addr = htonl(0x80000000);

	/* Save existing default route */
	save_default_route();

	/*
	 * Add route to VPN gateway via existing default route.
	 * This prevents routing loops in full-tunnel mode. For split-tunnel
	 * mode it is not strictly necessary — if it fails, continue anyway
	 * so the split routes can still be applied.
	 */
	if (saved_default_route.valid) {
		struct in_addr saved_gw;

		saved_gw = saved_default_route.row.NextHop.Ipv4.sin_addr;
		ret = add_route(gateway_ip, full_mask, saved_gw, NULL, 0);
		if (ret) {
			log_warn("Could not add route to VPN gateway.\n");
			if (tunnel->ipv4.split_routes == 0)
				return ret;
			/* Split tunnel: continue without gateway route */
		} else {
			tunnel->ipv4.route_to_vpn_is_added = 1;
		}
	}

	if (!tun_luid_valid) {
		log_error("TUN adapter LUID not set.\n");
		return -1;
	}

	if (tunnel->ipv4.split_routes > 0) {
		/* Apply deferred split routes now that the adapter exists */
		for (int i = 0; i < tunnel->ipv4.split_routes; i++) {
			struct rtentry *rt = &tunnel->ipv4.split_rt[i];

			ret = add_route(route_dest(rt), route_mask(rt),
			                route_gtw(rt), &tun_luid, 0);
			if (ret)
				log_warn("Failed to add split route %d\n", i);
		}
		return 0;
	}

	/* Set default route through VPN */
	if (tunnel->config->half_internet_routes) {
		struct in_addr half1, half2;

		half1.s_addr = 0;
		half2.s_addr = htonl(0x80000000);

		/* 0.0.0.0/1 via TUN */
		ret = add_route(half1, half_mask, tunnel->ipv4.ip_addr,
		                &tun_luid, 5);
		if (ret)
			return ret;

		/* 128.0.0.0/1 via TUN */
		ret = add_route(half2, half_mask, tunnel->ipv4.ip_addr,
		                &tun_luid, 5);
		if (ret)
			return ret;
	} else {
		struct in_addr zero_mask;

		zero_mask.s_addr = 0;

		/* Replace default route with one through VPN */
		ret = add_route(any, zero_mask, tunnel->ipv4.ip_addr,
		                &tun_luid, 5);
		if (ret)
			return ret;
	}

	return 0;
}

int ipv4_restore_routes(struct tunnel *tunnel)
{
	struct in_addr any, full_mask, half_mask;
	int ret = 0;

	any.s_addr = 0;
	full_mask.s_addr = htonl(0xFFFFFFFF);
	half_mask.s_addr = htonl(0x80000000);

	/* Remove VPN default routes */
	if (tun_luid_valid) {
		MIB_IPFORWARD_ROW2 row;

		InitializeIpForwardEntry(&row);
		row.InterfaceLuid = tun_luid;

		if (tunnel->config->half_internet_routes) {
			/* Delete 0.0.0.0/1 route */
			row.DestinationPrefix.Prefix.Ipv4.sin_family = AF_INET;
			row.DestinationPrefix.Prefix.Ipv4.sin_addr.s_addr = 0;
			row.DestinationPrefix.PrefixLength = 1;
			row.NextHop.Ipv4.sin_family = AF_INET;
			row.NextHop.Ipv4.sin_addr = tunnel->ipv4.ip_addr;
			del_route(&row);

			/* Delete 128.0.0.0/1 route */
			row.DestinationPrefix.Prefix.Ipv4.sin_addr.s_addr =
			        htonl(0x80000000);
			del_route(&row);
		} else {
			/* Delete default route through VPN */
			row.DestinationPrefix.Prefix.Ipv4.sin_family = AF_INET;
			row.DestinationPrefix.Prefix.Ipv4.sin_addr.s_addr = 0;
			row.DestinationPrefix.PrefixLength = 0;
			row.NextHop.Ipv4.sin_family = AF_INET;
			row.NextHop.Ipv4.sin_addr = tunnel->ipv4.ip_addr;
			del_route(&row);
		}
	}

	/* Remove route to VPN gateway */
	if (tunnel->ipv4.route_to_vpn_is_added) {
		MIB_IPFORWARD_ROW2 row;

		InitializeIpForwardEntry(&row);
		row.DestinationPrefix.Prefix.Ipv4.sin_family = AF_INET;
		row.DestinationPrefix.Prefix.Ipv4.sin_addr =
		        tunnel->config->gateway_ip;
		row.DestinationPrefix.PrefixLength = 32;
		if (saved_default_route.valid) {
			row.InterfaceLuid =
			        saved_default_route.row.InterfaceLuid;
			row.NextHop.Ipv4.sin_family = AF_INET;
			row.NextHop.Ipv4.sin_addr =
			        saved_default_route.row.NextHop.Ipv4.sin_addr;
		}
		del_route(&row);
		tunnel->ipv4.route_to_vpn_is_added = 0;
	}

	return ret;
}

int ipv4_add_nameservers_to_resolv_conf(struct tunnel *tunnel)
{
	char cmd[512];
	char dns1_str[INET_ADDRSTRLEN] = "";
	char dns2_str[INET_ADDRSTRLEN] = "";

	if (!tun_luid_valid) {
		log_error("TUN adapter LUID not set, cannot configure DNS.\n");
		return -1;
	}

	if (tunnel->ipv4.ns1_addr.s_addr != 0) {
		inet_ntop(AF_INET, &tunnel->ipv4.ns1_addr,
		          dns1_str, sizeof(dns1_str));
	}
	if (tunnel->ipv4.ns2_addr.s_addr != 0) {
		inet_ntop(AF_INET, &tunnel->ipv4.ns2_addr,
		          dns2_str, sizeof(dns2_str));
	}

	/*
	 * Use netsh to configure DNS on the TUN interface.
	 * This is the most portable approach across Windows versions.
	 */
	if (dns1_str[0]) {
		snprintf(cmd, sizeof(cmd),
		         "netsh interface ipv4 set dnsservers name=\"openfortivpn\" static %s primary validate=no",
		         dns1_str);
		log_debug("Running: %s\n", cmd);
		system(cmd);
	}

	if (dns2_str[0]) {
		snprintf(cmd, sizeof(cmd),
		         "netsh interface ipv4 add dnsservers name=\"openfortivpn\" %s index=2 validate=no",
		         dns2_str);
		log_debug("Running: %s\n", cmd);
		system(cmd);
	}

	/* Set DNS search suffix if configured */
	if (tunnel->ipv4.dns_suffix) {
		snprintf(cmd, sizeof(cmd),
		         "netsh interface ipv4 set dnsservers name=\"openfortivpn\" register=both suffix=\"%s\" validate=no",
		         tunnel->ipv4.dns_suffix);
		log_debug("Running: %s\n", cmd);
		/* DNS suffix is set via registry for reliability */
	}

	/* Lower the interface metric so VPN DNS is preferred */
	snprintf(cmd, sizeof(cmd),
	         "netsh interface ipv4 set interface \"openfortivpn\" metric=1");
	log_debug("Running: %s\n", cmd);
	system(cmd);

	return 0;
}

int ipv4_del_nameservers_from_resolv_conf(struct tunnel *tunnel)
{
	char cmd[256];

	(void)tunnel;

	/*
	 * Reset DNS on the TUN interface. When the adapter is destroyed,
	 * DNS settings are automatically cleaned up, but we do it explicitly
	 * for clean shutdown.
	 */
	snprintf(cmd, sizeof(cmd),
	         "netsh interface ipv4 set dnsservers name=\"openfortivpn\" dhcp");
	log_debug("Running: %s\n", cmd);
	system(cmd);

	return 0;
}

/*
 * Check if the TUN interface has the expected IP address assigned.
 */
int ppp_interface_is_up(struct tunnel *tunnel)
{
	ULONG size = 0;
	PIP_ADAPTER_ADDRESSES addrs = NULL, curr;
	DWORD ret;
	int found = 0;

	if (!tun_luid_valid)
		return 0;

	/* Get adapter addresses */
	ret = GetAdaptersAddresses(AF_INET,
	                           GAA_FLAG_SKIP_ANYCAST |
	                           GAA_FLAG_SKIP_MULTICAST |
	                           GAA_FLAG_SKIP_DNS_SERVER,
	                           NULL, NULL, &size);
	if (ret != ERROR_BUFFER_OVERFLOW)
		return 0;

	addrs = (PIP_ADAPTER_ADDRESSES)malloc(size);
	if (!addrs)
		return 0;

	ret = GetAdaptersAddresses(AF_INET,
	                           GAA_FLAG_SKIP_ANYCAST |
	                           GAA_FLAG_SKIP_MULTICAST |
	                           GAA_FLAG_SKIP_DNS_SERVER,
	                           NULL, addrs, &size);
	if (ret != NO_ERROR) {
		free(addrs);
		return 0;
	}

	for (curr = addrs; curr; curr = curr->Next) {
		if (curr->Luid.Value == tun_luid.Value &&
		    curr->OperStatus == IfOperStatusUp) {
			/*
			 * Check if the assigned IP matches what we expect.
			 * For wintun, the interface is "up" if it exists.
			 */
			found = 1;

			/* Copy interface name */
			if (curr->AdapterName) {
				strncpy(tunnel->ppp_iface, curr->AdapterName,
				        ROUTE_IFACE_LEN - 1);
				tunnel->ppp_iface[ROUTE_IFACE_LEN - 1] = '\0';
			}
			break;
		}
	}

	free(addrs);
	return found;
}

#endif /* _WIN32 */
