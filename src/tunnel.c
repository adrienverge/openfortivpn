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
#include <netinet/in.h>
#include <netdb.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <pty.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <signal.h>
#include <openssl/err.h>
#include <ifaddrs.h>
#include <net/if.h>

#include "http.h"
#include "io.h"
#include "ipv4.h"
#include "log.h"
#include "tunnel.h"

static int on_ppp_if_up(struct tunnel *tunnel)
{
	log_info("ppp interface is up.\n");

	if (tunnel->config->set_routes) {
		if (ipv4_set_tunnel_routes(tunnel))
			log_warn("Error setting IP routes.\n");
			//return 1;
	}

	if (tunnel->config->set_dns) {
		log_info("Adding VPN nameservers...\n");
		ipv4_add_nameservers_to_resolv_conf(tunnel);
	}

	log_info("Tunnel is up and running.\n");

	return 0;
}

static int on_ppp_if_down(struct tunnel *tunnel)
{
	log_info("Setting ppp interface down.\n");

	if (tunnel->config->set_routes) {
		if (ipv4_restore_routes(tunnel))
			log_warn("Error restoring IP routes.\n");
			//return 1;
	}

	if (tunnel->config->set_dns) {
		// TODO: if the nameservers were already present, don't delete
		// them at the end.
		log_info("Removing VPN nameservers...\n");
		ipv4_del_nameservers_from_resolv_conf(tunnel);
	}

	return 0;
}

static int pppd_run(struct tunnel *tunnel)
{
	pid_t pid;
	int amaster;
	struct termios termp;

	termp.c_cflag = B9600;
	termp.c_cc[VTIME] = 0;
	termp.c_cc[VMIN] = 1;

	pid = forkpty(&amaster, NULL, &termp, NULL);
	if (pid == -1) {
		log_error("forkpty: %s\n", strerror(errno));
		return 1;
	} else if (pid == 0) {
		char *args[] = {
			"/usr/sbin/pppd", "38400", "noipdefault", "noaccomp",
			"noauth", "default-asyncmap", "nopcomp",
			"nodefaultroute", ":1.1.1.1", "nodetach",
			"lcp-max-configure", "40", "usepeerdns", "mru", "1024",
			"debug", "logfile", tunnel->config->pppd_log, NULL };
		if (!tunnel->config->pppd_log)
			args[15] = NULL; // Remove "debug logfile pppd.log"

		close(tunnel->ssl_socket);
		if (execvp(args[0], args) == -1) {
			log_error("execvp: %s\n", strerror(errno));
			return 1;
		}
	}

	// Set non-blocking
	int flags;
	if ((flags = fcntl(amaster, F_GETFL, 0)) == -1)
		flags = 0;
	if (fcntl(amaster, F_SETFL, flags | O_NONBLOCK) == -1) {
		log_error("fcntl: %s\n", strerror(errno));
		return 1;
	}

	tunnel->pppd_pid = pid;
	tunnel->pppd_pty = amaster;

	return 0;
}

static int pppd_terminate(struct tunnel *tunnel)
{
	close(tunnel->pppd_pty);

	log_debug("Waiting for pppd to exit...\n");
	waitpid(tunnel->pppd_pid, NULL, 0);

	return 0;
}

int ppp_interface_is_up(struct tunnel *tunnel)
{
	struct ifaddrs *ifap, *ifa;

	if (getifaddrs(&ifap)) {
		log_error("getifaddrs: %s\n", strerror(errno));
		return 0;
	}

	for (ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
		if (strstr(ifa->ifa_name, "ppp") != NULL && ifa->ifa_flags & IFF_UP) {
			strncpy(tunnel->ppp_iface, ifa->ifa_name, ROUTE_IFACE_LEN - 1);
			log_debug("Interface %s is UP.\n", tunnel->ppp_iface);

			freeifaddrs(ifap);
			return 1;
		}
	}
	freeifaddrs(ifap);

	return 0;
}

static int get_gateway_host_ip(struct tunnel *tunnel)
{
	struct hostent *host = gethostbyname(tunnel->config->gateway_host);
	if (host == NULL) {
		log_error("gethostbyname: %s\n", strerror(h_errno));
		return 1;
	}

	tunnel->config->gateway_ip = *((struct in_addr *) host->h_addr_list[0]);
	return 0;
}

/*
 * Establish a regular TCP connection.
 */
static int tcp_connect(struct tunnel *tunnel)
{
	int ret, handle;
	struct sockaddr_in server;

	handle = socket(AF_INET, SOCK_STREAM, 0);
	if (handle == -1) {
		log_error("socket: %s\n", strerror(errno));
		return -1;
	}

	server.sin_family = AF_INET;
	server.sin_port = htons(tunnel->config->gateway_port);
	server.sin_addr = tunnel->config->gateway_ip;
	bzero(&(server.sin_zero), 8);

	ret = connect(handle, (struct sockaddr *) &server, sizeof(struct sockaddr));
	if (ret == -1) {
		log_error("connect: %s\n", strerror(errno));
		return -1;
	}

	return handle;
}

/*
 * Connects to the gateway and initiate a SSL session.
 */
static int ssl_connect(struct tunnel *tunnel)
{
	tunnel->ssl_handle = NULL;
	tunnel->ssl_context = NULL;

	tunnel->ssl_socket = tcp_connect(tunnel);
	if (tunnel->ssl_socket == -1) {
		return 1;
	}

	// Register the error strings for libcrypto & libssl
	SSL_load_error_strings();
	// Register the available ciphers and digests
	SSL_library_init();

	tunnel->ssl_context = SSL_CTX_new(SSLv23_client_method());
	if (tunnel->ssl_context == NULL) {
		log_error("SSL_CTX_new: %s\n", ERR_error_string(ERR_peek_last_error(), NULL));
		return 1;
	}

	//tunnel->ssl_bio = BIO_new_ssl_connect(tunnel->ssl_context);
	//BIO_get_ssl(tunnel->ssl_bio, &tunnel->ssl_handle);
	//if (!tunnel->ssl_handle)
	//	return 1;
	//SSL_set_mode(tunnel->ssl_handle, SSL_MODE_AUTO_RETRY);
	///* Attempt to connect */
	//BIO_set_conn_hostname(tunnel->ssl_bio, "62.23.54.234:10443");
	//if (BIO_do_connect(tunnel->ssl_bio) < 1) {
	//	BIO_free(tunnel->ssl_bio);
	//	return 1;
	//}

	tunnel->ssl_handle = SSL_new(tunnel->ssl_context);
	if (tunnel->ssl_handle == NULL) {
		log_error("SSL_new: %s\n", ERR_error_string(ERR_peek_last_error(), NULL));
		return 1;
	}

	if (!SSL_set_fd(tunnel->ssl_handle, tunnel->ssl_socket)) {
		log_error("SSL_set_fd: %s\n", ERR_error_string(ERR_peek_last_error(), NULL));
		return 1;
	}

	// Initiate SSL handshake
	if (SSL_connect(tunnel->ssl_handle) != 1) {
		log_error("SSL_connect: %s\n", ERR_error_string(ERR_peek_last_error(), NULL));
		return 1;
	}

	// TODO:
	//if (SSL_get_verify_result(tunnel->ssl_context) != X509_V_OK) {

	// Disable SIGPIPE (occurs when trying to write to an already-closed socket).
	signal(SIGPIPE, SIG_IGN);

	return 0;
}

/*
 * Destroy and free the SSL connection to the gateway.
 */
static void ssl_disconnect(struct tunnel *tunnel)
{
	SSL_shutdown(tunnel->ssl_handle);
	SSL_free(tunnel->ssl_handle);
	//BIO_free(tunnel->ssl_bio);
	SSL_CTX_free(tunnel->ssl_context);
	close(tunnel->ssl_socket);
}

int run_tunnel(struct vpn_config *config)
{
	int ret;
	struct tunnel tunnel;

	tunnel.config = config;
	tunnel.on_ppp_if_up = on_ppp_if_up;
	tunnel.on_ppp_if_down = on_ppp_if_down;
	tunnel.nameserver1.s_addr = 0;
	tunnel.nameserver2.s_addr = 0;

	tunnel.state = STATE_DOWN;

	// Step 0: get gateway host IP
	ret = get_gateway_host_ip(&tunnel);
	if (ret)
		goto err_ssl;

	// Step 1: open a SSL connection to the gateway
	ret = ssl_connect(&tunnel);
	if (ret)
		goto err_ssl;
	log_info("Connected to gateway.\n");

	// Step 2: connect to the HTTP interface and authenticate to get a cookie
	ret = auth_log_in(&tunnel);
	if (ret > 0) {
		log_error("Gateway answered: permission denied.\n");
		goto err_log_in;
	} else if (ret < 0) {
		log_error("Could not authenticate to gateway.\n");
		goto err_log_in;
	}
	log_info("Authenticated.\n");
	log_debug("Cookie: %s\n", config->cookie);

	ret = auth_request_vpn_allocation(&tunnel);
	if (ret)
		goto err_vpn_alloc;
	log_info("Remote gateway has allocated a VPN.\n");

	// Step 3: run a pppd process
	ret = pppd_run(&tunnel);
	if (ret)
		goto err_vpn_alloc;

	// Step 4: ask gateway to start tunneling
	ret = http_send(&tunnel,
		"GET /remote/sslvpn-tunnel HTTP/1.1\r\n"
		"Host: sslvpn\r\n"
		"Cookie: %s\r\n"
		"Connection: Keep-Alive\r\n\r\n", tunnel.config->cookie);
	if (ret)
		goto err_start_tunnel;

	tunnel.state = STATE_CONNECTING;
	ret = 0;

	// Step 5: perform io between pppd and the gateway, while tunnel is up
	io_loop(&tunnel);

	if (tunnel.state == STATE_UP)
		if (tunnel.on_ppp_if_down != NULL)
			tunnel.on_ppp_if_down(&tunnel);

	tunnel.state = STATE_DISCONNECTING;

err_start_tunnel:
	pppd_terminate(&tunnel);
	log_info("Terminated pppd.\n");
err_vpn_alloc:
	auth_log_out(&tunnel);
	log_info("Logged out.\n");
err_log_in:
	ssl_disconnect(&tunnel);
	log_info("Closed connection to gateway.\n");
err_ssl:
	tunnel.state = STATE_DOWN;

	return ret;
}
