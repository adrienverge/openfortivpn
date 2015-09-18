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

#include <fcntl.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <net/if.h>
#include <openssl/err.h>
#include <pty.h>
#include <sys/wait.h>

#include "http.h"
#include "log.h"

static int on_ppp_if_up(struct tunnel *tunnel)
{
	log_info("Interface %s is UP.\n", tunnel->ppp_iface);

	if (tunnel->config->set_routes) {
		log_info("Setting new routes...\n");
		ipv4_set_tunnel_routes(tunnel);
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
		log_info("Restoring routes...\n");
		ipv4_restore_routes(tunnel);
	}

	if (tunnel->config->set_dns) {
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
		int i = 15;
		char *args[] = {
			"/usr/sbin/pppd", "38400", "noipdefault", "noaccomp",
			"noauth", "default-asyncmap", "nopcomp",
			"nodefaultroute", ":1.1.1.1", "nodetach",
			"lcp-max-configure", "40", "usepeerdns", "mru", "1024",
			NULL, NULL, NULL,
			NULL, NULL, NULL };
		if (tunnel->config->pppd_log) {
			args[i++] = "debug";
			args[i++] = "logfile";
			args[i++] = tunnel->config->pppd_log;
		}
		if (tunnel->config->plugin) {
			args[i++] = "plugin";
			args[i++] = tunnel->config->plugin;
		}

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
		if (strstr(ifa->ifa_name, "ppp") != NULL
		    && ifa->ifa_flags & IFF_UP) {
			strncpy(tunnel->ppp_iface, ifa->ifa_name,
				ROUTE_IFACE_LEN - 1);
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

	tunnel->config->gateway_ip = *((struct in_addr *)
				       host->h_addr_list[0]);
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

	ret = connect(handle, (struct sockaddr *) &server, sizeof(server));
	if (ret == -1) {
		log_error("connect: %s\n", strerror(errno));
		return -1;
	}

	return handle;
}

static int ssl_verify_cert(struct tunnel *tunnel)
{
	int ret = -1;
	unsigned char digest[SHA256LEN];
	unsigned len;
	struct x509_digest *elem;
	char digest_str[SHA256STRLEN], *subject, *issuer;
	char *line;
	int i;

	X509 *cert = SSL_get_peer_certificate(tunnel->ssl_handle);
	if (cert == NULL) {
		log_error("Unable to get gateway certificate.\n");
		return 1;
	}

	// Try to validate certificate using local PKI
	if (SSL_get_verify_result(tunnel->ssl_handle) == X509_V_OK) {
		log_debug("Gateway certificate validation succeeded.\n");
		ret = 0;
		goto free_cert;
	}
	log_debug("Gateway certificate validation failed.\n");

	// If validation failed, check if cert is in the white list
	if (X509_digest(cert, EVP_sha256(), digest, &len) <= 0
	    || len != SHA256LEN) {
		log_error("Could not compute certificate sha256 digest.\n");
		goto free_cert;
	}
	// Encode digest in base16
	for (i = 0; i < SHA256LEN; i++)
		sprintf(&digest_str[2 * i], "%02x", digest[i]);
	// Is it in whitelist?
	for (elem = tunnel->config->cert_whitelist; elem != NULL;
	     elem = elem->next)
		if (memcmp(digest_str, elem->data, SHA256STRLEN) == 0)
			break;
	if (elem != NULL) { // break before end of loop
		log_debug("Gateway certificate digest found in white list.\n");
		ret = 0;
		goto free_cert;
	}

	subject = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
	issuer = X509_NAME_oneline(X509_get_issuer_name(cert), NULL, 0);

	log_error("Gateway certificate validation failed, and the certificate "
		  "digest in not in the local whitelist. If you trust it, "
		  "rerun with:\n");
	log_error("    --trusted-cert %s\n", digest_str);
	log_error("or add this line to your config file:\n");
	log_error("    trusted-cert = %s\n", digest_str);
	log_error("Gateway certificate:\n");
	log_error("    subject:\n");
	for (line = strtok(subject, "/"); line != NULL;
	     line = strtok(NULL, "/"))
		log_error("        %s\n", line);
	log_error("    issuer:\n");
	for (line = strtok(issuer, "/"); line != NULL;
	     line = strtok(NULL, "/"))
		log_error("        %s\n", line);
	log_error("    sha256 digest:\n");
	log_error("        %s\n", digest_str);

free_cert:
	X509_free(cert);
	return ret;
}

/*
 * Destroy and free the SSL connection to the gateway.
 */
static void ssl_disconnect(struct tunnel *tunnel)
{
	if (!tunnel->ssl_handle)
		return;

	SSL_shutdown(tunnel->ssl_handle);
	SSL_free(tunnel->ssl_handle);
	SSL_CTX_free(tunnel->ssl_context);
	close(tunnel->ssl_socket);

	tunnel->ssl_handle = NULL;
	tunnel->ssl_context = NULL;
}

/*
 * Connects to the gateway and initiate a SSL session.
 */
int ssl_connect(struct tunnel *tunnel)
{
	ssl_disconnect (tunnel);

	tunnel->ssl_socket = tcp_connect(tunnel);
	if (tunnel->ssl_socket == -1)
		return 1;

	// Register the error strings for libcrypto & libssl
	SSL_load_error_strings();
	// Register the available ciphers and digests
	SSL_library_init();

	tunnel->ssl_context = SSL_CTX_new(SSLv23_client_method());
	if (tunnel->ssl_context == NULL) {
		log_error("SSL_CTX_new: %s\n",
			  ERR_error_string(ERR_peek_last_error(), NULL));
		return 1;
	}

	tunnel->ssl_handle = SSL_new(tunnel->ssl_context);
	if (tunnel->ssl_handle == NULL) {
		log_error("SSL_new: %s\n",
			  ERR_error_string(ERR_peek_last_error(), NULL));
		return 1;
	}

	if (!SSL_set_fd(tunnel->ssl_handle, tunnel->ssl_socket)) {
		log_error("SSL_set_fd: %s\n",
			  ERR_error_string(ERR_peek_last_error(), NULL));
		return 1;
	}
	SSL_set_mode(tunnel->ssl_handle, SSL_MODE_AUTO_RETRY);

	// Initiate SSL handshake
	if (SSL_connect(tunnel->ssl_handle) != 1) {
		log_error("SSL_connect: %s\n",
			  ERR_error_string(ERR_peek_last_error(), NULL));
		return 1;
	}
	SSL_set_mode(tunnel->ssl_handle, SSL_MODE_AUTO_RETRY);

	if (tunnel->config->verify_cert)
		if (ssl_verify_cert(tunnel))
			return 1;

	// Disable SIGPIPE (occurs when trying to write to an already-closed
	// socket).
	signal(SIGPIPE, SIG_IGN);

	return 0;
}

int run_tunnel(struct vpn_config *config)
{
	int ret;
	struct tunnel tunnel;

	tunnel.config = config;
	tunnel.on_ppp_if_up = on_ppp_if_up;
	tunnel.on_ppp_if_down = on_ppp_if_down;
	tunnel.ipv4.ns1_addr.s_addr = 0;
	tunnel.ipv4.ns2_addr.s_addr = 0;
	tunnel.ssl_handle = NULL;
	tunnel.ssl_context = NULL;

	tunnel.state = STATE_DOWN;

	// Step 0: get gateway host IP
	ret = get_gateway_host_ip(&tunnel);
	if (ret)
		goto err_tunnel;

	// Step 1: open a SSL connection to the gateway
	ret = ssl_connect(&tunnel);
	if (ret)
		goto err_tunnel;
	log_info("Connected to gateway.\n");

	// Step 2: connect to the HTTP interface and authenticate to get a
	// cookie
	ret = auth_log_in(&tunnel);
	if (ret != 1) {
		log_error("Could not authenticate to gateway (%s).\n",
			  err_http_str(ret));
		ret = 1;
		goto err_tunnel;
	}
	log_info("Authenticated.\n");
	log_debug("Cookie: %s\n", config->cookie);

	ret = auth_request_vpn_allocation(&tunnel);
	if (ret != 1) {
		log_error("VPN allocation request failed (%s).\n",
			  err_http_str(ret));
		ret = 1;
		goto err_tunnel;
	}
	log_info("Remote gateway has allocated a VPN.\n");

	// Step 3: run a pppd process
	ret = pppd_run(&tunnel);
	if (ret)
		goto err_tunnel;

	// Step 4: ask gateway to start tunneling
	ret = ssl_connect(&tunnel);
	if (ret)
		goto err_tunnel;
	ret = http_send(&tunnel, "GET /remote/sslvpn-tunnel HTTP/1.1\r\n"
				 "Host: sslvpn\r\n"
				 "Cookie: %s\r\n"
				 "Connection: Keep-Alive\r\n\r\n",
			tunnel.config->cookie);
	if (ret != 1) {
		log_error("Could not start tunnel (%s).\n", err_http_str(ret));
		ret = 1;
		goto err_start_tunnel;
	}

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
err_tunnel:
	log_info("Closed connection to gateway.\n");
	tunnel.state = STATE_DOWN;

	if (ssl_connect(&tunnel)) {
		log_info("Could not log out.\n");
	} else {
		auth_log_out(&tunnel);
		log_info("Logged out.\n");
	}

	return ret;
}
