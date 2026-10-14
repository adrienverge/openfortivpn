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
 *  Windows tunnel lifecycle implementation.
 *  Replaces tunnel.c for Windows builds, using wintun instead of pppd.
 */

#ifdef _WIN32

#include "tunnel.h"
#include "http.h"
#include "ppp.h"
#include "wintun.h"
#include "log.h"
#include "userinput.h"
#include "ssl.h"
#include "event.h"
#include "exit_codes.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>

#include <openssl/err.h>
#include <openssl/x509v3.h>

#include <stdio.h>
#include <string.h>
#include <assert.h>

/* Wintun session ring buffer size: 4 MB */
#define WINTUN_RING_CAPACITY 0x400000

/* Adapter name visible in Windows Network Connections */
#define ADAPTER_NAME L"openfortivpn"
#define TUNNEL_TYPE  L"openfortivpn"


static struct wintun_api wt_api;
static int wt_api_loaded;

/*
 * Load wintun.dll and create a TUN adapter.
 */
static int wintun_create(struct tunnel *tunnel)
{
	WINTUN_ADAPTER_HANDLE adapter;
	WINTUN_SESSION_HANDLE session;
	NET_LUID luid;

	if (!wt_api_loaded) {
		if (wintun_load(&wt_api) != 0) {
			log_error("Failed to load wintun.dll. Please ensure wintun.dll is in the application directory or system PATH.\n");
			return 1;
		}
		wt_api_loaded = 1;

		DWORD ver = wt_api.GetRunningDriverVersion();

		log_info("Loaded wintun.dll (driver version %u.%u)\n",
		         (ver >> 16) & 0xffff, ver & 0xffff);
	}

	/* Create the adapter */
	adapter = wt_api.CreateAdapter(ADAPTER_NAME, TUNNEL_TYPE, NULL);
	if (!adapter) {
		log_error("Failed to create wintun adapter (error %lu).\nEnsure you are running as Administrator.\n",
		          GetLastError());
		return 1;
	}

	/* Get the adapter LUID for routing */
	wt_api.GetAdapterLUID(adapter, &luid);
	ipv4_win_set_tun_luid(&luid);

	/* Start a session */
	session = wt_api.StartSession(adapter, WINTUN_RING_CAPACITY);
	if (!session) {
		log_error("Failed to start wintun session (error %lu).\n",
		          GetLastError());
		wt_api.CloseAdapter(adapter);
		return 1;
	}

	/*
	 * Store handles in tunnel struct.
	 * tun_adapter stores a pointer to the static wt_api struct
	 * (which contains the function pointers AND the adapter handle),
	 * tun_session stores the session handle.
	 */
	tunnel->tun_adapter = (void *)&wt_api;
	tunnel->tun_session = (void *)session;

	log_info("Wintun adapter created.\n");
	return 0;
}

/*
 * Configure IP address on the wintun adapter.
 */
static int wintun_configure_ip(struct tunnel *tunnel)
{
	MIB_UNICASTIPADDRESS_ROW addr_row;
	NET_LUID luid;
	DWORD ret;
	char ip_str[INET_ADDRSTRLEN];

	/* Use netsh to set the IP address (most reliable approach) */
	inet_ntop(AF_INET, &tunnel->ipv4.ip_addr, ip_str, sizeof(ip_str));

	char cmd[256];

	snprintf(cmd, sizeof(cmd),
	         "netsh interface ipv4 set address name=\"openfortivpn\" static %s 255.255.255.255",
	         ip_str);
	log_debug("Running: %s\n", cmd);
	ret = system(cmd);
	if (ret != 0)
		log_warn("Failed to set IP address on adapter.\n");

	/* Set MTU to match PPP MRU */
	snprintf(cmd, sizeof(cmd),
	         "netsh interface ipv4 set subinterface \"openfortivpn\" mtu=1354 store=active");
	log_debug("Running: %s\n", cmd);
	system(cmd);

	return 0;
}

static void wintun_destroy(struct tunnel *tunnel)
{
	if (tunnel->tun_session) {
		wt_api.EndSession((WINTUN_SESSION_HANDLE)tunnel->tun_session);
		tunnel->tun_session = NULL;
	}

	/* Close adapter - remove it from Windows */
	/* Note: adapter handle is managed via wt_api, not stored separately */

	log_info("Wintun adapter destroyed.\n");
}

/*
 * TCP connection to the VPN gateway.
 */
static int tcp_connect(struct tunnel *tunnel)
{
	SOCKET sock;
	struct addrinfo hints, *result = NULL;
	char port_str[6];
	int ret;
	char ip_str[INET_ADDRSTRLEN];

	inet_ntop(AF_INET, &tunnel->config->gateway_ip,
	          ip_str, sizeof(ip_str));
	snprintf(port_str, sizeof(port_str), "%u",
	         tunnel->config->gateway_port);

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	ret = getaddrinfo(ip_str, port_str, &hints, &result);
	if (ret != 0) {
		log_error("getaddrinfo: %s\n", gai_strerror(ret));
		return -1;
	}

	sock = socket(result->ai_family, result->ai_socktype,
	              result->ai_protocol);
	if (sock == INVALID_SOCKET) {
		log_error("socket: %d\n", WSAGetLastError());
		freeaddrinfo(result);
		return -1;
	}

	ret = connect(sock, result->ai_addr, (int)result->ai_addrlen);
	freeaddrinfo(result);
	if (ret == SOCKET_ERROR) {
		log_error("connect: %d\n", WSAGetLastError());
		closesocket(sock);
		return -1;
	}

	tunnel->ssl_socket = (int)sock;
	return 0;
}

/*
 * SSL/TLS connection to the gateway.
 */
int ssl_connect(struct tunnel *tunnel)
{
	int ret;

	/* Disconnect any existing SSL connection */
	if (tunnel->ssl_handle) {
		SSL_shutdown(tunnel->ssl_handle);
		SSL_free(tunnel->ssl_handle);
		tunnel->ssl_handle = NULL;
	}
	if (tunnel->ssl_context) {
		SSL_CTX_free(tunnel->ssl_context);
		tunnel->ssl_context = NULL;
	}
	if (tunnel->ssl_socket >= 0) {
		closesocket(tunnel->ssl_socket);
		tunnel->ssl_socket = -1;
	}

	/* TCP connect */
	ret = tcp_connect(tunnel);
	if (ret)
		return ret;

	/* Set up SSL context */
	tunnel->ssl_context = SSL_CTX_new(SSLv23_client_method());
	if (!tunnel->ssl_context) {
		log_error("SSL_CTX_new failed.\n");
		return 1;
	}

	/* Set minimum TLS version if configured */
	if (tunnel->config->min_tls > 0)
		SSL_CTX_set_min_proto_version(tunnel->ssl_context,
		                              tunnel->config->min_tls);

	/* Disable insecure protocols unless explicitly requested */
	if (!tunnel->config->insecure_ssl) {
		SSL_CTX_set_options(tunnel->ssl_context,
		                    SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
	}

	/* Load CA certificate if specified */
	if (tunnel->config->ca_file) {
		if (!SSL_CTX_load_verify_locations(tunnel->ssl_context,
		                                   tunnel->config->ca_file,
		                                   NULL)) {
			log_error("Could not load CA certificate: %s\n",
			          tunnel->config->ca_file);
		}
	} else {
		SSL_CTX_set_default_verify_paths(tunnel->ssl_context);
	}

	/* Load client certificate if specified */
	if (tunnel->config->user_cert) {
		if (SSL_CTX_use_certificate_file(tunnel->ssl_context,
		                                 tunnel->config->user_cert,
		                                 SSL_FILETYPE_PEM) != 1) {
			log_error("Could not load user certificate.\n");
		}
	}

	if (tunnel->config->user_key) {
		if (SSL_CTX_use_PrivateKey_file(tunnel->ssl_context,
		                                tunnel->config->user_key,
		                                SSL_FILETYPE_PEM) != 1) {
			log_error("Could not load user private key.\n");
		}
	}

	/* Set cipher list if specified */
	if (tunnel->config->cipher_list) {
		SSL_CTX_set_cipher_list(tunnel->ssl_context,
		                        tunnel->config->cipher_list);
	}

	/* Create SSL connection */
	tunnel->ssl_handle = SSL_new(tunnel->ssl_context);
	if (!tunnel->ssl_handle) {
		log_error("SSL_new failed.\n");
		return 1;
	}

	SSL_set_fd(tunnel->ssl_handle, tunnel->ssl_socket);

	/* Set SNI */
	{
		const char *sni = tunnel->config->sni[0] ?
		                  tunnel->config->sni :
		                  tunnel->config->gateway_host;
		SSL_set_tlsext_host_name(tunnel->ssl_handle, sni);
	}

	ret = SSL_connect(tunnel->ssl_handle);
	if (ret != 1) {
		log_error("SSL_connect failed: %s\n",
		          ERR_error_string(ERR_get_error(), NULL));
		return 1;
	}

	/* Verify server certificate */
	if (!tunnel->config->insecure_ssl) {
		long verify_result = SSL_get_verify_result(tunnel->ssl_handle);

		if (verify_result != X509_V_OK) {
			X509 *cert = SSL_get_peer_certificate(tunnel->ssl_handle);

			if (cert) {
				/* Check against trusted cert whitelist */
				unsigned char digest[32];
				unsigned int digest_len = sizeof(digest);
				char digest_str[65];
				struct x509_digest *trusted;
				int found = 0;

				X509_digest(cert, EVP_sha256(), digest,
				            &digest_len);
				for (unsigned int i = 0; i < digest_len; i++)
					sprintf(&digest_str[i * 2], "%02x",
					        digest[i]);
				digest_str[64] = '\0';

				for (trusted = tunnel->config->cert_whitelist;
				     trusted; trusted = trusted->next) {
					if (strcasecmp(trusted->data,
					               digest_str) == 0) {
						found = 1;
						break;
					}
				}

				X509_free(cert);

				if (!found) {
					log_error("Server certificate verification failed.\n");
					log_error("Certificate digest: %s\n",
					          digest_str);
					event_emit_cert_error(digest_str,
					                      "verification_failed");
					return OFV_EXIT_CERT_FAILED;
				}
				log_debug("Trusted certificate matched.\n");
			} else {
				log_error("No server certificate received.\n");
				return 1;
			}
		}
	}

	return 0;
}

static void ssl_disconnect(struct tunnel *tunnel)
{
	if (tunnel->ssl_handle) {
		SSL_shutdown(tunnel->ssl_handle);
		SSL_free(tunnel->ssl_handle);
		tunnel->ssl_handle = NULL;
	}
	if (tunnel->ssl_context) {
		SSL_CTX_free(tunnel->ssl_context);
		tunnel->ssl_context = NULL;
	}
	if (tunnel->ssl_socket >= 0) {
		closesocket(tunnel->ssl_socket);
		tunnel->ssl_socket = -1;
	}
}

/*
 * Resolve gateway hostname to IP address.
 */
static int get_gateway_host_ip(struct tunnel *tunnel)
{
	struct addrinfo hints, *result = NULL;
	int ret;

	if (tunnel->config->gateway_ip.s_addr != 0)
		return 0;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;

	ret = getaddrinfo(tunnel->config->gateway_host, NULL, &hints, &result);
	if (ret != 0 || !result) {
		log_error("Could not resolve host: %s\n",
		          tunnel->config->gateway_host);
		event_emit_error(OFV_EXIT_DNS_FAILED, "dns",
		                 "Could not resolve host");
		return 1;
	}

	tunnel->config->gateway_ip =
	        ((struct sockaddr_in *)result->ai_addr)->sin_addr;
	freeaddrinfo(result);

	{
		char ip_str[INET_ADDRSTRLEN];

		inet_ntop(AF_INET, &tunnel->config->gateway_ip,
		          ip_str, sizeof(ip_str));
		log_info("Gateway IP: %s\n", ip_str);
		event_emit("gateway_resolved", "\"ip\":\"%s\"", ip_str);
	}

	return 0;
}

/*
 * Callback when PPP interface comes up.
 */
static int on_ppp_if_up(struct tunnel *tunnel)
{
	struct ppp_context *ctx = (struct ppp_context *)tunnel->ppp_ctx;

	log_info("Tunnel interface is UP.\n");

	/* Copy negotiated IPs from PPP context to tunnel ipv4 config */
	memcpy(&tunnel->ipv4.ip_addr.s_addr, &ctx->local_ip, 4);
	memcpy(&tunnel->ipv4.ns1_addr.s_addr, &ctx->dns_primary, 4);
	memcpy(&tunnel->ipv4.ns2_addr.s_addr, &ctx->dns_secondary, 4);

	{
		char ip_str[INET_ADDRSTRLEN];

		inet_ntop(AF_INET, &tunnel->ipv4.ip_addr,
		          ip_str, sizeof(ip_str));
		log_info("Assigned IP: %s\n", ip_str);
		{
			char dns1_str[INET_ADDRSTRLEN] = "";
			char dns2_str[INET_ADDRSTRLEN] = "";

			inet_ntop(AF_INET, &tunnel->ipv4.ns1_addr,
			          dns1_str, sizeof(dns1_str));
			inet_ntop(AF_INET, &tunnel->ipv4.ns2_addr,
			          dns2_str, sizeof(dns2_str));
			event_emit_tunnel_up(ip_str, dns1_str,
			                     dns2_str);
		}
	}

	/* Configure IP on the wintun adapter */
	wintun_configure_ip(tunnel);

	/* Set up routes */
	if (tunnel->config->set_routes) {
		int ret = ipv4_set_tunnel_routes(tunnel);

		if (ret)
			log_warn("Could not set VPN routes.\n");
	}

	/* Set up DNS */
	if (tunnel->config->set_dns) {
		int ret = ipv4_add_nameservers_to_resolv_conf(tunnel);

		if (ret)
			log_warn("Could not configure DNS.\n");
	}

	return 0;
}

/*
 * Callback when PPP interface goes down.
 */
static int on_ppp_if_down(struct tunnel *tunnel)
{
	log_info("Tunnel interface is DOWN.\n");
	event_emit("tunnel_down", "\"reason\":\"interface_down\"");

	if (tunnel->config->set_dns)
		ipv4_del_nameservers_from_resolv_conf(tunnel);

	if (tunnel->config->set_routes)
		ipv4_restore_routes(tunnel);

	return 0;
}

int run_tunnel(struct vpn_config *config)
{
	int ret;
	struct ppp_context ppp_ctx;
	struct tunnel tunnel = {
		.config = config,
		.state = STATE_DOWN,
		.ssl_socket = -1,
		.ssl_context = NULL,
		.ssl_handle = NULL,
		.tun_adapter = NULL,
		.tun_session = NULL,
		.ppp_ctx = NULL,
		.ipv4.ns1_addr.s_addr = 0,
		.ipv4.ns2_addr.s_addr = 0,
		.ipv4.dns_suffix = NULL,
		.on_ppp_if_up = on_ppp_if_up,
		.on_ppp_if_down = on_ppp_if_down
	};

	/* Initialize PPP state machine */
	ppp_init(&ppp_ctx);
	tunnel.ppp_ctx = (void *)&ppp_ctx;

	/* Step 0: resolve gateway */
	event_emit("state_change", "\"state\":\"resolving\"");
	log_debug("Resolving gateway host ip\n");
	ret = get_gateway_host_ip(&tunnel);
	if (ret) {
		ret = OFV_EXIT_DNS_FAILED;
		goto err_tunnel;
	}

	/* Step 1: TLS connection */
	event_emit("state_change", "\"state\":\"connecting_tls\"");
	log_debug("Establishing TLS connection\n");
	ret = ssl_connect(&tunnel);
	if (ret) {
		if (ret != OFV_EXIT_CERT_FAILED)
			ret = OFV_EXIT_TLS_FAILED;
		goto err_tunnel;
	}
	log_info("Connected to gateway.\n");

	/* Step 2: authenticate */
	event_emit("state_change", "\"state\":\"authenticating\"");
	if (config->cookie)
		ret = auth_set_cookie(&tunnel, config->cookie);
	else
		ret = auth_log_in(&tunnel);
	if (ret != 1) {
		log_error("Could not authenticate to gateway.\n");
		ret = OFV_EXIT_AUTH_FAILED;
		goto err_tunnel;
	}
	log_info("Authenticated.\n");
	event_emit("state_change", "\"state\":\"allocating\"");

	ret = auth_request_vpn_allocation(&tunnel);
	if (ret != 1) {
		log_error("VPN allocation request failed.\n");
		ret = OFV_EXIT_ALLOC_DENIED;
		goto err_tunnel;
	}
	log_info("Remote gateway has allocated a VPN.\n");
	event_emit("state_change", "\"state\":\"configuring\"");

	ret = ssl_connect(&tunnel);
	if (ret) {
		if (ret != OFV_EXIT_CERT_FAILED)
			ret = OFV_EXIT_TLS_FAILED;
		goto err_tunnel;
	}

	/* Step 3: get VPN configuration */
	log_debug("Retrieving configuration\n");
	ret = auth_get_config(&tunnel);
	if (ret != 1) {
		log_error("Could not get VPN configuration.\n");
		ret = OFV_EXIT_CONFIG_FAILED;
		goto err_tunnel;
	}

	/* Step 4: create wintun adapter (replaces pppd_run) */
	event_emit("state_change", "\"state\":\"creating_adapter\"");
	log_debug("Creating wintun adapter\n");
	ret = wintun_create(&tunnel);
	if (ret) {
		ret = OFV_EXIT_ADAPTER_FAILED;
		goto err_tunnel;
	}

	/* Step 5: switch to tunnel mode */
	event_emit("state_change", "\"state\":\"tunneling\"");
	log_debug("Switch to tunneling mode\n");
	ret = http_send(&tunnel,
	                "GET /remote/sslvpn-tunnel HTTP/1.1\r\nHost: sslvpn\r\nCookie: %s\r\n\r\n",
	                tunnel.cookie);
	if (ret != 1) {
		log_error("Could not start tunnel.\n");
		ret = OFV_EXIT_TUNNEL_FAILED;
		goto err_start_tunnel;
	}

	tunnel.state = STATE_CONNECTING;

	/* Step 6: I/O loop (PPP negotiation + packet forwarding) */
	event_emit("state_change", "\"state\":\"connected\"");
	log_debug("Starting IO through the tunnel\n");
	io_loop(&tunnel);

	event_emit("state_change", "\"state\":\"disconnecting\"");
	log_debug("Disconnecting\n");
	if (tunnel.state == STATE_UP)
		if (tunnel.on_ppp_if_down != NULL)
			tunnel.on_ppp_if_down(&tunnel);

	tunnel.state = STATE_DISCONNECTING;

err_start_tunnel:
	wintun_destroy(&tunnel);
	log_info("Destroyed wintun adapter.\n");

err_tunnel:
	log_info("Closed connection to gateway.\n");
	tunnel.state = STATE_DOWN;

	if (ssl_connect(&tunnel) == 0) {
		auth_log_out(&tunnel);
		log_info("Logged out.\n");
		ssl_disconnect(&tunnel);
	} else {
		log_info("Could not log out.\n");
	}

	if (tunnel.ipv4.split_rt != NULL) {
		free(tunnel.ipv4.split_rt);
		tunnel.ipv4.split_rt = NULL;
	}
	return ret;
}

#endif /* _WIN32 */
