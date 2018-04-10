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
 *
 *  In addition, as a special exception, the copyright holders give permission
 *  to link the code of portions of this program with the OpenSSL library under
 *  certain conditions as described in each individual source file, and
 *  distribute linked combinations including the two.
 *  You must obey the GNU General Public License in all respects for all of the
 *  code used other than OpenSSL.  If you modify file(s) with this exception,
 *  you may extend this exception to your version of the file(s), but you are
 *  not obligated to do so.  If you do not wish to do so, delete this exception
 *  statement from your version.  If you delete this exception statement from
 *  all source files in the program, then also delete it here.
 */

#include "tunnel.h"
#include "http.h"
#include "log.h"

#include <unistd.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <errno.h>
#include <string.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#ifdef __APPLE__
#include <util.h>
#else
#include <pty.h>
#endif
#include <signal.h>
#include <sys/wait.h>
#include <assert.h>


static int on_ppp_if_up(struct tunnel *tunnel)
{
	log_info("Interface %s is UP.\n", tunnel->ppp_iface);

	if (tunnel->config->set_routes) {
		int ret;

		log_info("Setting new routes...\n");

		ret = ipv4_set_tunnel_routes(tunnel);

		if (ret != 0) {
			log_warn("Adding route table is incomplete. Please check route table.\n");
		}
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
#ifndef __APPLE__
	struct termios termp = {
		.c_cflag = B9600,
		.c_cc[VTIME] = 0,
		.c_cc[VMIN] = 1
	};
#endif

	static const char pppd_path[] = "/usr/sbin/pppd";

	if (access(pppd_path, F_OK) != 0) {
		log_error("%s: %s.\n", pppd_path, strerror(errno));
		return 1;
	}

#ifdef __APPLE__
	pid = forkpty(&amaster, NULL, NULL, NULL);
#else
	pid = forkpty(&amaster, NULL, &termp, NULL);
#endif

	if (pid == -1) {
		log_error("forkpty: %s\n", strerror(errno));
		return 1;
	} else if (pid == 0) { // child process
		static const char *args[] = {
			pppd_path,
			"38400", // speed
			":192.0.2.1", // <local_IP_address>:<remote_IP_address>
			"noipdefault",
			"noaccomp",
			"noauth",
			"default-asyncmap",
			"nopcomp",
			"receive-all",
			"nodefaultroute",
			"nodetach",
			"lcp-max-configure", "40",
			"mru", "1354",
			NULL, // "usepeerdns"
			NULL, NULL, NULL, // "debug", "logfile", pppd_log
			NULL, NULL, // "plugin", pppd_plugin
			NULL, NULL, // "ipparam", pppd_ipparam
			NULL, NULL, // "ifname", pppd_ifname
			NULL // terminal null pointer required by execvp()
		};

		if (tunnel->config->pppd_call) {
			/* overwrite args[]: keep pppd_path, replace all
			 * options with "call <name>" */
			int j = 1;
			args[j++] = "call";
			args[j++] = tunnel->config->pppd_call;
			while (j < ARRAY_SIZE(args))
				args[j++] = NULL;
		}

		// Dynamically get first NULL pointer so that changes of
		// args above don't need code changes here
		int i = ARRAY_SIZE(args) - 1;
		while (args[i] == NULL)
			i--;
		i++;

		/*
		 * Coverity detected a defect:
		 * 	CID 196857: Out-of-bounds write (OVERRUN)
		 *
		 * It is actually a false positive:
		 * Although 'args' is  constant, Coverity is unable
		 * to infer there are enough NULL elements in 'args'
		 * to add the following options.
		 */
		if (tunnel->config->pppd_use_peerdns)
			args[i++] = "usepeerdns";
		if (tunnel->config->pppd_log) {
			args[i++] = "debug";
			args[i++] = "logfile";
			args[i++] = tunnel->config->pppd_log;
		}
		if (tunnel->config->pppd_plugin) {
			args[i++] = "plugin";
			args[i++] = tunnel->config->pppd_plugin;
		}
		if (tunnel->config->pppd_ipparam) {
			args[i++] = "ipparam";
			args[i++] = tunnel->config->pppd_ipparam;
		}
		if (tunnel->config->pppd_ifname) {
			args[i++] = "ifname";
			args[i++] = tunnel->config->pppd_ifname;
		}
		// Assert that we didn't use up all NULL pointers above
		assert(i < ARRAY_SIZE(args));

		close(tunnel->ssl_socket);
		execv(args[0], (char *const *)args);
		/*
		 * The following call to fprintf() doesn't work, probably
		 * because of the prior call to forkpty().
		 * TODO: print a meaningful message using strerror(errno)
		 */
		fprintf(stderr, "execvp: %s\n", strerror(errno));
		_exit(EXIT_FAILURE);
	}

	// Set non-blocking
	int flags = fcntl(amaster, F_GETFL, 0);
	if (flags == -1)
		flags = 0;
	if (fcntl(amaster, F_SETFL, flags | O_NONBLOCK) == -1) {
		log_error("fcntl: %s\n", strerror(errno));
		return 1;
	}

	tunnel->pppd_pid = pid;
	tunnel->pppd_pty = amaster;

	return 0;
}

static const char * const pppd_message[] = {
	"Has detached, or otherwise the connection was successfully established and terminated at the peer's request.",
	"An immediately fatal error of some kind occurred, such as an essential system call failing, or running out of virtual memory.",
	"An error was detected in processing the options given, such as two mutually exclusive options being used.",
	"Is not setuid-root and the invoking user is not root.",
	"The kernel does not support PPP, for example, the PPP kernel driver is not included or cannot be loaded.",
	"Terminated because it was sent a SIGINT, SIGTERM or SIGHUP signal.",
	"The serial port could not be locked.",
	"The serial port could not be opened.",
	"The connect script failed (returned a non-zero exit status).",
	"The command specified as the argument to the pty option could not be run.",
	"The PPP negotiation failed, that is, it didn't reach the point where at least one network protocol (e.g. IP) was running.",
	"The peer system failed (or refused) to authenticate itself.",
	"The link was established successfully and terminated because it was idle.",
	"The link was established successfully and terminated because the connect time limit was reached.",
	"Callback was negotiated and an incoming call should arrive shortly.",
	"The link was terminated because the peer is not responding to echo requests.",
	"The link was terminated by the modem hanging up.",
	"The PPP negotiation failed because serial loopback was detected.",
	"The init script failed (returned a non-zero exit status).",
	"We failed to authenticate ourselves to the peer."
};

static int pppd_terminate(struct tunnel *tunnel)
{
	close(tunnel->pppd_pty);

	log_debug("Waiting for pppd to exit...\n");
	int status;
	if (waitpid(tunnel->pppd_pid, &status, 0) == -1) {
		log_error("waitpid: %s\n", strerror(errno));
		return 1;
	}
	if (WIFEXITED(status)) {
		int exit_status = WEXITSTATUS(status);
		log_debug("waitpid: pppd exit status code %d\n", exit_status);
		if (exit_status >= ARRAY_SIZE(pppd_message) || exit_status < 0)
			log_error("pppd: Returned an unknown exit status: %d\n",
			          exit_status);
		else
			switch (exit_status) {
			case 0: // success
				log_debug("pppd: %s\n", pppd_message[exit_status]);
				break;
			case 16: // emitted when exiting normally
				log_info("pppd: %s\n", pppd_message[exit_status]);
				break;
			default:
				log_error("pppd: %s\n", pppd_message[exit_status]);
				break;
			}
	} else if (WIFSIGNALED(status)) {
		int signal_number = WTERMSIG(status);
		log_debug("waitpid: pppd terminated by signal %d\n",
		          signal_number);
		log_error("pppd: terminated by signal: %s\n",
		          strsignal(signal_number));
	}

	return 0;
}

int ppp_interface_is_up(struct tunnel *tunnel)
{
	struct ifaddrs *ifap, *ifa;

	log_debug("Got Address: %s\n", inet_ntoa(tunnel->ipv4.ip_addr));

	if (getifaddrs(&ifap)) {
		log_error("getifaddrs: %s\n", strerror(errno));
		return 0;
	}

	for (ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
		if (((tunnel->config->pppd_ifname
		      && strstr(ifa->ifa_name, tunnel->config->pppd_ifname) != NULL)
		     || strstr(ifa->ifa_name, "ppp") != NULL)
		    && ifa->ifa_flags & IFF_UP) {
			if (&(ifa->ifa_addr->sa_family) != NULL
			    && ifa->ifa_addr->sa_family == AF_INET) {
				struct in_addr if_ip_addr =
				        cast_addr(ifa->ifa_addr)->sin_addr;

				log_debug("Interface Name: %s\n", ifa->ifa_name);
				log_debug("Interface Addr: %s\n", inet_ntoa(if_ip_addr));

				if (tunnel->ipv4.ip_addr.s_addr == if_ip_addr.s_addr) {
					strncpy(tunnel->ppp_iface, ifa->ifa_name,
					        ROUTE_IFACE_LEN - 1);
					freeifaddrs(ifap);
					return 1;
				}
			}
		}
	}
	freeifaddrs(ifap);

	return 0;
}

static int get_gateway_host_ip(struct tunnel *tunnel)
{
	const struct addrinfo hints = { .ai_family = AF_INET };
	struct addrinfo *result = NULL;

	int ret = getaddrinfo(tunnel->config->gateway_host, NULL, &hints, &result);

	if (ret) {
		if (ret == EAI_SYSTEM)
			log_error("getaddrinfo: %s\n", strerror(errno));
		else
			log_error("getaddrinfo: %s\n", gai_strerror(ret));
		return 1;
	}

	tunnel->config->gateway_ip = ((struct sockaddr_in *)
	                              result->ai_addr)->sin_addr;
	freeaddrinfo(result);

	setenv("VPN_GATEWAY", inet_ntoa(tunnel->config->gateway_ip), 0);

	return 0;
}

/*
 * Establish a regular TCP connection.
 */
static int tcp_connect(struct tunnel *tunnel)
{
	int ret, handle;
	struct sockaddr_in server;
	char *env_proxy;

	handle = socket(AF_INET, SOCK_STREAM, 0);
	if (handle == -1) {
		log_error("socket: %s\n", strerror(errno));
		goto err_socket;
	}
	env_proxy = getenv("https_proxy");
	if (env_proxy == NULL)
		env_proxy = getenv("HTTPS_PROXY");
	if (env_proxy == NULL)
		env_proxy = getenv("all_proxy");
	if (env_proxy == NULL)
		env_proxy = getenv("ALL_PROXY");
	if (env_proxy != NULL) {
		char *proxy_host, *proxy_port;
		// protect the original environment from modifications
		env_proxy = strdup(env_proxy);
		if (env_proxy == NULL) {
			log_error("strdup: %s\n", strerror(errno));
			goto err_strdup;
		}
		// get rid of a trailing slash
		if (*env_proxy && env_proxy[strlen(env_proxy) - 1] == '/')
			env_proxy[strlen(env_proxy) - 1] = '\0';
		// get rid of a http(s):// prefix in env_proxy
		proxy_host = strstr(env_proxy, "://");
		if (proxy_host == NULL)
			proxy_host = env_proxy;
		else
			proxy_host += 3;
		// split host and port
		proxy_port = index(proxy_host, ':');
		if (proxy_port != NULL) {
			proxy_port[0] = '\0';
			proxy_port++;
			server.sin_port = htons(strtol(proxy_port, NULL, 10));
		} else {
			server.sin_port = htons(tunnel->config->gateway_port);
		}
		// get rid of a trailing slash
		if (*proxy_host && proxy_host[strlen(proxy_host) - 1] == '/')
			proxy_host[strlen(proxy_host) - 1] = '\0';
		log_debug("proxy_host: %s\n", proxy_host);
		log_debug("proxy_port: %s\n", proxy_port);
		server.sin_addr.s_addr = inet_addr(proxy_host);
		// if host is given as fqhn we have to do a dns lookup
		if (server.sin_addr.s_addr == INADDR_NONE) {
			const struct addrinfo hints = { .ai_family = AF_INET };
			struct addrinfo *result = NULL;

			ret = getaddrinfo(proxy_host, NULL, &hints, &result);
			if (ret) {
				if (ret == EAI_SYSTEM)
					log_error("getaddrinfo: %s\n", strerror(errno));
				else
					log_error("getaddrinfo: %s\n", gai_strerror(ret));
				goto err_connect;
			}

			server.sin_addr = ((struct sockaddr_in *)
			                   result->ai_addr)->sin_addr;
			freeaddrinfo(result);
		}
	} else {
		server.sin_port = htons(tunnel->config->gateway_port);
		server.sin_addr = tunnel->config->gateway_ip;
	}

	log_debug("server_addr: %s\n", inet_ntoa(server.sin_addr));
	log_debug("server_port: %u\n", ntohs(server.sin_port));
	server.sin_family = AF_INET;
	memset(&(server.sin_zero), '\0', 8);
	log_debug("gateway_addr: %s\n", inet_ntoa(tunnel->config->gateway_ip));
	log_debug("gateway_port: %u\n", tunnel->config->gateway_port);

	ret = connect(handle, (struct sockaddr *) &server, sizeof(server));
	if (ret) {
		log_error("connect: %s\n", strerror(errno));
		goto err_connect;
	}

	if (env_proxy != NULL) {
		char request[128];

		// https://tools.ietf.org/html/rfc7231#section-4.3.6
		sprintf(request, "CONNECT %s:%u HTTP/1.1\r\nHost: %s:%u\r\n\r\n",
		        inet_ntoa(tunnel->config->gateway_ip),
		        tunnel->config->gateway_port,
		        inet_ntoa(tunnel->config->gateway_ip),
		        tunnel->config->gateway_port);
		ssize_t bytes_written = write(handle, request, strlen(request));
		if (bytes_written != strlen(request)) {
			log_error("write error while talking to proxy: %s\n",
			          strerror(errno));
			goto err_connect;
		}

		// wait for a "200 OK" reply from the proxy,
		// be careful not to fetch too many bytes at once
		const char *response = NULL;

		memset(&(request), '\0', sizeof(request));
		for (int j = 0; response == NULL; j++) {
			/*
			 * Coverity detected a defect:
			 *  CID 200508: String not null terminated (STRING_NULL)
			 *
			 * It is actually a false positive:
			 * • Function memset() initializes 'request' with '\0'
			 * • Function read() gets a single char into: request[j]
			 * • The final '\0' cannot be overwritten because:
			 *   	j < ARRAY_SIZE(request) - 1
			 */
			ssize_t bytes_read = read(handle, &(request[j]), 1);
			if (bytes_read < 1) {
				log_error("Proxy response is unexpectedly large and cannot fit in the %d-bytes buffer.\n",
				          ARRAY_SIZE(request));
				goto err_proxy_response;
			}

			// detect "200"
			const char HTTP_STATUS_200[] = "200";
			response = strstr(request, HTTP_STATUS_200);

			// detect end-of-line after "200"
			if (response != NULL) {
				/*
				 * RFC2616 states in section 2.2 Basic Rules:
				 * 	CR     = <US-ASCII CR, carriage return (13)>
				 * 	LF     = <US-ASCII LF, linefeed (10)>
				 * 	HTTP/1.1 defines the sequence CR LF as the
				 * 	end-of-line marker for all protocol elements
				 * 	except the entity-body (see appendix 19.3
				 * 	for tolerant applications).
				 * 		CRLF   = CR LF
				 *
				 * RFC2616 states in section 19.3 Tolerant Applications:
				 * 	The line terminator for message-header fields
				 * 	is the sequence CRLF. However, we recommend
				 * 	that applications, when parsing such headers,
				 * 	recognize a single LF as a line terminator
				 * 	and ignore the leading CR.
				 */
				static const char *HTTP_EOL[] = {
					"\r\n\r\n",
					"\n\n"
				};
				const char *eol = NULL;
				for (int i = 0; (i < ARRAY_SIZE(HTTP_EOL)) &&
				     (eol == NULL); i++)
					eol = strstr(response, HTTP_EOL[i]);
				response = eol;
			}

			if (j > ARRAY_SIZE(request) - 2) {
				log_error("Proxy response does not contain \"%s\" as expected.\n",
				          HTTP_STATUS_200);
				goto err_proxy_response;
			}
		}

		free(env_proxy); // release memory allocated by strdup()
	}

	return handle;

err_proxy_response:
err_connect:
	free(env_proxy); // release memory allocated by strdup()
err_strdup:
	close(handle);
err_socket:
	return -1;
}

static int ssl_verify_cert(struct tunnel *tunnel)
{
	int ret = -1;
	int cert_valid = 0;
	unsigned char digest[SHA256LEN];
	unsigned int len;
	struct x509_digest *elem;
	char digest_str[SHA256STRLEN], *subject, *issuer;
	char *line;
	int i;
	X509_NAME *subj;
	char common_name[FIELD_SIZE + 1];

	SSL_set_verify(tunnel->ssl_handle, SSL_VERIFY_PEER, NULL);

	X509 *cert = SSL_get_peer_certificate(tunnel->ssl_handle);
	if (cert == NULL) {
		log_error("Unable to get gateway certificate.\n");
		return 1;
	}

	subj = X509_get_subject_name(cert);

#ifdef HAVE_X509_CHECK_HOST
	// Use OpenSSL native host validation if v >= 1.0.2.
	if (X509_check_host(cert, common_name, FIELD_SIZE, 0, NULL))
		cert_valid = 1;
#else
	// Use explicit Common Name check if native validation not available.
	// Note: this will ignore Subject Alternative Name fields.
	if (subj
	    && X509_NAME_get_text_by_NID(subj, NID_commonName, common_name,
	                                 FIELD_SIZE) > 0
	    && strncasecmp(common_name, tunnel->config->gateway_host,
	                   FIELD_SIZE) == 0)
		cert_valid = 1;
#endif

	// Try to validate certificate using local PKI
	if (cert_valid
	    && SSL_get_verify_result(tunnel->ssl_handle) == X509_V_OK) {
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
	digest_str[SHA256STRLEN - 1] = '\0';
	// Is it in whitelist?
	for (elem = tunnel->config->cert_whitelist; elem != NULL;
	     elem = elem->next)
		if (memcmp(digest_str, elem->data, SHA256STRLEN - 1) == 0)
			break;
	if (elem != NULL) { // break before end of loop
		log_debug("Gateway certificate digest found in white list.\n");
		ret = 0;
		goto free_cert;
	}

	subject = X509_NAME_oneline(subj, NULL, 0);
	issuer = X509_NAME_oneline(X509_get_issuer_name(cert), NULL, 0);

	log_error("Gateway certificate validation failed, and the certificate digest in not in the local whitelist. If you trust it, rerun with:\n");
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
	ssl_disconnect(tunnel);

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

	// Load the OS default CA files
	if (!SSL_CTX_set_default_verify_paths(tunnel->ssl_context))
		log_error("Could not load OS OpenSSL files.\n");

	if (tunnel->config->ca_file) {
		if (!SSL_CTX_load_verify_locations(
		            tunnel->ssl_context,
		            tunnel->config->ca_file, NULL)) {
			log_error("SSL_CTX_load_verify_locations: %s\n",
			          ERR_error_string(ERR_peek_last_error(), NULL));
			return 1;
		}
	}

	if (tunnel->config->user_cert) {
		if (!SSL_CTX_use_certificate_file(
		            tunnel->ssl_context, tunnel->config->user_cert,
		            SSL_FILETYPE_PEM)) {
			log_error("SSL_CTX_use_certificate_file: %s\n",
			          ERR_error_string(ERR_peek_last_error(), NULL));
			return 1;
		}
	}

	if (tunnel->config->user_key) {
		if (!SSL_CTX_use_PrivateKey_file(
		            tunnel->ssl_context, tunnel->config->user_key,
		            SSL_FILETYPE_PEM)) {
			log_error("SSL_CTX_use_PrivateKey_file: %s\n",
			          ERR_error_string(ERR_peek_last_error(), NULL));
			return 1;
		}
	}

	if (tunnel->config->user_cert && tunnel->config->user_key) {
		if (!SSL_CTX_check_private_key(tunnel->ssl_context)) {
			log_error("SSL_CTX_check_private_key: %s\n",
			          ERR_error_string(ERR_peek_last_error(), NULL));
			return 1;
		}
	}

	if (!tunnel->config->insecure_ssl) {
		long sslctxopt = SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION;
		long checkopt;

		checkopt = SSL_CTX_set_options(tunnel->ssl_context, sslctxopt);
		if ((checkopt & sslctxopt) != sslctxopt) {
			log_error("SSL_CTX_set_options didn't set opt: %s\n",
			          ERR_error_string(ERR_peek_last_error(), NULL));
			return 1;
		}
	}

	tunnel->ssl_handle = SSL_new(tunnel->ssl_context);
	if (tunnel->ssl_handle == NULL) {
		log_error("SSL_new: %s\n",
		          ERR_error_string(ERR_peek_last_error(), NULL));
		return 1;
	}

	if (!tunnel->config->insecure_ssl && !tunnel->config->cipher_list) {
		const char *cipher_list = "HIGH:!aNULL:!kRSA:!PSK:!SRP:!MD5:!RC4";

		if (tunnel->config->cipher_list)
			cipher_list = tunnel->config->cipher_list;
		if (!SSL_set_cipher_list(tunnel->ssl_handle, cipher_list)) {
			log_error("SSL_set_cipher_list failed: %s\n",
			          ERR_error_string(ERR_peek_last_error(), NULL));
			return 1;
		}
	}

	if (!SSL_set_fd(tunnel->ssl_handle, tunnel->ssl_socket)) {
		log_error("SSL_set_fd: %s\n",
		          ERR_error_string(ERR_peek_last_error(), NULL));
		return 1;
	}
	SSL_set_mode(tunnel->ssl_handle, SSL_MODE_AUTO_RETRY);

	// Initiate SSL handshake
	if (SSL_connect(tunnel->ssl_handle) != 1) {
		log_error("SSL_connect: %s\n"
		          "You might want to try --insecure-ssl or specify a different --cipher-list\n",
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
	struct tunnel tunnel = {
		.config = config,
		.state = STATE_DOWN,
		.ssl_context = NULL,
		.ssl_handle = NULL,
		.ipv4.ns1_addr.s_addr = 0,
		.ipv4.ns2_addr.s_addr = 0,
		.on_ppp_if_up = on_ppp_if_up,
		.on_ppp_if_down = on_ppp_if_down
	};

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

	ret = ssl_connect(&tunnel);
	if (ret)
		goto err_tunnel;

	// Step 3: get configuration
	ret = auth_get_config(&tunnel);
	if (ret != 1) {
		log_error("Could not get VPN configuration (%s).\n",
		          err_http_str(ret));
		ret = 1;
		goto err_tunnel;
	}

	// Step 4: run a pppd process
	ret = pppd_run(&tunnel);
	if (ret)
		goto err_tunnel;

	// Step 5: ask gateway to start tunneling
	ret = http_send(&tunnel,
	                "GET /remote/sslvpn-tunnel HTTP/1.1\r\n"
	                "Host: sslvpn\r\n"
	                "Cookie: %s\r\n\r\n",
	                tunnel.config->cookie);
	if (ret != 1) {
		log_error("Could not start tunnel (%s).\n", err_http_str(ret));
		ret = 1;
		goto err_start_tunnel;
	}

	tunnel.state = STATE_CONNECTING;
	ret = 0;

	// Step 6: perform io between pppd and the gateway, while tunnel is up
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

	// explicitly free the buffer allocated for split routes of the ipv4 config
	if (tunnel.ipv4.split_rt != NULL) {
		free(tunnel.ipv4.split_rt);
		tunnel.ipv4.split_rt = NULL;
	}
	return ret;
}
