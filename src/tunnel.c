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
#include "userinput.h"

#include <openssl/err.h>
#ifndef OPENSSL_NO_ENGINE
#include <openssl/engine.h>
#endif
#include <openssl/ui.h>
#include <openssl/x509v3.h>
#if HAVE_SYSTEMD
#include <systemd/sd-daemon.h>
#endif

#include <unistd.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <netdb.h>
#if HAVE_PTY_H
#include <pty.h>
#elif HAVE_UTIL_H
#include <util.h>
#endif
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <termios.h>
#if HAVE_LIBUTIL_H
#include <libutil.h>
#endif
#if HAVE_LINUX_IF_TUN_H
#include <linux/if_tun.h>
#endif

#include <errno.h>
#include <signal.h>
#include <string.h>
#include <assert.h>


struct ofv_varr {
	unsigned int cap;	// current capacity
	unsigned int off;	// next slot to write, always < max(cap - 1, 1)
	const char **data;	// NULL terminated
};

static int ofv_append_varr(struct ofv_varr *p, const char *x)
{
	if (p->off + 1 >= p->cap) {
		const char **ndata;
		unsigned int ncap = (p->off + 1) * 2;

		if (p->off + 1 >= ncap) {
			log_error("%s: ncap exceeded\n", __func__);
			return 1;
		};
		ndata = realloc(p->data, ncap * sizeof(const char *));
		if (ndata) {
			p->data = ndata;
			p->cap = ncap;
		} else {
			log_error("realloc: %s\n", strerror(errno));
			return 1;
		}
	}
	if (p->data == NULL) {
		log_error("%s: NULL data\n", __func__);
		return 1;
	}
	if (p->off + 1 >= p->cap) {
		log_error("%s: cap exceeded in p\n", __func__);
		return 1;
	}
	p->data[p->off] = x;
	p->data[++p->off] = NULL;
	return 0;
}

static int on_ppp_if_up(struct tunnel *tunnel)
{
	log_info("Interface %s is UP.\n", tunnel->ppp_iface);

	if (tunnel->config->set_routes) {
		int ret;

		log_info("Setting new routes...\n");

		ret = ipv4_set_tunnel_routes(tunnel);

		if (ret != 0)
			log_warn("Adding route table is incomplete. Please check route table.\n");
	}

	if (tunnel->config->set_dns) {
		log_info("Adding VPN nameservers...\n");
		ipv4_add_nameservers_to_resolv_conf(tunnel);
	}

	log_info("Tunnel is up and running.\n");

#if HAVE_SYSTEMD
	sd_notify(0, "READY=1");
#endif

	return 0;
}

static int on_ppp_if_down(struct tunnel *tunnel)
{
#if HAVE_SYSTEMD
	sd_notify(0, "STOPPING=1");
#endif

	log_info("Setting %s interface down.\n", tunnel->ppp_iface);

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

static const char TUN_PATH[] = "/dev/net/tun";

#define TUN_ASSERT(cond, fmt, ...) do {                    \
		if (!(cond)) {                             \
			log_info(fmt "\n", ##__VA_ARGS__); \
			exit(EXIT_FAILURE);                \
		}                                          \
	} while (0)

static int tun_open(struct ifreq *ifr)
{
	int ret = 0;
	int fd = -1;

	fd = open(TUN_PATH, O_RDWR, 0);
	if (fd >= 0) {
		ret = ioctl(fd, TUNSETIFF, ifr);
		if (ret < 0) {
			log_error("ioctl: %s\n", strerror(errno));
			close(fd);
			return ret;
		}
		log_info("interface <%s> created\n", ifr->ifr_name);
	} else {
		log_error("fcntl: %s\n", strerror(errno));
	}

	return fd;
}

static int tun_close(int fd)
{
	return close(fd);
}

int tun_ifup(const char *ifname, uint32_t ip_addr, uint32_t peer_addr)
{
	struct ifreq ifreq = {
		.ifr_flags = IFF_UP,
	};
	int fd = -1;
	int ret = -1;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		return fd;

	TUN_ASSERT(strlen(ifname) < IFNAMSIZ, "ifname length");
	strcpy(ifreq.ifr_name, ifname);

	ret = ioctl(fd, SIOCGIFFLAGS, &ifreq);
	TUN_ASSERT(ret == 0, "ioctl get ifflags");
	if (ret == 0) {
		ifreq.ifr_flags |= IFF_UP;
		ret = ioctl(fd, SIOCSIFFLAGS, &ifreq);
		TUN_ASSERT(ret == 0, "ioctl set ifflags");
	}

	if (ip_addr != 0) {
		struct sockaddr_in *sin = (struct sockaddr_in *)&ifreq.ifr_addr;

		sin->sin_family = AF_INET;
		sin->sin_port = 0;
		sin->sin_addr.s_addr = ip_addr;
		ret = ioctl(fd, SIOCSIFADDR, &ifreq);
		TUN_ASSERT(ret == 0, "ioctl set ifaddr err: %s", strerror(errno));
		log_info("setup <%s> ip addr to %s\n", ifname, inet_ntoa(sin->sin_addr));
	}

	if (peer_addr != 0) {
		struct sockaddr_in *sin = (struct sockaddr_in *)&ifreq.ifr_addr;

		sin->sin_family = AF_INET;
		sin->sin_port = 0;
		sin->sin_addr.s_addr = peer_addr;
		ret = ioctl(fd, SIOCSIFDSTADDR, &ifreq);
		TUN_ASSERT(ret == 0, "ioctl set dst ifaddr");
	}

	close(fd);

	return ret;
}

static int tun_setup(struct tunnel *tunnel)
{
	int flags = 0;
	int tun_fd = -1;
	struct ifreq ifreq = {
		.ifr_flags = IFF_TUN | IFF_NO_PI,
	};

	tun_fd = tun_open(&ifreq);
	if (tun_fd < 0) {
		log_error("tun_open failed: %s\n", strerror(errno));
		return 1;
	}

	flags = fcntl(tun_fd, F_GETFL, 0);
	if (flags == -1)
		flags = 0;
	if (fcntl(tun_fd, F_SETFL, flags | O_NONBLOCK) == -1) {
		log_error("fcntl failed: %s\n", strerror(errno));
		tun_close(tun_fd);
		return 1;
	}

	strcpy(tunnel->tun_iface, ifreq.ifr_name);
	tun_ifup(tunnel->tun_iface, 0, 0);

	tunnel->pppd_pid = -1;
	tunnel->pppd_pty = tun_fd;

	return 0;
}

static int pppd_run(struct tunnel *tunnel)
{
	pid_t pid;
	int amaster;
	int slave_stderr;

#ifdef HAVE_STRUCT_TERMIOS
	struct termios termp = {
		.c_cflag = B9600,
		.c_cc[VTIME] = 0,
		.c_cc[VMIN] = 1
	};
#endif

	static const char ppp_path[] = PPP_PATH;

	if (access(ppp_path, F_OK) != 0) {
		log_error("%s: %s.\n", ppp_path, strerror(errno));
		return 1;
	}
	log_debug("ppp_path: %s\n", ppp_path);

	slave_stderr = dup(STDERR_FILENO);

	if (slave_stderr < 0) {
		log_error("slave stderr: %s\n", strerror(errno));
		return 1;
	}

#ifdef HAVE_STRUCT_TERMIOS
	pid = forkpty(&amaster, NULL, &termp, NULL);
#else
	pid = forkpty(&amaster, NULL, NULL, NULL);
#endif

	if (pid == 0) { // child process

		struct ofv_varr pppd_args = { 0, 0, NULL };

		dup2(slave_stderr, STDERR_FILENO);
		if (close(slave_stderr))
			log_warn("Could not close slave stderr (%s).\n", strerror(errno));

#if HAVE_USR_SBIN_PPP
		/*
		 * assume there is a default configuration to start.
		 * Support for taking options from the command line
		 * e.g. the name of the configuration or options
		 * to send interactively to ppp will be added later
		 */
		static const char *const v[] = {
			ppp_path,
			"-direct"
		};
		for (unsigned int i = 0; i < ARRAY_SIZE(v); i++)
			if (ofv_append_varr(&pppd_args, v[i])) {
				free(pppd_args.data);
				return 1;
			}
#endif
#if HAVE_USR_SBIN_PPPD
		if (tunnel->config->pppd_call) {
			if (ofv_append_varr(&pppd_args, ppp_path)) {
				free(pppd_args.data);
				return 1;
			}
			if (ofv_append_varr(&pppd_args, "call")) {
				free(pppd_args.data);
				return 1;
			}
			if (ofv_append_varr(&pppd_args, tunnel->config->pppd_call)) {
				free(pppd_args.data);
				return 1;
			}
		} else {
			static const char *const v[] = {
				ppp_path,
				/*
				 * On systems such as 4.4BSD and NetBSD, any speed can
				 * be specified. Other systems (e.g. Linux, SunOS) only
				 * support the  commonly-used baud rates.
				 */
				"230400",
				/*
				 * Set the local and/or remote interface IP addresses.
				 * Either one may be omitted. The IP addresses can be
				 * specified with a host name or in decimal dot notation
				 * (e.g. 150.234.56.78). The default local address is
				 * the (first) IP address of the system (unless the
				 * noipdefault option is given). The remote address will
				 * be obtained from the peer if not specified in any
				 * option.
				 * Thus, in simple cases, this option is not required.
				 * If a local and/or remote IP address is specified with
				 * this option, pppd will not accept a different value
				 * from the peer in the IPCP negotiation, unless the
				 * ipcp-accept-local and/or ipcp-accept-remote options
				 * are given, respectively.
				 */
				":169.254.2.1",
				/*
				 * Disables the default behaviour when no local
				 * IP address is specified, which is to determine
				 * (if possible) the local IP address from the hostname.
				 * With this option, the peer will have to supply the
				 * local IP address during IPCP negotiation (unless
				 * it specified explicitly on the command line or in
				 * an options file).
				 */
				"noipdefault",
				/*
				 * With this option, pppd will accept the peer's idea
				 * of our local IP address, even if the local IP address
				 * was specified in an option.
				 *
				 * pppd < 2.5.0 requires this option to avoid this error:
				 *     Peer refused to agree to our IP address
				 * This doesn't make sense to me. I feel it should be the
				 * default because:
				 * 1. we do not specify a local IP address,
				 * 2. we use option noipdefault to specifically ask the
				 *    peer to supply the local IP address.
				 */
				"ipcp-accept-local",
				"noaccomp",
				"noauth",
				"default-asyncmap",
				"nopcomp",
				"receive-all",
				"nodefaultroute",
				"nodetach",
				"lcp-max-configure", "40",
				"mru", "1354"
			};
			for (unsigned int i = 0; i < ARRAY_SIZE(v); i++)
				if (ofv_append_varr(&pppd_args, v[i])) {
					free(pppd_args.data);
					return 1;
				}
		}
		if (tunnel->config->pppd_accept_remote)
			/*
			 * With this option, pppd will accept the peer's idea of its
			 * (remote) IP address, even if the remote IP address was
			 * specified in an option.
			 *
			 * pppd ≥ 2.5.0 requires this option to avoid this error:
			 *     Peer refused to agree to his IP address
			 * This makes sense.
			 *
			 * Unfortunately, pppd < 2.5.0 does not like this option.
			 * Again, this doesn't make sense to me.
			 */
			if (ofv_append_varr(&pppd_args, "ipcp-accept-remote")) {
				free(pppd_args.data);
				return 1;
			}
		if (tunnel->config->pppd_use_peerdns)
			if (ofv_append_varr(&pppd_args, "usepeerdns")) {
				free(pppd_args.data);
				return 1;
			}
		if (tunnel->config->pppd_log) {
			if (ofv_append_varr(&pppd_args, "debug")) {
				free(pppd_args.data);
				return 1;
			}
			if (ofv_append_varr(&pppd_args, "logfile")) {
				free(pppd_args.data);
				return 1;
			}
			if (ofv_append_varr(&pppd_args, tunnel->config->pppd_log)) {
				free(pppd_args.data);
				return 1;
			}
		} else {
			/*
			 * pppd defaults to logging to fd=1, clobbering the
			 * actual PPP data
			 */
			if (ofv_append_varr(&pppd_args, "logfd")) {
				free(pppd_args.data);
				return 1;
			}
			if (ofv_append_varr(&pppd_args, "2")) {
				free(pppd_args.data);
				return 1;
			}
		}
		if (tunnel->config->pppd_plugin) {
			if (ofv_append_varr(&pppd_args, "plugin")) {
				free(pppd_args.data);
				return 1;
			}
			if (ofv_append_varr(&pppd_args, tunnel->config->pppd_plugin)) {
				free(pppd_args.data);
				return 1;
			}
		}
		if (tunnel->config->pppd_ipparam) {
			if (ofv_append_varr(&pppd_args, "ipparam")) {
				free(pppd_args.data);
				return 1;
			}
			if (ofv_append_varr(&pppd_args, tunnel->config->pppd_ipparam)) {
				free(pppd_args.data);
				return 1;
			}
		}
		if (tunnel->config->pppd_ifname) {
			if (ofv_append_varr(&pppd_args, "ifname")) {
				free(pppd_args.data);
				return 1;
			}
			if (ofv_append_varr(&pppd_args, tunnel->config->pppd_ifname)) {
				free(pppd_args.data);
				return 1;
			}
		}
#endif
#if HAVE_USR_SBIN_PPP
		if (tunnel->config->ppp_system) {
			if (ofv_append_varr(&pppd_args, tunnel->config->ppp_system)) {
				free(pppd_args.data);
				return 1;
			}
		}
#endif

		if (close(tunnel->ssl_socket))
			log_warn("Could not close TLS socket (%s).\n", strerror(errno));
		tunnel->ssl_socket = -1;
		execv(pppd_args.data[0], (char *const *)pppd_args.data);
		free(pppd_args.data);

		fprintf(stderr, "execv: %s\n", strerror(errno));
		_exit(EXIT_FAILURE);
	} else {
		if (close(slave_stderr))
			log_error("Could not close slave stderr (%s).\n",
			          strerror(errno));
		if (pid == -1) {
			log_error("forkpty: %s\n", strerror(errno));
			return 1;
		}
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

static const char * const ppp_message[] = {
#if HAVE_USR_SBIN_PPPD // pppd(8) - https://ppp.samba.org/pppd.html
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
#endif
#if HAVE_USR_SBIN_PPP // sysexits(3) - https://www.freebsd.org/cgi/man.cgi?query=sysexits
	// EX_NORMAL = EX_OK (0)
	"Successful exit.",
	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, // 1-9
	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, // 10-19
	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, // 20-29
	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, // 30-39
	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, // 40-49
	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, // 50-59
	NULL, NULL, NULL, NULL, // 60-63
	// EX_USAGE (64)
	"The command was used incorrectly, e.g., with the wrong number of arguments, a bad flag, a bad syntax in a parameter, or whatever.",
	NULL, NULL, NULL, NULL, // 65-68
	// EX_UNAVAILABLE (69)
	"A service is unavailable. This can occur if a support program or file does not exist.",
	// EX_ERRDEAD = EX_SOFTWARE (70)
	"An internal software error has been detected.",
	NULL, NULL, NULL, NULL, NULL, NULL, NULL, // 71-77
	// EX_CONFIG (78)
	"Something was found in an unconfigured or misconfigured state.",
	NULL, // 79
	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, // 80-89
	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, // 90-98
	NULL // EX_TERMINATE (99), PPP internal pseudo-code
#endif
};

static int pppd_terminate(struct tunnel *tunnel)
{
	if (close(tunnel->pppd_pty))
		log_warn("Could not close pppd pty (%s).\n", strerror(errno));

	log_debug("Waiting for %s to exit...\n", PPP_DAEMON);

	int status;

	/*
	 * Errors outside of the PPP process are returned as negative integers.
	 */
	if (waitpid(tunnel->pppd_pid, &status, 0) == -1) {
		log_error("waitpid: %s\n", strerror(errno));
		return -1;
	}

	/*
	 * Errors in the PPP process are returned as positive integers.
	 */
	if (WIFEXITED(status)) {
		int exit_status = WEXITSTATUS(status);

		/*
		 * PPP exit status codes are positive integers. The way we interpret
		 * their value is not straightforward:
		 * - in the case of "normal" exit, the PPP process may return 0,
		 *   but also a strictly positive integer such as 16 in the case of
		 *   pppd,
		 * - in the case of failure, the PPP process will return a strictly
		 *   positive integer.
		 * For now we process PPP exit status codes as follows:
		 * - exit status codes synonym of success are logged and then
		 *   translated to 0 before they are returned to the calling function,
		 * - other exit status codes are considered synonyms of failure and
		 *   returned to the calling function as is.
		 */
		log_debug("waitpid: %s exit status code %d\n",
		          PPP_DAEMON, exit_status);
		if (exit_status >= ARRAY_SIZE(ppp_message)) {
			log_error("%s: Returned an unknown exit status code: %d\n",
			          PPP_DAEMON, exit_status);
		} else {
			switch (exit_status) {
			/*
			 * PPP exit status codes considered as success
			 */
			case 0:
				log_debug("%s: %s\n",
				          PPP_DAEMON, ppp_message[exit_status]);
				break;
#if HAVE_USR_SBIN_PPPD
			case 16: // emitted by Ctrl+C or "kill -15"
				if (get_sig_received() == SIGINT
				    || get_sig_received() == SIGTERM) {
					log_info("%s: %s\n",
					         PPP_DAEMON, ppp_message[exit_status]);
					exit_status = 0;
					break;
				}
#endif
			/*
			 * PPP exit status codes considered as failure
			 */
			default:
				if (ppp_message[exit_status])
					log_error("%s: %s\n",
					          PPP_DAEMON, ppp_message[exit_status]);
				else
					log_error("%s: Returned an unexpected exit status code: %d\n",
					          PPP_DAEMON, exit_status);
				break;
			}
		}
		return exit_status;
	} else if (WIFSIGNALED(status)) {
		int signal_number = WTERMSIG(status);

		/*
		 * For now we do not consider interruption of the PPP process by
		 * a signal as a failure. Should we?
		 */
		log_debug("waitpid: %s terminated by signal %d\n",
		          PPP_DAEMON, signal_number);
		log_error("%s: terminated by signal: %s\n",
		          PPP_DAEMON, strsignal(signal_number));
	}

	return 0;
}

int ppp_interface_is_up(struct tunnel *tunnel)
{
	struct ifaddrs *ifap;

	log_debug("Got Address: %s\n", inet_ntoa(tunnel->ipv4.ip_addr));

	if (getifaddrs(&ifap)) {
		log_error("getifaddrs: %s\n", strerror(errno));
		return 0;
	}

	for (struct ifaddrs *ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
		if (
#if HAVE_USR_SBIN_PPPD
		        ((tunnel->config->pppd_ifname &&
		          strstr(ifa->ifa_name, tunnel->config->pppd_ifname) != NULL) ||
		         strstr(ifa->ifa_name, "ppp") != NULL ||
		         strstr(ifa->ifa_name, "tun") != NULL) &&
#endif
#if HAVE_USR_SBIN_PPP
		        strstr(ifa->ifa_name, "tun") != NULL &&
#endif
		        ifa->ifa_flags & IFF_UP) {
			if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET) {
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
	const int iface_len = strnlen(tunnel->config->iface_name, IF_NAMESIZE);

	handle = socket(AF_INET, SOCK_STREAM, 0);

	if (handle == -1) {
		log_error("socket: %s\n", strerror(errno));
		goto err_socket;
	}

	if (iface_len == IF_NAMESIZE) {
		log_error("socket: Too long iface name\n");
		goto err_post_socket;
	}
	if (iface_len > 0) {
#if HAVE_SO_BINDTODEVICE
		ret = setsockopt(handle, SOL_SOCKET, SO_BINDTODEVICE,
		                 tunnel->config->iface_name, iface_len);
#else
		struct ifreq ifr;

		memset(&ifr, 0, sizeof(ifr));
		if (strlcpy(ifr.ifr_name, tunnel->config->iface_name, IF_NAMESIZE)
		    >= IF_NAMESIZE) {
			log_error("interface name too long\n");
			goto err_post_socket;
		} else {
			strcpy(ifr.ifr_name, tunnel->config->iface_name);
		}
		ifr.ifr_addr.sa_family = AF_INET;
		if (ioctl(handle, SIOCGIFADDR, &ifr) == -1) {
			log_error("ioctl(%d,SIOCGIFADDR,\"%s\") failed\n", handle,
			          ifr.ifr_name);
			goto err_post_socket;
		}
		ret = bind(handle, &ifr.ifr_addr, ifr.ifr_addr.sa_len);
#endif
		if (ret) {
			log_error("socket: setting interface name failed with error: %d\n",
			          errno);
			goto err_post_socket;
		}
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
		proxy_port = strchr(proxy_host, ':');
		if (proxy_port != NULL) {
			proxy_port[0] = '\0';
			proxy_port++;
			server.sin_port = htons(strtoul(proxy_port, NULL, 10));
		} else {
			server.sin_port = htons(tunnel->config->gateway_port);
		}
		// get rid of a trailing slash
		if (*proxy_host && proxy_host[strlen(proxy_host) - 1] == '/')
			proxy_host[strlen(proxy_host) - 1] = '\0';
		log_debug("proxy_host: %s\n", proxy_host);
		log_debug("proxy_port: %s\n", proxy_port);
		server.sin_addr.s_addr = inet_addr(proxy_host);
		// if host is given as a FQDN we have to do a DNS lookup
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
	memset(&(server.sin_zero), 0, sizeof(server.sin_zero));
	log_debug("gateway_ip: %s\n", inet_ntoa(tunnel->config->gateway_ip));
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

		memset(&(request), 0, sizeof(request));
		for (int j = 0; response == NULL; j++) {
			if (j >= ARRAY_SIZE(request) - 1) {
				log_error("Proxy response is unexpectedly large and cannot fit in the %lu-bytes buffer.\n",
				          ARRAY_SIZE(request));
				goto err_proxy_response;
			}

			ssize_t bytes_read = read(handle, &(request[j]), 1);
			static const char HTTP_STATUS_200[] = "200";

			// we have reached the end of the data sent by the proxy
			// and have not seen HTTP status code 200
			if (bytes_read < 1) {
				log_error("Proxy response does not contain \"%s\" as expected.\n",
				          HTTP_STATUS_200);
				goto err_proxy_response;
			}

			// detect "200"
			response = strstr(request, HTTP_STATUS_200);

			// detect end-of-line after "200"
			if (response != NULL) {
				/*
				 * RFC 2616 states in section 2.2 Basic Rules:
				 *      CR     = <US-ASCII CR, carriage return (13)>
				 *      LF     = <US-ASCII LF, linefeed (10)>
				 *      HTTP/1.1 defines the sequence CR LF as the
				 *      end-of-line marker for all protocol elements
				 *      except the entity-body (see appendix 19.3
				 *      for tolerant applications).
				 *              CRLF   = CR LF
				 *
				 * RFC 2616 states in section 19.3 Tolerant Applications:
				 *      The line terminator for message-header fields
				 *      is the sequence CRLF. However, we recommend
				 *      that applications, when parsing such headers,
				 *      recognize a single LF as a line terminator
				 *      and ignore the leading CR.
				 */
				static const char *const HTTP_EOL[] = {
					"\r\n\r\n",
					"\n\n"
				};
				const char *eol = NULL;

				for (int i = 0; (i < ARRAY_SIZE(HTTP_EOL)) &&
				     (eol == NULL); i++)
					eol = strstr(response, HTTP_EOL[i]);
				response = eol;
			}
		}

		free(env_proxy); // release memory allocated by strdup()
	}

	return handle;

err_proxy_response:
err_connect:
	free(env_proxy); // release memory allocated by strdup()
err_strdup:
err_post_socket:
	if (close(handle))
		log_warn("Could not close socket (%s).\n", strerror(errno));
err_socket:
	return -1;
}

static int ssl_verify_cert(struct tunnel *tunnel)
{
	int ret = -1;
	unsigned char digest[SHA256LEN];
	unsigned int len;
	struct x509_digest *elem;
	char digest_str[SHA256STRLEN], *subject, *issuer;
	X509_NAME *subj;
	char *saveptr = NULL;

	SSL_set_verify(tunnel->ssl_handle, SSL_VERIFY_PEER, NULL);

	X509 *cert = SSL_get_peer_certificate(tunnel->ssl_handle);

	if (cert == NULL) {
		log_error("Unable to get gateway certificate.\n");
		return 1;
	}

	// Validate certificate:
	// 1. Validate using local PKI
	// 2. Compare against gateway_host and correctly check return value
	//    to fix prior incorrect use of X509_check_host
	if (SSL_get_verify_result(tunnel->ssl_handle) == X509_V_OK
	    && X509_check_host(cert, tunnel->config->gateway_host,
	                       0, 0, NULL) == 1) {
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
	for (int i = 0; i < SHA256LEN; i++)
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

	subj = X509_get_subject_name(cert);

	log_error("Gateway certificate validation failed, and the certificate digest is not in the local whitelist. If you trust it, rerun with:\n");
	log_error("    --trusted-cert %s\n", digest_str);
	log_error("or add this line to your configuration file:\n");
	log_error("    trusted-cert = %s\n", digest_str);
	log_error("Gateway certificate:\n");
	log_error("    subject:\n");
	subject = X509_NAME_oneline(subj, NULL, 0);
	if (subject) {
		for (char *line = strtok_r(subject, "/", &saveptr); line != NULL;
		     line = strtok_r(NULL, "/", &saveptr))
			log_error("        %s\n", line);
		free(subject);
	}
	log_error("    issuer:\n");
	issuer = X509_NAME_oneline(X509_get_issuer_name(cert), NULL, 0);
	if (issuer) {
		for (char *line = strtok_r(issuer, "/", &saveptr); line != NULL;
		     line = strtok_r(NULL, "/", &saveptr))
			log_error("        %s\n", line);
		free(issuer);
	}
	log_error("    sha256 digest:\n");
	log_error("        %s\n", digest_str);

free_cert:
	X509_free(cert);
	return ret;
}

/*
 * Destroy and free the TLS connection to the gateway.
 */
static void ssl_disconnect(struct tunnel *tunnel)
{
	if (!tunnel->ssl_handle)
		return;

	SSL_shutdown(tunnel->ssl_handle);
	SSL_free(tunnel->ssl_handle);
	tunnel->ssl_handle = NULL;

	SSL_CTX_free(tunnel->ssl_context);
	tunnel->ssl_context = NULL;

	if (close(tunnel->ssl_socket))
		log_warn("Could not close TLS socket (%s).\n", strerror(errno));
	tunnel->ssl_socket = -1;
}

/*
 * Query for the pass phrase used for encrypted PEM structures
 * (normally only private keys).
 */
static int pem_passphrase_cb(char *buf, int size, int rwflag, void *u)
{
	struct vpn_config *cfg = (struct vpn_config *)u;

	/* We expect to only read PEM pass phrases, not write them. */
	if (rwflag == 0) {
		if (!cfg->pem_passphrase_set) {
			if (size > PEM_PASSPHRASE_SIZE) {
				read_password(NULL, NULL,
				              "Enter PEM pass phrase: ",
				              cfg->pem_passphrase,
				              PEM_PASSPHRASE_SIZE + 1);
				cfg->pem_passphrase_set =  1;
			} else {
				log_error("Buffer too small for PEM pass phrase: %d.\n",
				          size);
			}
		}
		if (cfg->pem_passphrase_set) {
			assert(strlen(cfg->pem_passphrase) < size);
			strncpy(buf, cfg->pem_passphrase, size);
			buf[size - 1] = '\0';
			return strlen(buf);
		}
	} else {
		log_error("We refuse to write PEM pass phrases!\n");
	}

	return -1;
}

/*
 * Connects to the gateway and initiate a TLS session.
 */
int ssl_connect(struct tunnel *tunnel)
{
	ssl_disconnect(tunnel);

	tunnel->ssl_socket = tcp_connect(tunnel);
	if (tunnel->ssl_socket == -1)
		goto err_tcp_connect;

	// https://wiki.openssl.org/index.php/Library_Initialization
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	// Register the error strings for libcrypto & libssl
	SSL_load_error_strings();
	// Register the available ciphers and digests
	SSL_library_init();

	tunnel->ssl_context = SSL_CTX_new(SSLv23_client_method());
#else
	tunnel->ssl_context = SSL_CTX_new(TLS_client_method());
#endif
	if (tunnel->ssl_context == NULL) {
		log_error("SSL_CTX_new: %s\n",
		          ERR_error_string(ERR_peek_last_error(), NULL));
		goto err_ssl_socket;
	}

	/* Load the OS default CA files */
	if (!SSL_CTX_set_default_verify_paths(tunnel->ssl_context))
		log_error("Could not load OS OpenSSL files.\n");

	if (tunnel->config->ca_file) {
		if (!SSL_CTX_load_verify_locations(tunnel->ssl_context,
		                                   tunnel->config->ca_file, NULL)) {
			log_error("SSL_CTX_load_verify_locations: %s\n",
			          ERR_error_string(ERR_peek_last_error(), NULL));
			goto err_ssl_context;
		}
	}

	/* Disable vulnerable TLS protocols and ciphers by default*/
	if (!tunnel->config->cipher_list) {
		if (!tunnel->config->insecure_ssl) {
			const char *cipher_list;

			if (tunnel->config->seclevel_1)
				cipher_list = "HIGH:!aNULL:!kRSA:!PSK:!SRP:!MD5:!RC4@SECLEVEL=1";
			else
				cipher_list = "HIGH:!aNULL:!kRSA:!PSK:!SRP:!MD5:!RC4";
			tunnel->config->cipher_list = strdup(cipher_list);
		} else if (tunnel->config->seclevel_1) {
			static const char cipher_list[] = "DEFAULT@SECLEVEL=1";

			tunnel->config->cipher_list = strdup(cipher_list);
		}
	}

	/* Set the password callback for PEM certificates with encryption. */
	SSL_CTX_set_default_passwd_cb(tunnel->ssl_context, &pem_passphrase_cb);
	SSL_CTX_set_default_passwd_cb_userdata(tunnel->ssl_context, tunnel->config);

	if (tunnel->config->cipher_list) {
		log_debug("Setting cipher list to: %s\n", tunnel->config->cipher_list);
		if (!SSL_CTX_set_cipher_list(tunnel->ssl_context,
		                             tunnel->config->cipher_list)) {
			log_error("SSL_CTX_set_cipher_list failed: %s\n",
			          ERR_error_string(ERR_peek_last_error(), NULL));
			goto err_ssl_context;
		}
	}

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	if (tunnel->config->min_tls > 0) {
		log_debug("Setting minimum protocol version to: 0x%x.\n",
		          tunnel->config->min_tls);
		if (!SSL_CTX_set_min_proto_version(tunnel->ssl_context,
		                                   tunnel->config->min_tls)) {
			log_error("Cannot set minimum protocol version (%s).\n",
			          ERR_error_string(ERR_peek_last_error(), NULL));
			goto err_ssl_context;
		}
	}
#else
	if (!tunnel->config->insecure_ssl || tunnel->config->min_tls > 0) {
		long sslctxopt = 0;
		long checkopt;

		if (!tunnel->config->insecure_ssl)
			sslctxopt |= SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION;
#ifdef TLS1_VERSION
		if (tunnel->config->min_tls > TLS1_VERSION)
			sslctxopt |= SSL_OP_NO_TLSv1;
#endif
#ifdef TLS1_1_VERSION
		if (tunnel->config->min_tls > TLS1_1_VERSION)
			sslctxopt |= SSL_OP_NO_TLSv1_1;
#endif
#ifdef TLS1_2_VERSION
		if (tunnel->config->min_tls > TLS1_2_VERSION)
			sslctxopt |= SSL_OP_NO_TLSv1_2;
#endif
		checkopt = SSL_CTX_set_options(tunnel->ssl_context, sslctxopt);
		if ((checkopt & sslctxopt) != sslctxopt) {
			log_error("SSL_CTX_set_options didn't set opt: %s\n",
			          ERR_error_string(ERR_peek_last_error(), NULL));
			goto err_ssl_context;
		}
	}
#endif

#ifndef OPENSSL_NO_ENGINE
	/* Use PKCS11 engine for PIV if user-cert config starts with pkcs11 URI: */
	if (tunnel->config->use_engine > 0) {
		ENGINE *e;

		ENGINE_load_builtin_engines();
		e = ENGINE_by_id("pkcs11");
		if (!e) {
			log_error("Could not load pkcs11 Engine: %s\n",
			          ERR_error_string(ERR_peek_last_error(), NULL));
			goto err_ssl_context;
		}
		if (!ENGINE_init(e)) {
			log_error("Could not init pkcs11 Engine: %s\n",
			          ERR_error_string(ERR_peek_last_error(), NULL));
			ENGINE_free(e);
			goto err_ssl_context;
		}
		if (!ENGINE_set_default_RSA(e))
			abort();

		ENGINE_finish(e);
		ENGINE_free(e);

		struct token parms;

		parms.uri = tunnel->config->user_cert;
		parms.cert = NULL;

		if (!ENGINE_ctrl_cmd(e, "LOAD_CERT_CTRL", 0, &parms, NULL, 1)) {
			log_error("PKCS11 ENGINE_ctrl_cmd: %s\n",
			          ERR_error_string(ERR_peek_last_error(), NULL));
			goto err_ssl_context;
		}

		if (!SSL_CTX_use_certificate(tunnel->ssl_context, parms.cert)) {
			log_error("PKCS11 SSL_CTX_use_certificate: %s\n",
			          ERR_error_string(ERR_peek_last_error(), NULL));
			goto err_ssl_context;
		}

		EVP_PKEY * privkey = ENGINE_load_private_key(
		                             e, parms.uri, UI_OpenSSL(), NULL);
		if (!privkey) {
			log_error("PKCS11 ENGINE_load_private_key: %s\n",
			          ERR_error_string(ERR_peek_last_error(), NULL));
			goto err_ssl_context;
		}

		if (!SSL_CTX_use_PrivateKey(tunnel->ssl_context, privkey)) {
			log_error("PKCS11 SSL_CTX_use_PrivateKey_file: %s\n",
			          ERR_error_string(ERR_peek_last_error(), NULL));
			goto err_ssl_context;
		}

		if (!SSL_CTX_check_private_key(tunnel->ssl_context)) {
			log_error("PKCS11 SSL_CTX_check_private_key: %s\n",
			          ERR_error_string(ERR_peek_last_error(), NULL));
			goto err_ssl_context;
		}
	} else { /* end PKCS11 engine */
#endif
		if (tunnel->config->user_cert) {
			if (!SSL_CTX_use_certificate_chain_file(
			            tunnel->ssl_context, tunnel->config->user_cert)) {
				log_error("SSL_CTX_use_certificate_chain_file: %s\n",
				          ERR_error_string(ERR_peek_last_error(), NULL));
				goto err_ssl_context;
			}
		}

		if (tunnel->config->user_key) {
			if (!SSL_CTX_use_PrivateKey_file(tunnel->ssl_context,
			                                 tunnel->config->user_key,
			                                 SSL_FILETYPE_PEM)) {
				log_error("SSL_CTX_use_PrivateKey_file: %s\n",
				          ERR_error_string(ERR_peek_last_error(), NULL));
				goto err_ssl_context;
			}
		}

		if (tunnel->config->user_cert && tunnel->config->user_key) {
			if (!SSL_CTX_check_private_key(tunnel->ssl_context)) {
				log_error("SSL_CTX_check_private_key: %s\n",
				          ERR_error_string(ERR_peek_last_error(), NULL));
				goto err_ssl_context;
			}
		}
#ifndef OPENSSL_NO_ENGINE
	}
#endif

	tunnel->ssl_handle = SSL_new(tunnel->ssl_context);
	if (tunnel->ssl_handle == NULL) {
		log_error("SSL_new: %s\n",
		          ERR_error_string(ERR_peek_last_error(), NULL));
		goto err_ssl_context;
	}

	if (!SSL_set_fd(tunnel->ssl_handle, tunnel->ssl_socket)) {
		log_error("SSL_set_fd: %s\n",
		          ERR_error_string(ERR_peek_last_error(), NULL));
		goto err_ssl_handle;
	}
	SSL_set_mode(tunnel->ssl_handle, SSL_MODE_AUTO_RETRY);


	// Set SNI for the session
	const char *sni = tunnel->config->sni[0] ? tunnel->config->sni :
	                  tunnel->config->gateway_host;
	if (SSL_set_tlsext_host_name(tunnel->ssl_handle, sni) != 1)
		log_warn("SSL_set_tlsext_host_name('%s'): %s\n",
		         sni,
		         ERR_error_string(ERR_peek_last_error(), NULL));
	else
		log_debug("Set SNI for TLS handshake: %s\n", sni);

	// Initiate SSL handshake
	if (SSL_connect(tunnel->ssl_handle) != 1) {
		log_error("SSL_connect: %s\n"
		          "You might want to try --insecure-ssl or specify a different --cipher-list\n",
		          ERR_error_string(ERR_peek_last_error(), NULL));
		goto err_ssl_handle;
	}
	SSL_set_mode(tunnel->ssl_handle, SSL_MODE_AUTO_RETRY);

	if (ssl_verify_cert(tunnel))
		goto err_ssl_handle;

	// Disable SIGPIPE (occurs when trying to write to an already-closed
	// socket).
	signal(SIGPIPE, SIG_IGN);

	return 0;

err_ssl_handle:
	SSL_shutdown(tunnel->ssl_handle);
	SSL_free(tunnel->ssl_handle);
	tunnel->ssl_handle = NULL;
err_ssl_context:
	SSL_CTX_free(tunnel->ssl_context);
	tunnel->ssl_context = NULL;
err_ssl_socket:
	if (close(tunnel->ssl_socket))
		log_warn("Could not close TLS socket (%s).\n", strerror(errno));
	tunnel->ssl_socket = -1;
err_tcp_connect:
	return 1;
}

int run_tunnel(struct vpn_config *config)
{
	int ret;
	struct tunnel tunnel = {
		.config = config,
		.state = STATE_DOWN,
		.ssl_socket = -1,
		.ssl_context = NULL,
		.ssl_handle = NULL,
		.ipv4.ns1_addr.s_addr = 0,
		.ipv4.ns2_addr.s_addr = 0,
		.ipv4.dns_suffix = NULL,
		.on_ppp_if_up = on_ppp_if_up,
		.on_ppp_if_down = on_ppp_if_down
	};

	// Step 0: get gateway host IP
	log_debug("Resolving gateway host ip\n");
	ret = get_gateway_host_ip(&tunnel);
	if (ret)
		goto err_tunnel;

	// Step 1: open a TLS connection to the gateway
	log_debug("Establishing TLS connection\n");
	ret = ssl_connect(&tunnel);
	if (ret)
		goto err_tunnel;
	log_info("Connected to gateway.\n");

	// Step 2: connect to the HTTP interface and authenticate to get a
	// cookie
	if (config->cookie)
		ret = auth_set_cookie(&tunnel, config->cookie);
	else
		ret = auth_log_in(&tunnel);
	if (ret != 1) {
		log_error("Could not authenticate to gateway. Please check the password, client certificate, etc.\n");
		log_debug("%s (%d)\n", err_http_str(ret), ret);
		ret = 1;
		goto err_tunnel;
	}
	log_info("Authenticated.\n");
	log_debug("Cookie: %s\n", tunnel.cookie);

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
	log_info("Retrieving configuration\n");
	ret = auth_get_config(&tunnel);
	if (ret != 1) {
		log_error("Could not get VPN configuration (%s).\n",
		          err_http_str(ret));
		ret = 1;
		goto err_tunnel;
	}

	// Step 4: run a pppd process
	log_info("Establishing the tunnel\n");
	if (config->tun)
		ret = tun_setup(&tunnel);
	else
		ret = pppd_run(&tunnel);
	if (ret)
		goto err_tunnel;

	// Step 5: ask gateway to start tunneling
	log_debug("Switch to tunneling mode\n");
	ret = http_send(&tunnel,
	                "GET /remote/sslvpn-tunnel HTTP/1.1\r\n"
	                "Host: sslvpn\r\n"
	                "Cookie: %s\r\n\r\n",
	                tunnel.cookie);
	if (ret != 1) {
		log_error("Could not start tunnel (%s).\n", err_http_str(ret));
		goto err_start_tunnel;
	}

	tunnel.state = STATE_CONNECTING;

	// Step 6: perform io between pppd and the gateway, while tunnel is up
	log_debug("Starting IO through the tunnel\n");
	io_loop(&tunnel);

	log_debug("Disconnecting\n");
	if (tunnel.state == STATE_UP)
		if (tunnel.on_ppp_if_down != NULL)
			tunnel.on_ppp_if_down(&tunnel);

	tunnel.state = STATE_DISCONNECTING;

err_start_tunnel:
	if (!config->tun) {
		ret = pppd_terminate(&tunnel);
		log_info("Terminated %s.\n", PPP_DAEMON);
	}
err_tunnel:
	log_info("Closed connection to gateway.\n");
	tunnel.state = STATE_DOWN;

	if (ssl_connect(&tunnel)) {
		log_info("Could not log out.\n");
	} else {
		auth_log_out(&tunnel);
		log_info("Logged out.\n");
	}

	// explicitly free the buffer allocated for split routes of the ipv4 configuration
	if (tunnel.ipv4.split_rt != NULL) {
		free(tunnel.ipv4.split_rt);
		tunnel.ipv4.split_rt = NULL;
	}
	return ret;
}
