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

#include <stdint.h>
#include <stdio.h>
#include <getopt.h>

#include "log.h"
#include "tunnel.h"

#define VERSION "1.0.0"

#define USAGE \
"Usage: openfortivpn <host>:<port> -u <user> -p <pass>\n" \
"                    [--no-routes] [--no-dns] [--pppd-log=<filename>]\n" \
"                    [-v|-q]\n" \
"       openfortivpn --help\n" \
"       openfortivpn --version\n"

#define HELP \
USAGE \
"\n" \
"Client for SSL VPN tunnels.\n" \
"openfortivpn connects to a VPN by setting up a tunnel to the gateway at\n" \
"<host>:<port>.\n" \
"\n" \
"Options:\n" \
"  -h --help                     Show this help message and exit.\n" \
"  --version                     Show version and exit.\n" \
"  -u <user>, --username=<user>  VPN account username.\n" \
"  -p <pass>, --password=<pass>  VPN account password.\n" \
"  --no-routes                   Do not try to configure IP routes through the\n" \
"                                VPN when tunnel is up.\n" \
"  --no-dns                      Do not add VPN nameservers in /etc/resolv.conf\n" \
"                                when tunnel is up.\n" \
"  --pppd-log=<filename>         Set pppd in debug mode and save its logs into\n" \
"                                <filename>.\n" \
"  -v                            Increase verbosity. Can be used multiple times\n" \
"                                to be even more verbose.\n" \
"  -q                            Decrease verbosity. Can be used multiple times\n" \
"                                to be even less verbose.\n"
 
int main(int argc, char **argv)
{
	struct vpn_config cfg;
	int c;
	char *port_str;
	long int port;

	// Set defaults
	cfg.username = NULL;
	cfg.password = NULL;
	cfg.set_routes = 1;
	cfg.set_dns = 1;
	cfg.pppd_log = NULL;

	struct option long_options[] = {
		{"help",          no_argument,       0, 'h'},
		{"version",       no_argument,       0, 0},
		{"username",      required_argument, 0, 'u'},
		{"password",      required_argument, 0, 'p'},
		{"no-routes",     no_argument, &cfg.set_routes, 0},
		{"no-dns",        no_argument, &cfg.set_dns, 0},
		{"pppd-log",      required_argument, 0, 0},
		{0, 0, 0, 0}
	};

	while (1) {
		/* getopt_long stores the option index here. */
		int option_index = 0;

		c = getopt_long(argc, argv, "hvqu:p:",
		long_options, &option_index);

		/* Detect the end of the options. */
		if (c == -1)
			break;

		switch (c) {
		case 0:
			/* If this option set a flag, do nothing else now. */
			if (long_options[option_index].flag != 0)
				break;
			if (strcmp(long_options[option_index].name,
				   "version") == 0) {
				printf(VERSION "\n");
				exit(EXIT_SUCCESS);
			}
			if (strcmp(long_options[option_index].name,
				   "pppd-log") == 0) {
				cfg.pppd_log = optarg;
				break;
			}
			goto user_error;
		case 'h':
			printf(HELP);
			exit(EXIT_SUCCESS);
		case 'v':
			increase_verbosity();
			break;
		case 'q':
			decrease_verbosity();
			break;
		case 'u':
			cfg.username = optarg;
			break;
		case 'p':
			cfg.password = optarg;
			break;
		default:
			goto user_error;
		}
	}

	if (optind != argc - 1)
		goto user_error;

	// Check host and port
	cfg.gateway_host = argv[optind++];
	port_str = strchr(cfg.gateway_host, ':');
	if (port_str == NULL) {
		fprintf(stderr, "Specify a valid host:port.\n");
		goto user_error;
	}
	port_str[0] = '\0';
	port_str++;
	port = strtol(port_str, NULL, 0);
	if (port <= 0 || port > 65535) {
		fprintf(stderr, "Specify a valid port.\n");
		goto user_error;
	}
	cfg.gateway_port = port;

	// Check username
	if (cfg.username == NULL) {
		fprintf(stderr, "Specify an username.\n");
		goto user_error;
		//char *env = getenv("VPN_USERNAME");
		//if (env == NULL) {
		//	fprintf(stderr, "Specify an username.\n");
		//	goto user_error;
		//}
		//cfg.username = env;
	}
	// Check password
	if (cfg.password == NULL) {
		fprintf(stderr, "Specify a password.\n");
		goto user_error;
		//char *env = getenv("VPN_PASSWORD");
		//if (env == NULL) {
		//	fprintf(stderr, "Specify a password.\n");
		//	goto user_error;
		//}
		//cfg.password = env;
	}

	if (geteuid() != 0)
		log_warn("This process was not spawned with root "
				"privileges, this will probably not work.\n");

	if (run_tunnel(&cfg) != 0)
		exit(EXIT_FAILURE);
        exit(EXIT_SUCCESS);

user_error:
	fprintf(stderr, USAGE);
	exit(EXIT_FAILURE);
}
