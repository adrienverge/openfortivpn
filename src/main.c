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

#include <getopt.h>
#include <termios.h>

#include "config.h"
#include "log.h"
#include "tunnel.h"

#define USAGE \
"Usage: openfortivpn [<host>:<port>] [-u <user>] [-p <pass>]\n" \
"                    [--no-routes] [--no-dns] [--pppd-log=<file>]\n" \
"                    [--plugin=<file>] [--ca-file=<file>]\n" \
"                    [--trusted-cert=<digest>] [-c <file>] [-v|-q]\n" \
"       openfortivpn --help\n" \
"       openfortivpn --version\n"

#define HELP \
USAGE \
"\n" \
"Client for PPP+SSL VPN tunnel services.\n" \
"openfortivpn connects to a VPN by setting up a tunnel to the gateway at\n" \
"<host>:<port>. It spawns a pppd process and operates the communication between\n" \
"the gateway and this process.\n" \
"\n" \
"Options:\n" \
"  -h --help                     Show this help message and exit.\n" \
"  --version                     Show version and exit.\n" \
"  -c <file>, --config=<file>    Specify a custom config file (default:\n" \
"                                /etc/openfortivpn/config).\n" \
"  -u <user>, --username=<user>  VPN account username.\n" \
"  -p <pass>, --password=<pass>  VPN account password.\n" \
"  --no-routes                   Do not try to configure IP routes through the\n" \
"                                VPN when tunnel is up.\n" \
"  --no-dns                      Do not add VPN nameservers in /etc/resolv.conf\n" \
"                                when tunnel is up.\n" \
"  --ca-file=<file>              Use specified PEM-encoded certificate bundle\n" \
"                                instead of system-wide store to verify the gateway\n" \
"                                certificate.\n" \
"  --trusted-cert=<digest>       Trust a given gateway. If classical SSL\n" \
"                                certificate validation fails, the gateway\n" \
"                                certificate will be matched against this value.\n" \
"                                <digest> is the X509 certificate's sha256 sum.\n" \
"                                This option can be used multiple times to trust\n" \
"                                several certificates.\n" \
"  --pppd-log=<file>             Set pppd in debug mode and save its logs into\n" \
"                                <file>.\n" \
"  --plugin=<file>               Use specified pppd plugin instead of configuring\n"\
"                                resolver and routes directly.\n" \
"  -v                            Increase verbosity. Can be used multiple times\n" \
"                                to be even more verbose.\n" \
"  -q                            Decrease verbosity. Can be used multiple times\n" \
"                                to be even less verbose.\n" \
"\n" \
"Config file:\n" \
"  Options can be taken from a configuration file. Options passed in the\n" \
"  command line will override those from the config file, though. The default\n" \
"  config file is /etc/openfortivpn/config, but this can be set using the -c\n" \
"  option. A config file looks like:\n" \
"      # this is a comment\n" \
"      host = vpn-gateway\n" \
"      port = 8443\n" \
"      username = foo\n" \
"      password = bar\n" \
"      trusted-cert = certificatedigest4daa8c5fe6c...\n" \
"      trusted-cert = othercertificatedigest6631bf...\n"

static void read_password(const char *prompt, char *pass, size_t len)
{
	int masked = 0;
	struct termios oldt, newt;
	int i;

	printf("%s", prompt);

	// Try to hide user input
	if (tcgetattr(STDIN_FILENO, &oldt) == 0) {
		newt = oldt;
		newt.c_lflag &= ~(ICANON | ECHO);
		tcsetattr(STDIN_FILENO, TCSANOW, &newt);
		masked = 1;
	}

	for (i = 0; i < len - 1; i++) {
		char c = getchar();
		if (c == '\n' || c == EOF)
			break;
		pass[i] = c;
	}
	pass[i] = '\0';

	if (masked) {
		tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
	}

	printf("\n");
}

int main(int argc, char **argv)
{
	int ret = EXIT_FAILURE;
	struct vpn_config cfg;
	char *config_file = "/etc/openfortivpn/config";
	char *host, *username = NULL, *password = NULL;
	char *port_str;
	long int port;

	init_logging();

	// Set defaults
	init_vpn_config(&cfg);
	cfg.set_routes = 1;
	cfg.set_dns = 1;
	cfg.verify_cert = 1;

	struct option long_options[] = {
		{"help",          no_argument,       0, 'h'},
		{"version",       no_argument,       0, 0},
		{"config",        required_argument, 0, 'c'},
		{"username",      required_argument, 0, 'u'},
		{"password",      required_argument, 0, 'p'},
		{"no-routes",     no_argument, &cfg.set_routes, 0},
		{"no-dns",        no_argument, &cfg.set_dns, 0},
		{"ca-file",       required_argument, 0, 0},
		{"trusted-cert",  required_argument, 0, 0},
		{"pppd-log",      required_argument, 0, 0},
		{"plugin",        required_argument, 0, 0},
		{0, 0, 0, 0}
	};

	while (1) {
		/* getopt_long stores the option index here. */
		int c, option_index = 0;

		c = getopt_long(argc, argv, "hvqc:u:p:",
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
				ret = EXIT_SUCCESS;
				goto exit;
			}
			if (strcmp(long_options[option_index].name,
				   "pppd-log") == 0) {
				cfg.pppd_log = optarg;
				break;
			}
			if (strcmp(long_options[option_index].name,
				   "plugin") == 0) {
				cfg.plugin = optarg;
				break;
			}
			if (strcmp(long_options[option_index].name,
				   "ca-file") == 0) {
				cfg.ca_file = optarg;
				break;
			}
			if (strcmp(long_options[option_index].name,
				   "trusted-cert") == 0) {
				if (add_trusted_cert(&cfg, optarg))
					log_warn("Could not add certificate "
						 "digest to whitelist.\n");
				break;
			}
			goto user_error;
		case 'h':
			printf(HELP);
			ret = EXIT_SUCCESS;
			goto exit;
		case 'v':
			increase_verbosity();
			break;
		case 'q':
			decrease_verbosity();
			break;
		case 'c':
			config_file = optarg;
			break;
		case 'u':
			username = optarg;
			break;
		case 'p':
			password = optarg;
			break;
		default:
			goto user_error;
		}
	}

	if (optind < argc - 1 || optind > argc)
		goto user_error;

	if (password != NULL)
		log_warn("You should not pass the password on the command "
			 "line. Type it interactively or use a config file "
			 "instead.\n");

	// Load config file
	if (config_file[0] != '\0') {
		ret = load_config(&cfg, config_file);
		if (ret == 0)
			log_debug("Loaded config file \"%s\".\n", config_file);
		else
			log_warn("Could not load config file \"%s\" (%s).\n",
				 config_file, err_cfg_str(ret));
	}

	// Read host and port from the command line
	if (optind == argc - 1) {
		host = argv[optind++];
		port_str = strchr(host, ':');
		if (port_str == NULL) {
			log_error("Specify a valid host:port couple.\n");
			goto user_error;
		}
		port_str[0] = '\0';
		strncpy(cfg.gateway_host, host, FIELD_SIZE - 1);
		port_str++;
		port = strtol(port_str, NULL, 0);
		if (port <= 0 || port > 65535) {
			log_error("Specify a valid port.\n");
			goto user_error;
		}
		cfg.gateway_port = port;
	}
	// Read username and password from the command line
	if (username != NULL)
		strncpy(cfg.username, username, FIELD_SIZE - 1);
	if (password != NULL)
		strncpy(cfg.password, password, FIELD_SIZE - 1);

	// Check host and port
	if (cfg.gateway_host[0] == '\0' || cfg.gateway_port == 0) {
		log_error("Specify a valid host:port couple.\n");
		goto user_error;
	}
	// Check username
	if (cfg.username[0] == '\0') {
		log_error("Specify an username.\n");
		goto user_error;
	}
	// If no password given, interactively ask user
	if (cfg.password[0] == '\0')
		read_password("VPN account password: ", cfg.password,
			      FIELD_SIZE);
	// Check password
	if (cfg.password[0] == '\0') {
		log_error("Specify a password.\n");
		goto user_error;
	}

	log_debug("Config host = \"%s\"\n", cfg.gateway_host);
	log_debug("Config port = \"%d\"\n", cfg.gateway_port);
	log_debug("Config username = \"%s\"\n", cfg.username);
	log_debug("Config password = \"%s\"\n", "********");

	if (geteuid() != 0)
		log_warn("This process was not spawned with root "
				"privileges, this will probably not work.\n");

	if (run_tunnel(&cfg) == 0)
		ret = EXIT_SUCCESS;
	goto exit;

user_error:
	fprintf(stderr, USAGE);
exit:
	destroy_vpn_config(&cfg);
	exit(ret);
}
