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

#include "config.h"
#include "log.h"
#include "tunnel.h"
#include "userinput.h"

#define USAGE \
"Usage: openfortivpn [<host>:<port>] [-u <user>] [-p <pass>]\n" \
"                    [--realm=<realm>] [--otp=<otp>] [--no-routes]\n" \
"                    [--no-dns] [--pppd-no-peerdns] [--pppd-log=<file>]\n" \
"                    [--pppd-ipparam=<string>] [--pppd-plugin=<file>]\n" \
"                    [--ca-file=<file>] [--user-cert=<file>]\n" \
"                    [--user-key=<file>] [--trusted-cert=<digest>]\n" \
"                    [--use-syslog] [-c <file>] [-v|-q]\n" \
"       openfortivpn --help\n" \
"       openfortivpn --version\n"

#define HELP \
"Client for PPP+SSL VPN tunnel services.\n" \
"openfortivpn connects to a VPN by setting up a tunnel to the gateway at\n" \
"<host>:<port>. It spawns a pppd process and operates the communication between\n" \
"the gateway and this process.\n" \
"\n" \
"Options:\n" \
"  -h --help                     Show this help message and exit.\n" \
"  --version                     Show version and exit.\n" \
"  -c <file>, --config=<file>    Specify a custom config file (default:\n" \
"                                "SYSCONFDIR"/openfortivpn/config).\n" \
"  -u <user>, --username=<user>  VPN account username.\n" \
"  -p <pass>, --password=<pass>  VPN account password.\n" \
"  -o <otp>, --otp=<otp>         One-Time-Password.\n" \
"  --realm=<realm>               Use specified authentication realm on VPN gateway\n" \
"                                when tunnel is up.\n" \
"  --no-routes                   Do not try to configure IP routes through the\n" \
"                                VPN when tunnel is up.\n" \
"  --no-dns                      Do not add VPN nameservers in /etc/resolv.conf\n" \
"  --ca-file=<file>              Use specified PEM-encoded certificate bundle\n" \
"                                instead of system-wide store to verify the gateway\n" \
"                                certificate.\n" \
"  --user-cert=<file>            Use specified PEM-encoded certificate if the server\n" \
"                                requires authentication with a certificate.\n" \
"  --user-key=<file>             Use specified PEM-encoded key if the server if the\n" \
"                                server requires authentication with a certificate.\n" \
"  --use-syslog                  Log to syslog instead of terminal.\n" \
"  --trusted-cert=<digest>       Trust a given gateway. If classical SSL\n" \
"                                certificate validation fails, the gateway\n" \
"                                certificate will be matched against this value.\n" \
"                                <digest> is the X509 certificate's sha256 sum.\n" \
"                                This option can be used multiple times to trust\n" \
"                                several certificates.\n" \
"  --insecure-ssl                Do not disable insecure SSL protocols/ciphers.\n" \
"                                If your server requires a specific cipher, consider\n" \
"                                using --cipher-list instead.\n" \
"  --cipher-list=<ciphers>       Openssl ciphers to use. If default does not work\n" \
"                                you can try with the cipher suggested in the output\n" \
"                                of 'openssl s_client -connect <host:port>'\n" \
"                                (e.g. AES256-GCM-SHA384)\n" \
"  --pppd-no-peerdns             Do not ask peer ppp server for DNS addresses\n" \
"                                and do not make pppd rewrite /etc/resolv.conf\n" \
"  --pppd-log=<file>             Set pppd in debug mode and save its logs into\n" \
"                                <file>.\n" \
"  --pppd-plugin=<file>          Use specified pppd plugin instead of configuring\n" \
"                                resolver and routes directly.\n" \
"  --pppd-ipparam=<string>       Provides  an extra parameter to the ip-up, ip-pre-up\n" \
"                                and ip-down scripts. see man (8) pppd\n" \
"  -v                            Increase verbosity. Can be used multiple times\n" \
"                                to be even more verbose.\n" \
"  -q                            Decrease verbosity. Can be used multiple times\n" \
"                                to be even less verbose.\n" \
"\n" \
"Config file:\n" \
"  Options can be taken from a configuration file. Options passed in the\n" \
"  command line will override those from the config file, though. The default\n" \
"  config file is "SYSCONFDIR"/openfortivpn/config,\n" \
"  but this can be set using the -c option.\n" \
"  A simple config file example looks like:\n" \
"      # this is a comment\n" \
"      host = vpn-gateway\n" \
"      port = 8443\n" \
"      username = foo\n" \
"      password = bar\n" \
"      trusted-cert = certificatedigest4daa8c5fe6c...\n" \
"      trusted-cert = othercertificatedigest6631bf...\n" \
"  For a full-featured config see man openfortivpn(1). \n"

int main(int argc, char **argv)
{
	int ret = EXIT_FAILURE;
	struct vpn_config cfg;
	char *config_file = SYSCONFDIR"/openfortivpn/config";
	char *host, *username = NULL, *password = NULL, *otp = NULL;
	char *port_str;
	long int port;

	/* Init cfg */
	memset (&cfg, 0, sizeof (cfg));

	init_logging();

	// Set defaults
	init_vpn_config(&cfg);
	cfg.set_routes = 1;
	cfg.set_dns = 1;
	cfg.verify_cert = 1;
	cfg.insecure_ssl = 0;
	cfg.pppd_use_peerdns = 1;

	struct option long_options[] = {
		{"help",            no_argument,       0, 'h'},
		{"version",         no_argument,       0, 0},
		{"config",          required_argument, 0, 'c'},
		{"realm",           required_argument, 0, 0},
		{"username",        required_argument, 0, 'u'},
		{"password",        required_argument, 0, 'p'},
		{"otp",             required_argument, 0, 'o'},
		{"no-routes",       no_argument, &cfg.set_routes, 0},
		{"no-dns",          no_argument, &cfg.set_dns, 0},
		{"pppd-no-peerdns", no_argument, &cfg.pppd_use_peerdns, 0},
		{"use-syslog",      no_argument, &cfg.use_syslog, 1},
		{"ca-file",         required_argument, 0, 0},
		{"user-cert",       required_argument, 0, 0},
		{"user-key",        required_argument, 0, 0},
		{"trusted-cert",    required_argument, 0, 0},
		{"insecure-ssl",    no_argument, &cfg.insecure_ssl, 1},
		{"cipher-list",     required_argument, 0, 0},
		{"pppd-log",        required_argument, 0, 0},
		{"pppd-plugin",     required_argument, 0, 0},
		{"pppd-ipparam",    required_argument, 0, 0},
		{"plugin",          required_argument, 0, 0}, // deprecated
		{0, 0, 0, 0}
	};

	while (1) {
		/* getopt_long stores the option index here. */
		int c, option_index = 0;

		c = getopt_long(argc, argv, "hvqc:u:p:o:",
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
			           "pppd-plugin") == 0) {
				cfg.pppd_plugin = optarg;
				break;
			}
			if (strcmp(long_options[option_index].name,
			           "pppd-ipparam") == 0) {
				cfg.pppd_ipparam = optarg;
				break;
			}
			// --plugin is deprecated, --pppd-plugin should be used
			if (cfg.pppd_plugin == NULL &&
			    strcmp(long_options[option_index].name,
			           "plugin") == 0) {
				cfg.pppd_plugin = optarg;
				break;
			}
			if (strcmp(long_options[option_index].name,
			           "ca-file") == 0) {
				cfg.ca_file = strdup(optarg);
				break;
			}
			if (strcmp(long_options[option_index].name,
			           "user-cert") == 0) {
				cfg.user_cert = strdup(optarg);
				break;
			}
			if (strcmp(long_options[option_index].name,
			           "user-key") == 0) {
				cfg.user_key = strdup(optarg);
				break;
			}
			if (strcmp(long_options[option_index].name,
			           "realm") == 0) {
				strncpy(cfg.realm, optarg, FIELD_SIZE);
				cfg.realm[FIELD_SIZE] = '\0';
				break;
			}
			if (strcmp(long_options[option_index].name,
			           "trusted-cert") == 0) {
				if (add_trusted_cert(&cfg, optarg))
					log_warn("Could not add certificate "
					         "digest to whitelist.\n");
				break;
			}
			if (strcmp(long_options[option_index].name,
			           "cipher-list") == 0) {
				cfg.cipher_list = strdup(optarg);
				break;
			}
			goto user_error;
		case 'h':
			printf(USAGE);
			printf("\n");
			printf(HELP);
			printf("\n");
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
		case 'o':
			otp = optarg;
			break;
		default:
			goto user_error;
		}
	}

	if (optind < argc - 1 || optind > argc)
		goto user_error;
	set_syslog (cfg.use_syslog);

	if (password != NULL)
		log_warn("You should not pass the password on the command "
		         "line. Type it interactively or use a config file "
		         "instead.\n");

	// Load config file
	if (config_file[0] != '\0') {
		ret = load_config(&cfg, config_file);
		set_syslog (cfg.use_syslog);
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
		strncpy(cfg.gateway_host, host, FIELD_SIZE);
		cfg.gateway_host[FIELD_SIZE] = '\0';
		port_str++;
		port = strtol(port_str, NULL, 0);
		if (port <= 0 || port > 65535) {
			log_error("Specify a valid port.\n");
			goto user_error;
		}
		cfg.gateway_port = port;
	}
	// Read username and password from the command line
	if (username != NULL) {
		strncpy(cfg.username, username, FIELD_SIZE);
		cfg.username[FIELD_SIZE] = '\0';
	}
	if (password != NULL) {
		strncpy(cfg.password, password, FIELD_SIZE);
		cfg.password[FIELD_SIZE] = '\0';
	}
	if (otp != NULL) {
		strncpy(cfg.otp, otp, FIELD_SIZE);
		cfg.otp[FIELD_SIZE] = '\0';
	}

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
	log_debug("Config realm = \"%s\"\n", cfg.realm);
	log_debug("Config port = \"%d\"\n", cfg.gateway_port);
	log_debug("Config username = \"%s\"\n", cfg.username);
	log_debug("Config password = \"%s\"\n", "********");
	if (cfg.otp[0] != '\0')
		log_debug("One-time password = \"%s\"\n", cfg.otp);

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
