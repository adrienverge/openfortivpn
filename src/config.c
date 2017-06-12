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

#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <string.h>
#include <ctype.h>

#include "config.h"
#include "log.h"

/*
 * Adds a sha256 digest to the list of trusted certificates.
 */
int add_trusted_cert(struct vpn_config *cfg, const char *digest)
{
	struct x509_digest *last, *new;

	new = malloc(sizeof(struct x509_digest));
	if (new == NULL)
		return ERR_CFG_NO_MEM;

	new->next = NULL;
	strncpy(new->data, digest, SHA256STRLEN - 1);
	new->data [SHA256STRLEN - 1] = '\0';

	if (cfg->cert_whitelist == NULL) {
		cfg->cert_whitelist = new;
	} else {
		for (last = cfg->cert_whitelist; last->next != NULL;
		     last = last->next) ;
		last->next = new;
	}

	return 0;
}

/*
 * Converts string to bool int
 *
 * @params[in] str  the string to read from
 * @return          0 or 1 if successful, < 0 if unrecognized value
 */
static int strtob(const char* str)
{
	if (str[0] == '\0') {
		return 0;
	} else if (strcasecmp(str, "true") == 0) {
		return 1;
	} else if (strcasecmp(str, "false") == 0) {
		return 0;
	} else if (isdigit(str[0]) == 0) {
		return -1;
	}

	long int i = strtol(str, NULL, 0);
	if (i < 0 || i > 1) {
		return -1;
	}
	return i;
}

/*
 * Reads filename contents and fill cfg with its values.
 *
 * @param[out] cfg       the struct vpn_config to store configuration values
 * @param[in]  filename  the file to read values from
 * @return               0 if successful, or < 0 in case of error
 */
int load_config(struct vpn_config *cfg, const char *filename)
{
	int ret = ERR_CFG_UNKNOWN;
	FILE *file;
	struct stat stat;
	char *buffer, *line;

	file = fopen(filename, "r");
	if (file == NULL)
		return ERR_CFG_SEE_ERRNO;

	if (fstat(fileno(file), &stat) == -1) {
		ret = ERR_CFG_SEE_ERRNO;
		goto err_close;
	}
	if (stat.st_size == 0) {
		ret = ERR_CFG_EMPTY_FILE;
		goto err_close;
	}

	buffer = malloc(stat.st_size + 1);
	if (buffer == NULL) {
		ret = ERR_CFG_NO_MEM;
		goto err_close;
	}

	// Copy all file contents at once
	if (fread(buffer, stat.st_size, 1, file) != 1) {
		ret = ERR_CFG_CANNOT_READ;
		goto err_free;
	}

	buffer[stat.st_size] = '\0';

	// Read line by line
	for (line = strtok(buffer, "\n"); line != NULL;
	     line = strtok(NULL, "\n")) {
		char *key, *equals, *val;
		int i;

		if (line[0] == '#')
			continue;

		// Expect something like: "key = value"
		equals = strchr(line, '=');
		if (equals == NULL) {
			log_warn("Bad line in config file: \"%s\".\n", line);
			continue;
		}
		equals[0] = '\0';
		key = line;
		val = equals + 1;

		// Remove heading spaces
		while (key[0] != '\0' && (key[0] == ' ' || key[0] == '\t'))
			key++;
		while (val[0] != '\0' && (val[0] == ' ' || val[0] == '\t'))
			val++;
		// Remove trailing spaces
		for (i = strlen(key) - 1; i > 0; i--) {
			if (key[i] == ' ' || key[i] == '\t')
				key[i] = '\0';
			else
				break;
		}
		for (i = strlen(val) - 1; i > 0; i--) {
			if (val[i] == ' ' || val[i] == '\t')
				val[i] = '\0';
			else
				break;
		}

		if (strcmp(key, "host") == 0) {
			strncpy(cfg->gateway_host, val, FIELD_SIZE);
			cfg->gateway_host[FIELD_SIZE] = '\0';
		} else if (strcmp(key, "port") == 0) {
			long int port = strtol(val, NULL, 0);
			if (port <= 0 || port > 65535) {
				log_warn("Bad port in config file: \"%d\".\n",
				         port);
				continue;
			}
			cfg->gateway_port = port;
		} else if (strcmp(key, "username") == 0) {
			strncpy(cfg->username, val, FIELD_SIZE - 1);
			cfg->username[FIELD_SIZE] = '\0';
		} else if (strcmp(key, "password") == 0) {
			strncpy(cfg->password, val, FIELD_SIZE - 1);
			cfg->password[FIELD_SIZE] = '\0';
		} else if (strcmp(key, "set-dns") == 0) {
			int set_dns = strtob(val);
			if (set_dns < 0) {
				log_warn("Bad set-dns in config file: \"%s\".\n",
				         val);
				continue;
			}
			cfg->set_dns = set_dns;
		} else if (strcmp(key, "set-routes") == 0) {
			int set_routes = strtob(val);
			if (set_routes < 0) {
				log_warn("Bad set-routes in config file: \"%s\".\n",
				         val);
				continue;
			}
			cfg->set_routes = set_routes;
		} else if (strcmp(key, "pppd-use-peerdns") == 0) {
			int pppd_use_peerdns = strtob(val);
			if (pppd_use_peerdns < 0) {
				log_warn("Bad pppd-use-peerdns in config file: \"%s\".\n",
				         val);
				continue;
			}
			cfg->pppd_use_peerdns = pppd_use_peerdns;
		} else if (strcmp(key, "pppd-log") == 0) {
			cfg->pppd_log = strdup(val);
		} else if (strcmp(key, "pppd-plugin") == 0) {
			cfg->pppd_plugin = strdup(val);
		} else if (strcmp(key, "pppd-ipparam") == 0) {
			cfg->pppd_ipparam = strdup(val);
		} else if (strcmp(key, "use-syslog") == 0) {
			int use_syslog = strtob(val);
			if (use_syslog < 0) {
				log_warn("Bad use-syslog in config file: \"%s\".\n",
				         val);
				continue;
			}
			cfg->use_syslog = use_syslog;
		} else if (strcmp(key, "trusted-cert") == 0) {
			if (strlen(val) != SHA256STRLEN - 1) {
				log_warn("Bad certificate sha256 digest in "
				         "config file: \"%s\".\n", val);
				continue;
			}
			if (add_trusted_cert(cfg, val))
				log_warn("Could not add certificate digest to "
				         "whitelist.\n");

		} else if (strcmp(key, "ca-file") == 0) {
			cfg->ca_file = strdup(val);
		} else if (strcmp(key, "user-cert") == 0) {
			cfg->user_cert = strdup(val);
		} else if (strcmp(key, "user-key") == 0) {
			cfg->user_key = strdup(val);
		} else if (strcmp(key, "insecure-ssl") == 0) {
			int insecure_ssl = strtob(val);
			if (insecure_ssl < 0) {
				log_warn("Bad insecure-ssl in config file: \"%s\".\n",
				         val);
				continue;
			}
			cfg->insecure_ssl = insecure_ssl;
		} else if (strcmp(key, "cipher-list") == 0) {
			cfg->cipher_list = strdup(val);
		} else {
			log_warn("Bad key in config file: \"%s\".\n", key);
			goto err_free;
		}
	}

	ret = 0;

err_free:
	free(buffer);
err_close:
	fclose(file);

	return ret;
}
