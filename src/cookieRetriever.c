/*
 * cookieRetriever.c
 *
 *  Created on: 28 apr 2024
 *      Author: filippor
 */
#include <stdio.h>
#include <stdlib.h>
#include "http.h"

#define MAX_RESPONSE_SIZE 4096
#define MAX_COOKIES 10


char* retrieve_id_with_external_browser(struct vpn_config *cfg) {
	char data[512];
	char *url = data;
	sprintf(url, "https://%s:%d/remote/saml/start?redirect=1", cfg->gateway_host,
			cfg->gateway_port);

	if (cfg->realm[0] != '\0') {
		strcat(url, "&realm=");
		char *dt = url + strlen(url);
		url_encode(dt, cfg->realm);
	}
	printf("open this address: ");
	printf(url);
	printf("\n");

	return "fakke-id";
}

