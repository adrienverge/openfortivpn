/*
 * cookieRetriever.c
 *
 *  Created on: 28 apr 2024
 *      Author: filippor
 */
#include "cookieRetriever.h"
#include <stdio.h>
#include "http.h"
#include "log.h"
char* retrieve_cookie_from_id(struct vpn_config *cfg) {
	char urlBuf[512];
	urlBuf[0] ='\0';
	char *url = urlBuf;
	sprintf(url, "https://%s:%d/remote/saml/auth_id?id=%s", cfg->gateway_host,
			cfg->gateway_port,cfg->auth_id);
	log_debug("Connecting to to %s \n",url );


	char *buf = "SPVTOKEN=fake-token";
	return buf;

}

char* retrieve_cookie_with_external_browser(struct vpn_config *cfg) {
	char data[512];
	char *d = data;
	sprintf(d, "https://%s:%d/remote/saml/start?redirect=1", cfg->gateway_host,
			cfg->gateway_port);

	if (cfg->realm[0] != '\0') {
		strcat(d, "&realm=");
		char *dt = d + strlen(d);
		url_encode(dt, cfg->realm);
	}
	printf("open this address: ");
	printf(d);
	printf("\n");
	char *buf = "SPVTOKEN=fake-token";
	return buf;
}

