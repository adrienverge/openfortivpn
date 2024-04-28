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
#include <curl/curl.h>

#define COOKIE_NAME "SVPNCOOKIE"

char* get_cookie_value(const char *cookie_name, struct curl_slist *cookies) {
	struct curl_slist *cookie;
	for (cookie = cookies; cookie; cookie = cookie->next) {
		char *cookie_str = cookie->data;
		// Tokenize the cookie string by tabs
		char *token = strtok(cookie_str, "\t");
		int token_count = 0;
		while (token != NULL) {
			switch (++token_count) {
			// Skip the first 5 tokens (domain, secure flag, path, HTTP-only flag, expiry time)
			case 6: // Check the cookie name
				if (strcmp(token, cookie_name) != 0) {
					// If the cookie name doesn't match, break out of the loop
					continue;
				}
				break;
			case 7: // Get the cookie value
				return token;
				break;
			case 8:
				continue;
			}
			// Move to the next token
			token = strtok(NULL, "\t");
		}

	}
	return NULL; // Cookie not found
}
// Dummy write function that does nothing
size_t discard_response(void *ptr, size_t size, size_t nmemb, void *userdata) {
	return size * nmemb;
}
char* retrieve_cookie_from_id(struct vpn_config *cfg) {
	char urlBuf[512];
	urlBuf[0] = '\0';
	char *request_url = urlBuf;
	sprintf(request_url, "https://%s:%d/remote/saml/auth_id?id=%s",
			cfg->gateway_host, cfg->gateway_port, cfg->auth_id);
	log_debug("Connecting to to %s \n", request_url);

	CURL *curl_handle;
	CURLcode res;

	char *cookie_value = NULL;

	curl_global_init(CURL_GLOBAL_ALL);
	curl_handle = curl_easy_init();
	if (curl_handle) {
		curl_easy_setopt(curl_handle, CURLOPT_URL, request_url);

		// Follow redirections
		curl_easy_setopt(curl_handle, CURLOPT_FOLLOWLOCATION, 1L);

		// Enable cookie handling
		curl_easy_setopt(curl_handle, CURLOPT_COOKIEFILE, ""); // Enable cookie engine
		// Set a dummy write function to discard response body
		curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, discard_response);

		// Disable SSL certificate verification
		curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYPEER, 0L);
		curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYHOST, 0L);
		// Perform the request
		res = curl_easy_perform(curl_handle);

		// Check for errors
		if (res != CURLE_OK) {
			log_error("Authentication with id failed: %s\n",
					curl_easy_strerror(res));
		} else {
			// Extract the cookie using the built-in cookie engine
			struct curl_slist *cookies;
			res = curl_easy_getinfo(curl_handle, CURLINFO_COOKIELIST, &cookies);
			if (res == CURLE_OK) {
				cookie_value = strdup(get_cookie_value(COOKIE_NAME, cookies));
				if (cookie_value) {
					log_debug("Found cookie %s value: %s\n", COOKIE_NAME,
							cookie_value);
				} else {
					log_error("Cookie %s not found in response from \"%s\"\n",
							COOKIE_NAME, request_url);
				}
				curl_slist_free_all(cookies);
			} else {
				log_error("curl_easy_getinfo(CURLINFO_COOKIELIST) failed: %s\n",
						curl_easy_strerror(res));
			}
		}
		curl_easy_cleanup(curl_handle);
	}
	curl_global_cleanup();

	return cookie_value;

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

