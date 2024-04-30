/*
 *  Copyright (c) 2024 Filippo Rossoni
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
#include "idlistener.h"
#include "log.h"
#include "http.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

#define MAX_REQUEST_SIZE 4096

static void print_url(struct vpn_config *cfg) {
	char url[512];
	snprintf(url, sizeof(url), "https://%s:%d/remote/saml/start?redirect=1",
			cfg->gateway_host, cfg->gateway_port);

	if (cfg->realm[0] != '\0') {
		strncat(url, "&realm=", sizeof(url) - 1);
		char *dt = url + strlen(url);
		url_encode(dt, cfg->realm);
	}
	log_info("Authenticate at %s\n", url);
}

// Function to parse HTTP request and extract parameter "id"
static char* parse_request(const char *request) {
	char *id_param;
	char *query_start = strchr(request, '?');
	if (query_start != NULL) {
		id_param = strstr(query_start, "id=");
		if (id_param != NULL) {
			id_param += 3; // Length of "id="
			char *id_end = strchr(id_param, '&');
			if (id_end == NULL) {
				id_end = strchr(id_param, ' ');
			}
			if (id_end == NULL) {
				id_end = strchr(id_param, '\r');
			}
			if (id_end == NULL) {
				id_end = id_param + strlen(id_param); // End of string
			}
			*id_end = '\0'; // Null-terminate the string
			return strdup(id_param);

		}
	}
	return NULL;
}

void send_response(int sockfd, const char *message) {
	char response[MAX_REQUEST_SIZE];
	sprintf(response, "HTTP/1.1 200 OK\r\n"
			"Content-Length: %lu\r\n"
			"Content-Type: text/html\r\n\r\n"
			"%s", strlen(message), message);
	write(sockfd, response, strlen(response));
}

char* listen_for_id(struct vpn_config *cfg) {
	int sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0) {
		log_error("Error opening socket");
		exit(1);
	}

	struct sockaddr_in serv_addr;
	bzero((char*) &serv_addr, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	serv_addr.sin_port = htons(cfg->listen_port);

	if (bind(sockfd, (struct sockaddr*) &serv_addr, sizeof(serv_addr)) < 0) {
		perror("Error on binding");
		exit(1);
	}

	int opt = 1;
	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
		log_error("Error setting SO_REUSEADDR");
	}
	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(int)) < 0) {
		log_error("error set SO_REUSEPORT");
	}

	listen(sockfd, 1);
	log_debug("Server listening on port %d to retrieve the id\n",
			cfg->listen_port);

	print_url(cfg);

	// Accept incoming connections
	struct sockaddr_in cli_addr;
	socklen_t clilen = sizeof(cli_addr);
	int newsockfd = accept(sockfd, &cli_addr, &clilen);
	if (newsockfd < 0) {
		log_error("Error on accept");
		return NULL;
	}
	close(sockfd);

	// Read HTTP request from client
	char buffer[MAX_REQUEST_SIZE];
	bzero(buffer, MAX_REQUEST_SIZE);
	read(newsockfd, buffer, MAX_REQUEST_SIZE - 1);
	log_debug("Received HTTP request:\n%s\n", buffer);

	char *id = parse_request(buffer);
	if (id != NULL) {
		log_debug("Extracted id: %s\n", id);
		// Send response to client
		send_response(newsockfd,
				"<html><body><h1>ID retrieved. Connecting...!</h1></body></html>");
	} else {
		log_error("id parameter not found\n");
		send_response(newsockfd,
				"<html><body><h1>ERROR! id not found</h1></body></html>");
	}
	close(newsockfd);

	return id;
}

