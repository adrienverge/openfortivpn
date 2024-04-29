/*
 * cookieRetriever.c
 *
 *  Created on: 28 apr 2024
 *      Author: filippor
 */
#include <stdio.h>
#include <stdlib.h>
#include "log.h"
#include "http.h"
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

#define MAX_REQUEST_SIZE 4096
// Function to parse HTTP request and extract parameter "id"
char* parse_request(const char *request) {
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
			return id_param;

		}
	}
	return NULL;
}

// Function to send HTTP response
void send_response(int sockfd, const char *message) {
	char response[MAX_REQUEST_SIZE];
	sprintf(response, "HTTP/1.1 200 OK\r\n"
			"Content-Length: %lu\r\n"
			"Content-Type: text/html\r\n\r\n"
			"%s", strlen(message), message);
	write(sockfd, response, strlen(response));
}

char* retrieve_id_with_external_browser(struct vpn_config *cfg) {
	int sockfd, newsockfd;
	struct sockaddr_in serv_addr, cli_addr;
	socklen_t clilen;
	char buffer[MAX_REQUEST_SIZE];

	// Create socket
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0) {
		log_error("Error opening socket");
		exit(1);
	}

	// Initialize server address structure
	bzero((char*) &serv_addr, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);;
	serv_addr.sin_port = htons(cfg->listen_port);

	// Bind socket to address
	if (bind(sockfd, (struct sockaddr*) &serv_addr, sizeof(serv_addr)) < 0) {
		perror("Error on binding");
		exit(1);
	}

	int opt = 1;
//	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(int))
//			< 0) {
//		log_error("error set SO_REUSEPORT");
//	}
	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
		log_error("Error setting SO_REUSEADDR");
	}

	// Listen for incoming connections
	listen(sockfd, 5);

	log_debug("Server listening on port %d to retrieve the id\n",
			cfg->listen_port);

	char data[512];
	char *url = data;
	sprintf(url, "https://%s:%d/remote/saml/start?redirect=1",
			cfg->gateway_host, cfg->gateway_port);

	if (cfg->realm[0] != '\0') {
		strcat(url, "&realm=");
		char *dt = url + strlen(url);
		url_encode(dt, cfg->realm);
	}
	log_info("open this address: %s\n", url);

	// Accept incoming connections
	clilen = sizeof(cli_addr);
	newsockfd = accept(sockfd, &cli_addr, &clilen);
	if (newsockfd < 0) {
		log_error("Error on accept");
		return NULL;
	}
	close(sockfd);

	// Read HTTP request from client
	bzero(buffer, MAX_REQUEST_SIZE);
	read(newsockfd, buffer, MAX_REQUEST_SIZE - 1);
	log_debug("Received HTTP request:\n%s\n", buffer);

	// Parse request and extract parameter "id"
	char *id = strdup(parse_request(buffer));
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

