/*
 *  Copyright (c) 2025 Rainer Keller
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
 *  Windows implementation of the embedded HTTP server for SAML login.
 *  Uses Winsock2 recv/send instead of POSIX read/write.
 */

#ifdef _WIN32

#include "http_server.h"
#include "log.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define HTTP_BUF_SIZE 8192

static const char http_response[] =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html\r\n"
        "Connection: close\r\n\r\n"
        "<html><body><h1>Authentication successful</h1><p>You can close this window and return to the terminal.</p></body></html>";

/*
 * Parse SAML cookie and session ID from the HTTP GET request.
 */
static int parse_saml_request(const char *request, struct vpn_config *config)
{
	const char *cookie_start, *session_start;
	const char *value_start, *value_end;

	/* Look for id= parameter */
	session_start = strstr(request, "id=");
	if (session_start) {
		value_start = session_start + 3;
		value_end = strchr(value_start, '&');
		if (!value_end)
			value_end = strchr(value_start, ' ');
		if (!value_end)
			value_end = value_start + strlen(value_start);

		size_t len = value_end - value_start;

		if (len >= MAX_SAML_SESSION_ID_LENGTH)
			len = MAX_SAML_SESSION_ID_LENGTH;
		strncpy(config->saml_session_id, value_start, len);
		config->saml_session_id[len] = '\0';
	}

	/* Look for SVPNCOOKIE in the request */
	cookie_start = strstr(request, "SVPNCOOKIE=");
	if (!cookie_start)
		cookie_start = strstr(request, "cookie=");
	if (cookie_start) {
		value_start = strchr(cookie_start, '=') + 1;
		value_end = strchr(value_start, '&');
		if (!value_end)
			value_end = strchr(value_start, ' ');
		if (!value_end)
			value_end = value_start + strlen(value_start);

		size_t len = value_end - value_start;

		if (len > COOKIE_SIZE)
			len = COOKIE_SIZE;

		if (config->cookie)
			free(config->cookie);
		config->cookie = malloc(len + 1);
		if (config->cookie) {
			strncpy(config->cookie, value_start, len);
			config->cookie[len] = '\0';
		}
	}

	return (config->cookie != NULL) ? 0 : -1;
}

int wait_for_http_request(struct vpn_config *config)
{
	SOCKET server_sock = INVALID_SOCKET;
	SOCKET client_sock = INVALID_SOCKET;
	struct sockaddr_in addr;
	char buffer[HTTP_BUF_SIZE];
	int ret = -1;
	int opt = 1;
	fd_set read_fds;
	struct timeval timeout;

	/* Create listening socket */
	server_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (server_sock == INVALID_SOCKET) {
		log_error("socket: %d\n", WSAGetLastError());
		return -1;
	}

	setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR,
	           (const char *)&opt, sizeof(opt));

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	addr.sin_port = htons(config->saml_port);

	if (bind(server_sock, (struct sockaddr *)&addr, sizeof(addr)) ==
	    SOCKET_ERROR) {
		log_error("bind: %d\n", WSAGetLastError());
		goto cleanup;
	}

	if (listen(server_sock, 1) == SOCKET_ERROR) {
		log_error("listen: %d\n", WSAGetLastError());
		goto cleanup;
	}

	log_info("Waiting for SAML login on port %d...\n", config->saml_port);
	log_info("Open http://127.0.0.1:%d in your browser to authenticate.\n",
	         config->saml_port);

	/* Wait for connection with timeout */
	while (1) {
		FD_ZERO(&read_fds);
		FD_SET(server_sock, &read_fds);
		timeout.tv_sec = 10;
		timeout.tv_usec = 0;

		int sel = select(0, &read_fds, NULL, NULL, &timeout);

		if (sel == SOCKET_ERROR) {
			log_error("select: %d\n", WSAGetLastError());
			goto cleanup;
		}
		if (sel == 0) {
			/* Timeout - check if we should stop */
			continue;
		}

		client_sock = accept(server_sock, NULL, NULL);
		if (client_sock == INVALID_SOCKET)
			continue;

		/* Read HTTP request */
		int bytes = recv(client_sock, buffer, sizeof(buffer) - 1, 0);

		if (bytes > 0) {
			buffer[bytes] = '\0';
			log_debug("SAML HTTP request: %s\n", buffer);

			/* Parse and extract cookie/session */
			if (parse_saml_request(buffer, config) == 0) {
				/* Send success response */
				send(client_sock, http_response,
				     (int)strlen(http_response), 0);
				closesocket(client_sock);
				ret = 0;
				break;
			}

			/* Send response even on failure */
			send(client_sock, http_response,
			     (int)strlen(http_response), 0);
		}

		closesocket(client_sock);
		client_sock = INVALID_SOCKET;
	}

cleanup:
	if (client_sock != INVALID_SOCKET)
		closesocket(client_sock);
	if (server_sock != INVALID_SOCKET)
		closesocket(server_sock);

	return ret;
}

#endif /* _WIN32 */
