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

#include "http.h"
#include "log.h"

#define BUFSZ 0x1000

/*
 * Send data to the HTTP server.
 */
int http_send(struct tunnel *tunnel, const char *request, ...)
{
	va_list args;
	char buffer[BUFSZ];
	int length;

	va_start(args, request);
	length = vsnprintf(buffer, BUFSZ, request, args);
	va_end(args);

	if (length < 0) {
		log_error("vsnprintf output error\n");
		return 1;
	} else if (length == BUFSZ) {
		log_error("vsnprintf error: request too long\n");
		return 1;
	}

	//log_info("%s\n", buffer);

	//if (BIO_write(tunnel->ssl_bio, buffer, length) < length) {
	//	log_error("BIO_write error\n");
	if (SSL_write(tunnel->ssl_handle, buffer, length) < length) {
		log_error("SSL_write error\n");
		return 1;
	}

	return 0;
}

/*
 * Receives data from the HTTP server.
 *
 * If response is not NULL, sets it to a the new allocated buffer containing
 * the answer.
 */
int http_receive(struct tunnel *tunnel, char **response)
{
	char *buffer, *res;
	int n;

	buffer = malloc(BUFSZ);
	if (buffer == NULL)
		return 1;

	n = SSL_read(tunnel->ssl_handle, buffer, BUFSZ - 1);
	//n = BIO_read(tunnel->ssl_bio, buffer, BUFSZ - 1);
	if (n <= 0)
		goto err;

	if (response == NULL) {
		free(buffer);
		return 0;
	}

	res = realloc(buffer, n + 1);
	if (res == NULL)
		goto err;
	res[n] = '\0';
	*response = res;
	return 0;

err:
	free(buffer);
	return 1;
}

/*
 * Sends and receives data from the HTTP server.
 *
 * If response is not NULL, sets it to a the new allocated buffer containing
 * the answer.
 */
static int http_request(struct tunnel *tunnel, const char *method,
		const char *uri, const char *data, char **response)
{
	char template[] =
		"%s %s HTTP/1.1\r\n"
		"Host: %s:%d\r\n"
		"User-Agent: Mozilla/5.0 SV1\r\n"
		"Accept: text/plain\r\n"
		"Accept-Encoding: identify\r\n"
		"Content-Type: application/x-www-form-urlencoded\r\n"
		"Cookie: %s\r\n"
		"Content-Length: %d\r\n"
		"\r\n%s";

	if (http_send(tunnel, template, method, uri,
		tunnel->config->gateway_host, tunnel->config->gateway_port,
		tunnel->config->cookie, strlen(data), data))
		return 1;
	if (http_receive(tunnel, response))
		return 1;

	return 0;
}

int auth_log_in(struct tunnel *tunnel)
{
	int ret = -1;
	char data[256];
	char *res, *line, *end;

	tunnel->config->cookie[0] = '\0';

	snprintf(data, 256, "username=%s&credential=%s&realm=&ajax=1"
		"&redir=%%2Fremote%%2Findex&just_logged_in=1",
		tunnel->config->username, tunnel->config->password);

	if (http_request(tunnel, "POST", "/remote/logincheck", data, &res))
		return -1;
	//log_info("%s\n", res);

	if (strncmp(res, "HTTP/1.1 200 OK\r\n", 17))
		goto end;

	// Look for cookie in the headers
	line = strtok(res, "\r\n\r\n");
	while (line != NULL) {
		if (strncmp(line, "Set-Cookie: SVPNCOOKIE=", 23) == 0) {
			line = &line[12];
			if (line[11] == ';' || line[11] == '\0') {
				log_warn("Empty cookie\n");
			} else {
				end = strstr(line, ";");
				if (end != NULL)
					end[0] = '\0';
				strncpy(tunnel->config->cookie, line, COOKIE_SIZE);
				ret = 0;
				goto end;
			}
		} else if (strstr(line, "permission_denied denied") ||
				strstr(line, "Permission denied")) {
			ret = 1;
			goto end;
		}
		line = strtok(NULL, "\r\n");
	}
end:
	free(res);
	return ret;
}

int auth_log_out(struct tunnel *tunnel)
{
	if (http_request(tunnel, "GET", "/remote/logout", "", NULL))
		return 1;

	return 0;
}

int auth_request_vpn_allocation(struct tunnel *tunnel)
{
	if (http_request(tunnel, "GET", "/remote/index", "", NULL))
		return 1;
	if (http_request(tunnel, "GET", "/remote/fortisslvpn", "", NULL))
		return 1;

	return 0;
}
