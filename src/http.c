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
#include "ssl.h"

#define BUFSZ 0x8000

/*
 * Sends data to the HTTP server.
 *
 * @param[in] request  the data to send to the server
 * @return    1        in case of success
 *            < 0      in case of error
 */
int http_send(struct tunnel *tunnel, const char *request, ...)
{
	va_list args;
	char buffer[BUFSZ];
	int length;
	int n = 0;

	va_start(args, request);
	length = vsnprintf(buffer, BUFSZ, request, args);
	va_end(args);

	if (length < 0)
		return ERR_HTTP_INVALID;
	else if (length == BUFSZ)
		return ERR_HTTP_TOO_LONG;

	while (n == 0)
		n = safe_ssl_write(tunnel->ssl_handle, (uint8_t *) buffer,
				   length);
	if (n < 0) {
		log_debug("Error writing to SSL connection (%s).\n",
			  err_ssl_str(n));
		return ERR_HTTP_SSL;
	}

	return 1;
}

/*
 * Receives data from the HTTP server.
 *
 * @param[out] response  if not NULL, this pointer is set to reference
 *                       the new allocated buffer containing the data
 *                       sent by the server
 * @return     1         in case of success
 *             < 0       in case of error
 */
int http_receive(struct tunnel *tunnel, char **response)
{
	char *buffer, *res;
	int n = 0;
	int bytes_read = 0;

	buffer = malloc(BUFSZ);
	if (buffer == NULL)
		return ERR_HTTP_NO_MEM;

	do {
		n = safe_ssl_read(tunnel->ssl_handle,
				  (uint8_t *) buffer + bytes_read,
				  BUFSZ - 1 - bytes_read);
		if (n > 0) {
			bytes_read += n;

			if (bytes_read >= 4
			    && !memcmp(&buffer[bytes_read - 4], "\r\n\r\n", 4))
				break;

			if (bytes_read == BUFSZ - 1) {
				log_warn("Response too big\n");
				free(buffer);
				return ERR_HTTP_SSL;
			}
		}
	} while (n >= 0);

	if (n < 0) {
		log_debug("Error reading from SSL connection (%s).\n",
			  err_ssl_str(n));
		free(buffer);
		return ERR_HTTP_SSL;
	}

	if (response == NULL) {
		free(buffer);
		return 1;
	}

	res = realloc(buffer, bytes_read + 1);
	if (res == NULL) {
		free(buffer);
		return ERR_HTTP_NO_MEM;
	}
	res[bytes_read] = '\0';

	*response = res;
	return 1;
}

static int do_http_request(struct tunnel *tunnel, const char *method,
			   const char *uri, const char *data, char **response)
{
	int ret;
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

	ret = http_send(tunnel, template, method, uri,
			tunnel->config->gateway_host,
			tunnel->config->gateway_port, tunnel->config->cookie,
			strlen(data), data);
	if (ret != 1)
		return ret;

	return http_receive(tunnel, response);
}
/*
 * Sends and receives data from the HTTP server.
 *
 * @param[out] response  if not NULL, this pointer is set to reference
 *                       the new allocated buffer containing the data
 *                       sent by the server
 * @return     1         in case of success
 *             < 0       in case of error
 */
static int http_request(struct tunnel *tunnel, const char *method,
			const char *uri, const char *data, char **response)
{
	int ret = do_http_request (tunnel, method, uri, data, response);

	if (ret == ERR_HTTP_SSL) {
		ssl_connect (tunnel);
		ret = do_http_request (tunnel, method, uri, data, response);
	}

	if (ret != 1)
		log_warn("Error issuing %s request\n", uri);

	return ret;
}

/*
 * Authenticates to gateway by sending username and password.
 *
 * @return  1   in case of success
 *          < 0 in case of error
 */
int auth_log_in(struct tunnel *tunnel)
{
	int ret;
	char data[256];
	char *res, *line, *end;

	tunnel->config->cookie[0] = '\0';

	snprintf(data, 256, "username=%s&credential=%s&realm=&ajax=1"
		 "&redir=%%2Fremote%%2Findex&just_logged_in=1",
		 tunnel->config->username, tunnel->config->password);

	ret = http_request(tunnel, "POST", "/remote/logincheck", data, &res);
	if (ret != 1)
		return ret;

	if (strncmp(res, "HTTP/1.1 200 OK\r\n", 17)) {
		ret = ERR_HTTP_BAD_RES_CODE;
		goto end;
	}

	ret = ERR_HTTP_NO_COOKIE;
	// Look for cookie in the headers
	line = strtok(res, "\r\n\r\n");
	while (line != NULL) {
		if (strncmp(line, "Set-Cookie: SVPNCOOKIE=", 23) == 0) {
			line = &line[12];
			if (line[11] == ';' || line[11] == '\0') {
				log_debug("Empty cookie.\n");
			} else {
				end = strstr(line, ";");
				if (end != NULL)
					end[0] = '\0';
				strncpy(tunnel->config->cookie, line,
					COOKIE_SIZE);
				ret = 1; // success
				goto end;
			}
		} else if (strstr(line, "permission_denied denied") ||
			   strstr(line, "Permission denied")) {
			ret = ERR_HTTP_PERMISSION;
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
	return http_request(tunnel, "GET", "/remote/logout", "", NULL);
}

int auth_request_vpn_allocation(struct tunnel *tunnel)
{
	int ret = http_request(tunnel, "GET", "/remote/index", "", NULL);
	if (ret != 1)
		return ret;

	return http_request(tunnel, "GET", "/remote/fortisslvpn", "", NULL);
}
