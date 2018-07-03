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
#include "xml.h"
#include "ssl.h"
#include "ipv4.h"
#include "userinput.h"
#include "log.h"

#include <ctype.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#define BUFSZ 0x8000

/*
 * URL-encodes a string for HTTP requests.
 *
 * The dest buffer size MUST be at least strlen(str) * 3 + 1.
 *
 * @param[out] dest  the buffer to write the URL-encoded string
 * @param[in]  str   the input string to be escaped
 */
static void url_encode(char *dest, const char *str)
{
	while (*str != '\0') {
		if (isalnum(*str) || *str == '-' || *str == '_'
		    || *str == '.' || *str == '~')
			*dest++ = *str;
		else if (*str == ' ')
			*dest++ = '+';
		else {
			static const char hex[] = "0123456789abcdef";

			*dest++ = '%';
			*dest++ = hex[*str >> 4];
			*dest++ = hex[*str & 15];
		}
		str++;
	}
	*dest = '\0';
}

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
	else if (length >= BUFSZ)
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

static const char *find_header(const char *res, const char *header)
{
	const char *line = res;

	while (memcmp(line, "\r\n", 2)) {
		int line_len = (char *) memmem(line, BUFSZ, "\r\n", 2) - line;
		int head_len = strlen(header);

		if (line_len >= head_len && !strncasecmp(line, header, head_len))
			return line + head_len;
		line += line_len + 2;
	}

	return NULL;
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
	int header_size = 0;
	int content_size = 0;
	int chunked = 0;

	buffer = malloc(BUFSZ);
	if (buffer == NULL)
		return ERR_HTTP_NO_MEM;

	do {
		n = safe_ssl_read(tunnel->ssl_handle,
		                  (uint8_t *) buffer + bytes_read,
		                  BUFSZ - 1 - bytes_read);
		if (n > 0) {
			const char *eoh;

			bytes_read += n;

			if (!header_size) {
				/* Did we see the header end? Then get the body size. */
				eoh = memmem(buffer, bytes_read, "\r\n\r\n", 4);
				if (eoh) {
					const char *header;

					header = find_header(buffer, "Content-Length: ");
					header_size = eoh - buffer + 4;
					if (header)
						content_size = atoi(header);

					if (find_header(buffer,
					                "Transfer-Encoding: chunked"))
						chunked = 1;
				}
			}

			if (header_size) {
				/* We saw the whole header, */
				/* let's check if the body is done as well */
				if (chunked) {
					/* Last chunk terminator. Done naively. */
					if (bytes_read >= 7 &&
					    !memcmp(&buffer[bytes_read - 7],
					            "\r\n0\r\n\r\n", 7))
						break;
				} else {
					if (bytes_read >= header_size + content_size)
						break;
				}
			}

			if (bytes_read == BUFSZ - 1) {
				log_warn("Response too big\n");
				free(buffer);
				return ERR_HTTP_SSL;
			}
		}
	} while (n >= 0);

	if (!header_size) {
		log_debug("Error reading from SSL connection (%s).\n",
		          err_ssl_str(n));
		free(buffer);
		return ERR_HTTP_SSL;
	}

	if (memmem(&buffer[header_size], bytes_read - header_size,
	           "<!--sslvpnerrmsgkey=sslvpn_login_permission_denied-->", 53) ||
	    memmem(buffer, header_size, "permission_denied denied", 24) ||
	    memmem(buffer, header_size, "Permission denied", 17)) {
		free(buffer);
		return ERR_HTTP_PERMISSION;
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
	const char *template = ("%s %s HTTP/1.1\r\n"
	                        "Host: %s:%d\r\n"
	                        "User-Agent: Mozilla/5.0 SV1\r\n"
	                        "Accept: text/plain\r\n"
	                        "Accept-Encoding: identify\r\n"
	                        "Content-Type: application/x-www-form-urlencoded\r\n"
	                        "Cookie: %s\r\n"
	                        "Content-Length: %d\r\n"
	                        "\r\n%s");

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
	int ret = do_http_request(tunnel, method, uri, data, response);

	if (ret == ERR_HTTP_SSL) {
		ssl_connect(tunnel);
		ret = do_http_request(tunnel, method, uri, data, response);
	}

	if (ret != 1)
		log_warn("Error issuing %s request\n", uri);

	return ret;
}

/*
 * Read value for key from a string like "key1=value1&key2=value2".
 * The `key` arg is supposed to contains the final "=".
 *
 * @return  1   in case of success
 *          -1  key not found
 *          -2  value too large for buffer
 *          -3  if no memory
 */
static int get_value_from_response(const char *buf, const char *key,
                                   char *retbuf, size_t retbuflen)
{
	int ret = -1;
	char *tokens;
	size_t keylen = strlen(key);

	tokens = strdup(buf);
	if (tokens == NULL) {
		ret = -3;
		goto end;
	}

	for (const char *kv_pair = strtok(tokens, "&,\r\n");
	     kv_pair != NULL;
	     kv_pair = strtok(NULL, "&,\r\n")) {
		if (strncmp(key, kv_pair, keylen) == 0) {
			const char *val = &kv_pair[keylen];

			if (strlen(val) > retbuflen - 1) {  // value too long
				ret = -2;
			} else {
				strcpy(retbuf, val);
				ret = 1;
			}
			break;
		}
	}

	free(tokens);
end:
	return ret;
}

static int get_auth_cookie(struct tunnel *tunnel, char *buf)
{
	int ret = 0;
	const char *line;

	ret = ERR_HTTP_NO_COOKIE;

	line = find_header(buf, "Set-Cookie: ");
	if (line) {
		if (strncmp(line, "SVPNCOOKIE=", 11) == 0) {
			if (line[11] == ';' || line[11] == '\0') {
				log_debug("Empty cookie.\n");
			} else {
				char *end;
				end = strstr(line, "\r");
				end[0] = '\0';
				end = strstr(line, ";");
				if (end != NULL)
					end[0] = '\0';
				log_debug("Cookie: %s\n", line);
				strncpy(tunnel->config->cookie, line, COOKIE_SIZE);
				tunnel->config->cookie[COOKIE_SIZE] = '\0';
				if (strlen(line) > COOKIE_SIZE) {
					log_error("Cookie larger than expected: %zu > %d\n",
					          strlen(line), COOKIE_SIZE);
				} else {
					ret = 1; // success
				}
			}
		}
	}
	return ret;
}

static
int try_otp_auth(struct tunnel *tunnel, const char *buffer, char **res)
{
	char data[256];
	char path[40];
	char tmp[40];
	char prompt[80];
	const char *t = NULL, *n = NULL, *v = NULL, *e = NULL;
	const char *s = buffer;
	char *d = data;
	const char *p = NULL;
	/* Length-check for destination buffer */
#define SPACE_AVAILABLE(sz) (sizeof(data) - (d - data) >= (sz))
	/* Get the form action */
	s = strcasestr(s, "<FORM");
	if (s == NULL)
		return -1;
	s = strcasestr(s + 5, "ACTION=\"");
	if (s == NULL)
		return -1;
	s += 8;
	e = strchr(s, '"');
	if (e == NULL)
		return -1;
	if (e - s + 1 > sizeof(path))
		return -1;
	strncpy(path, s, e - s);
	path[e - s] = '\0';
	/* Try to get password prompt, asume it starts with 'Please'
	 * Fall back to default prompt if not found/parseable
	 */
	p = strstr(s, "Please");
	if (p) {
		e = strchr(p, '<');
		if (e != NULL) {
			if (e - p + 1 < sizeof(prompt)) {
				strncpy(prompt, p, e - p);
				prompt[e - p] = '\0';
				p = prompt;
			} else {
				p = NULL;
			}
		} else {
			p = NULL;
		}
	}
	if (p == NULL)
		p = "Please enter one-time password:";
	/* Search for all inputs */
	while ((s = strcasestr(s, "<INPUT"))) {
		s += 6;
		/* check if we found parameters for a later INPUT
		 * during last round
		 */
		if (s < t || s < n || (v && s < v))
			return -1;
		t = strcasestr(s, "TYPE=\"");
		n = strcasestr(s, "NAME=\"");
		v = strcasestr(s, "VALUE=\"");
		if (t == NULL)
			return -1;
		if (n == NULL)
			continue;
		n += 6;
		t += 6;
		if (strncmp(t, "hidden", 6) == 0 || strncmp(t, "password", 8) == 0) {
			/* We try to be on the safe side
			 * and url-encode the variable name
			 */
			/* Append '&' if we found something in last round */
			if (d > data) {
				if (!SPACE_AVAILABLE(1))
					return -1;
				*d++ = '&';
			}
			e = strchr(n, '"');
			if (e == NULL)
				return -1;
			if (e - n + 1 > sizeof(tmp))
				return -1;
			strncpy(tmp, n, e - n);
			tmp[e - n] = '\0';
			if (!SPACE_AVAILABLE(3 * (e - n) + 1))
				return -1;
			url_encode(d, tmp);
			d += strlen(d);
			if (!SPACE_AVAILABLE(1))
				return -1;
			*d++ = '=';
		}
		if (strncmp(t, "hidden", 6) == 0) {
			/* Require value for hidden fields */
			if (v == NULL)
				return -1;
			v += 7;
			e = strchr(v, '"');
			if (e == NULL)
				return -1;
			if (e - v + 1 > sizeof(tmp))
				return -1;
			strncpy(tmp, v, e - v);
			tmp[e - v] = '\0';
			if (!SPACE_AVAILABLE(3 * (e - v) + 1))
				return -1;
			url_encode(d, tmp);
			d += strlen(d);
		} else if (strncmp(t, "password", 8) == 0) {
			struct vpn_config *cfg = tunnel->config;
			size_t l;
			v = NULL;
			if (cfg->otp[0] == '\0') {
				read_password(p, cfg->otp, FIELD_SIZE);
				if (cfg->otp[0] == '\0') {
					log_error("No OTP specified\n");
					return 0;
				}
			}
			l = strlen(cfg->otp);
			if (!SPACE_AVAILABLE(3 * l + 1))
				return -1;
			url_encode(d, cfg->otp);
			d += strlen(d);
		} else if (strncmp(t, "submit", 6) == 0) {
			/* avoid adding another '&' */
			n = v = e = NULL;
		}
	}
	if (!SPACE_AVAILABLE(1))
		return -1;
	*d++ = '\0';
	return http_request(tunnel, "POST", path, data, res);
#undef SPACE_AVAILABLE
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
	char username[3 * FIELD_SIZE + 1];
	char password[3 * FIELD_SIZE + 1];
	char realm[3 * FIELD_SIZE + 1];
	char reqid[32] = { '\0' };
	char polid[32] = { '\0' };
	char group[128] = { '\0' };
	char data[256], token[128], tokenresponse[256];
	char *res = NULL;

	url_encode(username, tunnel->config->username);
	url_encode(password, tunnel->config->password);
	url_encode(realm, tunnel->config->realm);

	tunnel->config->cookie[0] = '\0';

	snprintf(data, 256, "username=%s&credential=%s&realm=%s&ajax=1"
	         "&redir=%%2Fremote%%2Findex&just_logged_in=1",
	         username, password, realm);

	ret = http_request(tunnel, "POST", "/remote/logincheck", data, &res);
	if (ret != 1)
		goto end;

	/* Probably one-time password required */
	if (strncmp(res, "HTTP/1.1 401 Authorization Required\r\n", 37) == 0) {
		ret = try_otp_auth(tunnel, res, &res);
		if (ret != 1)
			goto end;
	}

	if (strncmp(res, "HTTP/1.1 200 OK\r\n", 17)) {
		ret = ERR_HTTP_BAD_RES_CODE;
		goto end;
	}
	ret = get_auth_cookie(tunnel, res);
	if (ret == ERR_HTTP_NO_COOKIE) {
		struct vpn_config *cfg = tunnel->config;

		/* If the response body includes a tokeninfo= parameter,
		 * it means the VPN gateway expects two-factor authentication.
		 * It sends a one-time authentication credential for example
		 * by email or SMS, and expects to receive it back in the
		 * second authentication stage. No SVPNCOOKIE will be provided
		 * until after the second call to /remote/logincheck.
		 *
		 * If we receive neither a tokeninfo= parameter nor an
		 * SVPNCOOKIE, it means our authentication attempt was
		 * rejected.
		 */

		ret = get_value_from_response(res, "tokeninfo=", token, 128);
		if (ret != 1) {
			// No SVPNCOOKIE and no tokeninfo, return error.
			ret = ERR_HTTP_NO_COOKIE;
			goto end;
		}
		// Two-factor authentication needed.
		get_value_from_response(res, "grp=", group, 128);
		get_value_from_response(res, "reqid=", reqid, 32);
		get_value_from_response(res, "polid=", polid, 32);

		if (cfg->otp[0] == '\0') {
			read_password("Two-factor authentication token: ",
			              cfg->otp, FIELD_SIZE);
			if (cfg->otp[0] == '\0') {
				log_error("No token specified\n");
				return 0;
			}
		}

		url_encode(tokenresponse, cfg->otp);
		snprintf(data, 256, "username=%s&realm=%s&reqid=%s&polid=%s&grp=%s"
		         "&code=%s&code2=&redir=%%2Fremote%%2Findex&just_logged_in=1",
		         username, realm, reqid, polid, group, tokenresponse);

		ret = http_request(tunnel, "POST", "/remote/logincheck", data, &res);
		if (ret != 1)
			goto end;

		if (strncmp(res, "HTTP/1.1 200 OK\r\n", 17)) {
			ret = ERR_HTTP_BAD_RES_CODE;
			goto end;
		}

		ret = get_auth_cookie(tunnel, res);
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

static int parse_xml_config(struct tunnel *tunnel, const char *buffer)
{
	const char *val;
	char *gateway;

	if (strncmp(buffer, "HTTP/1.1 200 OK\r\n", 17))
		return ERR_HTTP_BAD_RES_CODE;

	// Skip the HTTP header
	buffer = strstr(buffer, "\r\n\r\n");

	// The address of a local end of a router
	val = xml_find('<', "assigned-addr", buffer, 1);
	gateway = xml_get(xml_find(' ', "ipv4=", val, 1));
	if (!gateway)
		log_warn("No gateway address, using interface for routing\n");

	// Routes the tunnel wants to push
	val = xml_find('<', "split-tunnel-info", buffer, 1);
	while ((val = xml_find('<', "addr", val, 2))) {
		char *dest, *mask;
		dest = xml_get(xml_find(' ', "ip=", val, 1));
		if (!dest) {
			log_warn("No ip address for a route\n");
			continue;
		}

		mask = xml_get(xml_find(' ', "mask=", val, 1));
		if (!mask) {
			log_warn("No mask for a route\n");
			free(dest);
			continue;
		}

		ipv4_add_split_vpn_route(tunnel, dest, mask, gateway);

		free(dest);
		free(mask);
	}

	free(gateway);

	return 1;
}

static
int parse_config(struct tunnel *tunnel, const char *buffer)
{
	const char *c, *end;

	buffer = strcasestr(buffer, "NAME=\"text6\"");
	if (!buffer)
		return 1;
	buffer = strcasestr(buffer, "VALUE=\"");
	if (!buffer)
		return 1;
	buffer += 7;

	end = strchr(buffer, '"');
	if (end == NULL || end == buffer) {
		log_info("No split VPN route\n");
		return 1;
	}

	do {
		char dest[16], mask[16];

		c = strchr(buffer, '/');
		if (c == NULL || c >= end || c - buffer > 15) {
			log_warn("Wrong addresses in split VPN route: expected <dest>/<mask>\n");
			return 1;
		}
		memcpy(dest, buffer, c - buffer);
		dest[c - buffer] = '\0';
		buffer = c + 1;

		c = strchr(buffer, ',');
		if (c == NULL || c > end)
			c = end;

		if (c - buffer > 15) {
			log_warn("Wrong addresses in split VPN route: expected <dest>/<mask>\n");
			return 1;
		}
		memcpy(mask, buffer, c - buffer);
		mask[c - buffer] = '\0';
		buffer = c + 1;

		ipv4_add_split_vpn_route(tunnel, dest, mask, NULL);

	} while (c < end && *c == ',');

	return 1;
}

int auth_get_config(struct tunnel *tunnel)
{
	char *buffer;
	int ret;

	ret = http_request(tunnel, "GET", "/remote/fortisslvpn_xml", "", &buffer);
	if (ret == 1) {
		ret = parse_xml_config(tunnel, buffer);
		free(buffer);
	}
	if (ret == 1)
		return ret;

	ret = http_request(tunnel, "GET", "/remote/fortisslvpn", "", &buffer);
	if (ret == 1) {
		ret = parse_config(tunnel, buffer);
		free(buffer);
	}

	return ret;
}
