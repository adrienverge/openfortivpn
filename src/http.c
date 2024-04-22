/*
 *  Copyright (c) 2015 Adrien Vergé
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

#include <unistd.h>
#include <arpa/inet.h>

#include <assert.h>
#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * Fixed size of the buffer for outgoing HTTP requests.
 * Initial size of the buffer for incoming HTTP responses.
 */
#define HTTP_BUFFER_SIZE 0x10000


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
		if (isalnum(*str) || *str == '-' || *str == '_' ||
		    *str == '.' || *str == '~') {
			*dest++ = *str;
		} else {
			static const char hex[] = "0123456789ABCDEF";

			*dest++ = '%';
			*dest++ = hex[(unsigned char)*str >> 4];
			*dest++ = hex[(unsigned char)*str & 15];
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
	char buffer[HTTP_BUFFER_SIZE];
	char logbuffer[HTTP_BUFFER_SIZE];
	int length;
	int n = 0;

	va_start(args, request);
	length = vsnprintf(buffer, HTTP_BUFFER_SIZE, request, args);
	va_end(args);
	strcpy(logbuffer, buffer);
	if (loglevel <= OFV_LOG_DEBUG_DETAILS && tunnel->config->password[0] != '\0') {
		char *pwstart;
		char password[3 * PASSWORD_SIZE + 1];

		url_encode(password, tunnel->config->password);

		while ((pwstart = strstr(logbuffer, password))) {
			int pos, pwlen;

			pos = pwstart - logbuffer;
			pwlen = strlen(password);
			for (int i = pos; i < pos + pwlen; i++)
				logbuffer[i] = '*';
		}
	}

	if (length < 0)
		return ERR_HTTP_INVALID;
	else if (length >= HTTP_BUFFER_SIZE)
		return ERR_HTTP_TOO_LONG;

	log_debug_details("%s:\n%s\n", __func__, logbuffer);

	while (n == 0)
		n = safe_ssl_write(tunnel->ssl_handle, (uint8_t *) buffer,
		                   length);
	if (n < 0) {
		log_debug("Error writing to TLS connection (%s).\n",
		          err_ssl_str(n));
		return ERR_HTTP_TLS;
	}

	return 1;
}


static const char *find_header(const char *res, const char *header,
                               uint32_t response_size)
{
	const char *line = res;

	while (memcmp(line, "\r\n", 2)) {
		int line_len = (char *) memmem(
		                       line, response_size - (line - res), "\r\n", 2
		               ) - line;
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
int http_receive(struct tunnel *tunnel,
                 char **response, uint32_t *response_size)
{
	uint32_t capacity = HTTP_BUFFER_SIZE;
	char *buffer;
	uint32_t bytes_read = 0;
	uint32_t header_size = 0;
	uint32_t content_size = 0;
	int chunked = 0;

	buffer = malloc(capacity + 1); // room for terminal '\0'
	if (buffer == NULL)
		return ERR_HTTP_NO_MEM;

	while (1) {
		int n;

		while ((n = safe_ssl_read(tunnel->ssl_handle,
		                          (uint8_t *) buffer + bytes_read,
		                          capacity - bytes_read)) == ERR_TLS_AGAIN)
			;
		if (n < 0) {
			log_debug("Error reading from TLS connection (%s).\n",
			          err_ssl_str(n));
			free(buffer);
			return ERR_HTTP_TLS;
		}
		bytes_read += n;

		log_debug_details("%s:\n%s\n", __func__, buffer);

		if (!header_size) {
			/* Have we reached the end of the HTTP header? */
			static const char EOH[4] = "\r\n\r\n";
			const char *eoh = memmem(buffer, bytes_read,
			                         EOH, sizeof(EOH));

			if (eoh) {
				header_size = eoh - buffer + sizeof(EOH);

				/* Get the body size. */
				const char *header = find_header(buffer,
				                                 "Content-Length: ",
				                                 header_size);

				if (header)
					content_size = strtol(header, NULL, 10);

				if (find_header(buffer,
				                "Transfer-Encoding: chunked",
				                header_size))
					chunked = 1;
			}
		}

		if (header_size) {
			/* Have we reached the end of the HTTP body? */
			if (chunked) {
				static const char EOB[7] = "\r\n0\r\n\r\n";

				/* Last chunk terminator. Done naively. */
				if (bytes_read >= sizeof(EOB) &&
				    !memcmp(&buffer[bytes_read - sizeof(EOB)],
				            EOB, sizeof(EOB)))
					break;
			} else {
				if (bytes_read >= header_size + content_size)
					break;
			}
		}

		/* expand the buffer if necessary */
		if (bytes_read == capacity) {
			char *new_buffer;

			if ((UINT32_MAX - 1) / capacity < 2) {
				free(buffer);
				return ERR_HTTP_TOO_LONG;
			}
			capacity *= 2;

			new_buffer = realloc(buffer, capacity + 1);
			if (new_buffer == NULL) {
				free(buffer);
				return ERR_HTTP_NO_MEM;
			}
			buffer = new_buffer;
		}
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
	} else {
		assert(bytes_read < capacity);
		buffer[bytes_read] = '\0';
		*response = buffer;

		if (response_size != NULL)
			*response_size = bytes_read + 1;
	}
	return 1;
}


static int do_http_request(struct tunnel *tunnel,
                           const char *method,
                           const char *uri,
                           const char *data,
                           char **response,
                           uint32_t *response_size
                          )
{
	int ret;
	const char *template = ("%s %s HTTP/1.1\r\n"
	                        "Host: %s:%d\r\n"
	                        "User-Agent: %s\r\n"
	                        "Accept: */*\r\n"
	                        "Accept-Encoding: identity\r\n"
	                        "Pragma: no-cache\r\n"
	                        "Cache-Control: no-store, no-cache, must-revalidate\r\n"
	                        "If-Modified-Since: Sat, 1 Jan 2000 00:00:00 GMT\r\n"
	                        "Content-Type: application/x-www-form-urlencoded\r\n"
	                        "Cookie: %s\r\n"
	                        "Content-Length: %d\r\n"
	                        "\r\n%s");

	ret = http_send(tunnel, template, method, uri,
	                tunnel->config->gateway_host, tunnel->config->gateway_port,
	                tunnel->config->user_agent, tunnel->cookie,
	                strlen(data), data);
	if (ret != 1)
		return ret;

	return http_receive(tunnel, response, response_size);
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
                        const char *uri,
                        const char *data,
                        char **response,
                        uint32_t *response_size
                       )
{
	int ret;

	ret = do_http_request(tunnel, method, uri, data,
	                      response, response_size);
	if (ret == ERR_HTTP_TLS) {
		ssl_connect(tunnel);
		ret = do_http_request(tunnel, method, uri, data,
		                      response, response_size);
	}
	if (ret != 1)
		log_debug("Error issuing %s request\n", uri);

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
	char *saveptr = NULL;

	tokens = strdup(buf);
	if (tokens == NULL) {
		ret = -3;
		goto end;
	}

	for (const char *kv_pair = strtok_r(tokens, "&,\r\n", &saveptr);
	     kv_pair != NULL;
	     kv_pair = strtok_r(NULL, "&,\r\n", &saveptr)) {
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

static int get_action_url(const char *buf, const char *key,
                          char *retbuf, size_t retbuflen)
{
	int ret = -1;
	char *tokens;
	size_t keylen = strlen(key);
	char *saveptr = NULL;

	tokens = strdup(buf);
	if (tokens == NULL) {
		ret = -3;
		goto end;
	}

	for (const char *kv_pair = strtok_r(tokens, " \"\r\n", &saveptr);
	     kv_pair != NULL;
	     kv_pair = strtok_r(NULL, " \"\r\n", &saveptr)) {
		if (strncmp(key, kv_pair, keylen) == 0) {
			const char *val = strtok_r(NULL, "\"\r\n", &saveptr);

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

static int auth_get_cookie(struct tunnel *tunnel, char *buf, uint32_t buffer_size)
{
	const char *line;

	line = find_header(buf, "Set-Cookie: ", buffer_size);
	return auth_set_cookie(tunnel, line);
}

int auth_set_cookie(struct tunnel *tunnel, const char *line)
{
	int ret = ERR_HTTP_NO_COOKIE;

	if (line) {
		const char *cookie_start;

		cookie_start = strstr(line, "SVPNCOOKIE=");
		if (cookie_start != NULL) {
			const char *cookie_end;
			size_t cookie_len;

			cookie_end = strpbrk(cookie_start, "\r\n;");
			if (cookie_end)
				cookie_len = cookie_end - cookie_start;
			else
				cookie_len = strlen(cookie_start);

			if (cookie_len > COOKIE_SIZE) {
				log_error("Cookie larger than expected: %zu > %d\n",
				          cookie_len, COOKIE_SIZE);
			} else {
				strncpy(tunnel->cookie, cookie_start, COOKIE_SIZE);
				tunnel->cookie[cookie_len] = '\0';

				if (tunnel->cookie[11] == '\0') {
					log_debug("Empty cookie.\n");
				} else {
					log_debug("Cookie: %s\n", tunnel->cookie);
					ret = 1; // success
				}
			}
		} else {
			log_debug("No cookie found\n");
		}
	}
	return ret;
}


static void delay_otp(struct tunnel *tunnel)
{
	if (tunnel->config->otp_delay > 0) {
		log_info("Delaying OTP by %d seconds...\n", tunnel->config->otp_delay);
		sleep(tunnel->config->otp_delay);
	}
}


static int try_otp_auth(struct tunnel *tunnel, const char *buffer,
                        char **res, uint32_t *response_size)
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
	/*
	 * Try to get password prompt, assume it starts with 'Please'
	 * Fall back to default prompt if not found/parseable
	 */
	p = strstr(s, "Please");
	if (tunnel->config->otp_prompt != NULL)
		p = strstr(s, tunnel->config->otp_prompt);
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
		p = "Please enter one-time password: ";
	/* Search for all inputs */
	while ((s = strcasestr(s, "<INPUT"))) {
		s += 6;
		/*
		 * check if we found parameters for a later INPUT
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
			/*
			 * We try to be on the safe side
			 * and URL-encode the variable name
			 *
			 * Append '&' if we found something in last round
			 */
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
				// Interactively ask user for OTP
				char hint[USERNAME_SIZE + 1 + REALM_SIZE + 1 + GATEWAY_HOST_SIZE + 5];

				sprintf(hint, "%s_%s_%s_otp",
				        cfg->username, cfg->realm, cfg->gateway_host);
				read_password(cfg->pinentry, hint,
				              p, cfg->otp, OTP_SIZE);
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
			/*  realm workaround */
			if (cfg->realm[0] != '\0') {
				l = strlen(cfg->realm);
				if (!SPACE_AVAILABLE(3 * l + 8))
					return -1;
				strcat(d, "&realm=");
				d += strlen(d);
				url_encode(d, cfg->realm);
				d += strlen(d);
			}
		} else if (strncmp(t, "submit", 6) == 0) {
			/* avoid adding another '&' */
			n = v = e = NULL;
		}
	}
	if (!SPACE_AVAILABLE(1))
		return -1;
	*d++ = '\0';
	return http_request(tunnel, "POST", path, data, res, response_size);
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
	char username[3 * USERNAME_SIZE + 1];
	char password[3 * PASSWORD_SIZE + 1];
	char realm[3 * REALM_SIZE + 1];
	char reqid[32] = { '\0' };
	char polid[32] = { '\0' };
	char group[128] = { '\0' };
	char portal[64] = { '\0' };
	char magic[32] = {'\0' };
	char peer[32]  = { '\0' };
	char data[9 + 3 * USERNAME_SIZE + 12 + 3 * PASSWORD_SIZE + 7 + 3 * REALM_SIZE + 7 + 1];
	char token[128], tokenresponse[256], tokenparams[320];
	char action_url[1024] = { '\0' };
	char *res = NULL;
	uint32_t response_size;

	url_encode(username, tunnel->config->username);
	url_encode(realm, tunnel->config->realm);

	tunnel->cookie[0] = '\0';

	if (username[0] == '\0' && tunnel->config->password[0] == '\0') {
		snprintf(data, sizeof(data), "cert=&nup=1");
		ret = http_request(tunnel, "GET", "/remote/login",
		                   data, &res, &response_size);
	} else {
		if (tunnel->config->password[0] == '\0') {
			snprintf(data, sizeof(data),
			         "username=%s&realm=%s&ajax=1&redir=%%2Fremote%%2Findex&just_logged_in=1",
			         username, realm);
		} else {
			url_encode(password, tunnel->config->password);
			snprintf(data, sizeof(data),
			         "username=%s&credential=%s&realm=%s&ajax=1",
			         username, password, realm);
		}
		ret = http_request(tunnel, "POST", "/remote/logincheck",
		                   data, &res, &response_size);
	}

	if (ret != 1)
		goto end;

	/* Probably one-time password required */
	if (strncmp(res, "HTTP/1.1 401 Authorization Required\r\n", 37) == 0) {
		delay_otp(tunnel);

		ret = try_otp_auth(tunnel, res, &res, &response_size);
		if (ret != 1)
			goto end;
	}

	if (strncmp(res, "HTTP/1.1 200 OK\r\n", 17)) {
		char word[17];

		if (sscanf(res, "%16s %d", word, &ret) < 2)
			ret = ERR_HTTP_BAD_RES_CODE;
		goto end;
	}
	ret = auth_get_cookie(tunnel, res, response_size);
	if (ret == ERR_HTTP_NO_COOKIE) {
		struct vpn_config *cfg = tunnel->config;

		/*
		 * If the response body includes a tokeninfo= parameter,
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
		get_value_from_response(res, "portal=", portal, 64);
		get_value_from_response(res, "magic=", magic, 32);
		get_value_from_response(res, "peer=", peer, 32);

		if (cfg->otp[0] == '\0' &&
		    strncmp(token, "ftm_push", 8) == 0 &&
		    cfg->no_ftm_push == 0) {
			/*
			 * The server supports FTM push if `tokeninfo` is `ftm_push`,
			 * but only try this if the OTP is not provided by the config
			 * file or command line.
			 */
			snprintf(tokenparams, sizeof(tokenparams), "ftmpush=1");
		} else {
			if (cfg->otp[0] == '\0') {
				// Interactively ask user for 2FA token
				char hint[USERNAME_SIZE + 1 + REALM_SIZE + 1 + GATEWAY_HOST_SIZE + 5];

				sprintf(hint, "%s_%s_%s_2fa",
				        cfg->username, cfg->realm, cfg->gateway_host);
				read_password(cfg->pinentry, hint,
				              "Two-factor authentication token: ",
				              cfg->otp, OTP_SIZE);

				if (cfg->otp[0] == '\0') {
					log_error("No token specified\n");
					return 0;
				}
			}

			url_encode(tokenresponse, cfg->otp);
			snprintf(tokenparams, sizeof(tokenparams),
			         "code=%s&code2=&magic=%s",
			         tokenresponse, magic);
		}

		snprintf(data, sizeof(data),
		         "username=%s&realm=%s&reqid=%s&polid=%s&grp=%s&portal=%s&peer=%s&%s",
		         username, realm, reqid, polid, group, portal, peer,
		         tokenparams);

		delay_otp(tunnel);
		ret = http_request(tunnel, "POST", "/remote/logincheck",
		                   data, &res, &response_size);
		if (ret != 1)
			goto end;

		if (strncmp(res, "HTTP/1.1 200 OK\r\n", 17)) {
			char word[17];

			if (sscanf(res, "%16s %d", word, &ret) < 2)
				ret = ERR_HTTP_BAD_RES_CODE;
			goto end;
		}

		ret = auth_get_cookie(tunnel, res, response_size);
	}

	/*
	 * If hostchecking enabled, get action url
	 */
	get_action_url(res, "action=", action_url, 1024);
	if (strlen(action_url) != 0) {
		snprintf(data, sizeof(data), "hostcheck=%s&check_virtual_desktop=%s",
		         tunnel->config->hostcheck,
		         tunnel->config->check_virtual_desktop);
		ret = http_request(tunnel, "POST", action_url,
		                   data, &res, &response_size);
	}

end:
	free(res);
	return ret;
}


int auth_log_out(struct tunnel *tunnel)
{
	return http_request(tunnel, "GET", "/remote/logout", "", NULL, NULL);
}


int auth_request_vpn_allocation(struct tunnel *tunnel)
{
	int ret = http_request(tunnel, "GET", "/remote/index", "", NULL, NULL);

	if (ret != 1)
		return ret;

	return http_request(tunnel, "GET", "/remote/fortisslvpn", "", NULL, NULL);
}


static int parse_xml_config(struct tunnel *tunnel, const char *buffer)
{
	const char *val;
	char *gateway;
	char *dns_server;
	int ret = 0;

	if (strncmp(buffer, "HTTP/1.1 200 OK\r\n", 17)) {
		char word[17];

		if (sscanf(buffer, "%16s %d", word, &ret) < 2)
			ret = ERR_HTTP_BAD_RES_CODE;
		return ret;
	}

	// Skip the HTTP header
	buffer = strstr(buffer, "\r\n\r\n");

	// The address of a local end of a router
	val = xml_find('<', "assigned-addr", buffer, 1);
	gateway = xml_get(xml_find(' ', "ipv4=", val, 1));
	if (!gateway)
		log_warn("No gateway address, using interface for routing\n");

	// The dns search string
	val = buffer;
	while ((val = xml_find('<', "dns", val, 2))) {
		if (xml_find(' ', "domain=", val, 1)) {
			tunnel->ipv4.dns_suffix
			        = xml_get(xml_find(' ', "domain=", val, 1));
			log_debug("Found dns suffix %s in xml config\n",
			          tunnel->ipv4.dns_suffix);
			break;
		}
	}

	// The dns servers
	val = buffer;
	while ((val = xml_find('<', "dns", val, 2))) {
		if (xml_find(' ', "ip=", val, 1)) {
			dns_server = xml_get(xml_find(' ', "ip=", val, 1));
			log_debug("Found dns server %s in xml config\n", dns_server);
			if (!tunnel->ipv4.ns1_addr.s_addr)
				tunnel->ipv4.ns1_addr.s_addr = inet_addr(dns_server);
			else if (!tunnel->ipv4.ns2_addr.s_addr)
				tunnel->ipv4.ns2_addr.s_addr = inet_addr(dns_server);
			free(dns_server);
		}
	}

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


int auth_get_config(struct tunnel *tunnel)
{
	char *buffer;
	int ret;

	ret = http_request(tunnel, "GET", "/remote/fortisslvpn_xml", "", &buffer, NULL);
	if (ret == 1) {
		ret = parse_xml_config(tunnel, buffer);
		free(buffer);
	}

	return ret;
}
