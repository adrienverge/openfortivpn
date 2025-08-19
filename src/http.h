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

#ifndef OPENFORTIVPN_HTTP_H
#define OPENFORTIVPN_HTTP_H

#include "tunnel.h"

#include <stdint.h>

#define ERR_HTTP_INVALID	-1
#define ERR_HTTP_TOO_LONG	-2
#define ERR_HTTP_NO_MEM		-3
#define ERR_HTTP_SSL		-4  // deprecated
#define ERR_HTTP_TLS		-4
#define ERR_HTTP_BAD_RES_CODE	-5
#define ERR_HTTP_PERMISSION	-6
#define ERR_HTTP_NO_COOKIE	-7

/*
 * URL-encodes a string for HTTP requests.
 *
 * The dest buffer size MUST be at least strlen(str) * 3 + 1.
 *
 * @param[out] dest  the buffer to write the URL-encoded string
 * @param[in]  str   the input string to be escaped
 */
void url_encode(char *dest, const char *str);

static inline const char *err_http_str(int code)
{
	if (code > 0)
		switch(code) 
		{
			case 400:
				return "HTTP status code: 400 - Bad Request";
			case 401:
				return "HTTP status code: 401 - Unauthorized";
			case 403:
				return "HTTP status code: 403 - Forbidden";
			case 500:
				return "HTTP status code: 500 - Internal Server Error";
			default: return "HTTP status code";
		}
	}
	else if (code == ERR_HTTP_INVALID)
		return "Invalid input";
	else if (code == ERR_HTTP_TOO_LONG)
		return "Request too long";
	else if (code == ERR_HTTP_NO_MEM)
		return "Not enough memory";
	else if (code == ERR_HTTP_TLS)
		return "TLS error";
	else if (code == ERR_HTTP_BAD_RES_CODE)
		return "Bad HTTP response code";
	else if (code == ERR_HTTP_PERMISSION)
		return "Permission denied";
	else if (code == ERR_HTTP_NO_COOKIE)
		return "No cookie given";
	return "unknown";
}

int http_send(struct tunnel *tunnel, const char *request, ...);
int http_receive(struct tunnel *tunnel, char **response, uint32_t *response_size);

int auth_log_in(struct tunnel *tunnel);
int auth_log_out(struct tunnel *tunnel);
int auth_request_vpn_allocation(struct tunnel *tunnel);
int auth_get_config(struct tunnel *tunnel);
int auth_set_cookie(struct tunnel *tunnel, const char *line);

#endif
