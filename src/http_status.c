/*
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include "http_status.h"

#include <string.h>

static int is_digit(char c)
{
	return c >= '0' && c <= '9';
}


int http_response_status_code(const char *response)
{
	int code;

	if (!response || strlen(response) < 12 ||
	    strncmp(response, "HTTP/", 5) != 0 ||
	    !is_digit(response[5]) || response[6] != '.' ||
	    !is_digit(response[7]) || response[8] != ' ' ||
	    !is_digit(response[9]) || !is_digit(response[10]) ||
	    !is_digit(response[11]))
		return -1;

	if (response[12] != ' ' && response[12] != '\r' &&
	    response[12] != '\n' && response[12] != '\0')
		return -1;

	code = (response[9] - '0') * 100 +
	       (response[10] - '0') * 10 + response[11] - '0';
	return code >= 100 && code <= 599 ? code : -1;
}
