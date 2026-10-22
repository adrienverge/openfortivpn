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

#include "http_form.h"

#include <string.h>

static int append_text(char *buffer, size_t capacity, size_t *length,
                       const char *text, size_t text_length)
{
	if (*length >= capacity || text_length > capacity - *length - 1)
		return -1;

	memcpy(buffer + *length, text, text_length);
	*length += text_length;
	buffer[*length] = '\0';
	return 0;
}


static int is_unreserved(unsigned char c)
{
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
	       (c >= '0' && c <= '9') || c == '-' || c == '_' ||
	       c == '.' || c == '~';
}


static int append_form_field(char *buffer, size_t capacity, size_t *length,
                             const char *name, const char *value,
                             int encode_value)
{
	static const char hex[] = "0123456789ABCDEF";

	if (*length && append_text(buffer, capacity, length, "&", 1) != 0)
		return -1;
	if (append_text(buffer, capacity, length, name, strlen(name)) != 0 ||
	    append_text(buffer, capacity, length, "=", 1) != 0)
		return -1;
	if (!encode_value)
		return append_text(buffer, capacity, length, value, strlen(value));

	for (const unsigned char *p = (const unsigned char *) value; *p; p++) {
		if (is_unreserved(*p)) {
			char c = *p;

			if (append_text(buffer, capacity, length, &c, 1) != 0)
				return -1;
		} else {
			char encoded[] = { '%', hex[*p >> 4], hex[*p & 0x0f] };

			if (append_text(buffer, capacity, length, encoded,
			                sizeof(encoded)) != 0)
				return -1;
		}
	}

	return 0;
}


int http_build_otp_form(char *buffer, size_t capacity,
                        const char *username, const char *realm,
                        const char *reqid, const char *polid,
                        const char *group, const char *portal,
                        const char *peer, const char *token_fields)
{
	size_t length = 0;

	if (!buffer || !capacity || !username || !realm || !reqid || !polid ||
	    !group || !portal || !peer || !token_fields)
		return -1;

	buffer[0] = '\0';
	if (append_form_field(buffer, capacity, &length, "username", username, 0) ||
	    append_form_field(buffer, capacity, &length, "realm", realm, 0) ||
	    append_form_field(buffer, capacity, &length, "reqid", reqid, 0) ||
	    append_form_field(buffer, capacity, &length, "polid", polid, 0) ||
	    append_form_field(buffer, capacity, &length, "grp", group, 1) ||
	    append_form_field(buffer, capacity, &length, "portal", portal, 1) ||
	    append_form_field(buffer, capacity, &length, "peer", peer, 0))
		return -1;

	if (token_fields[0] &&
	    (append_text(buffer, capacity, &length, "&", 1) != 0 ||
	     append_text(buffer, capacity, &length, token_fields,
	                 strlen(token_fields)) != 0))
		return -1;

	return 0;
}
