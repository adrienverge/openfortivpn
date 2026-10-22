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

#ifndef OPENFORTIVPN_HTTP_FORM_H
#define OPENFORTIVPN_HTTP_FORM_H

#include <stddef.h>

/*
 * Builds the fields used by the second 2FA request. username, realm and
 * token_fields are already URL-encoded by the caller; group and portal are
 * encoded here because they can contain spaces or form delimiters. Other
 * opaque values are preserved. Returns 0 on success, or -1 if the destination
 * is too small or an argument is NULL.
 */
int http_build_otp_form(char *buffer, size_t capacity,
                        const char *username, const char *realm,
                        const char *reqid, const char *polid,
                        const char *group, const char *portal,
                        const char *peer, const char *token_fields);

#endif
