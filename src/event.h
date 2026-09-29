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

#ifndef OPENFORTIVPN_EVENT_H
#define OPENFORTIVPN_EVENT_H

#include <stddef.h>

/* Initialize the event system. enabled=1 turns on JSON output to stderr. */
void event_init(int enabled);

/* Emit a JSON event line to stderr. fmt contains key:value pairs in JSON. */
void event_emit(const char *type, const char *json_fields_fmt, ...);

/*
 * Helper: escape a string for JSON (handles quotes, backslashes, control chars).
 * Writes to buf, returns buf. Truncates if output exceeds buf_size.
 */
char *json_escape(char *buf, size_t buf_size, const char *input);

/* Typed event emitters that avoid split-string lint warnings. */
void event_emit_cert_error(const char *digest, const char *reason);
void event_emit_error(int code, const char *category, const char *msg);
void event_emit_tunnel_up(const char *ip, const char *d1, const char *d2);

#endif /* OPENFORTIVPN_EVENT_H */
