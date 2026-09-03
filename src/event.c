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

#include "event.h"

#include <pthread.h>

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

static int events_enabled;
static int64_t seq_counter;
static pthread_mutex_t event_mutex = PTHREAD_MUTEX_INITIALIZER;

void event_init(int enabled)
{
	events_enabled = enabled;
}

void event_emit(const char *type, const char *json_fields_fmt, ...)
{
	va_list ap;
	char fields_buf[2048];

	if (!events_enabled)
		return;

	pthread_mutex_lock(&event_mutex);

	fprintf(stderr, "{\"event\":\"%s\",\"ts\":%lld,\"seq\":%lld",
	        type, (long long)time(NULL), (long long)seq_counter++);

	if (json_fields_fmt && json_fields_fmt[0] != '\0') {
		va_start(ap, json_fields_fmt);
		vsnprintf(fields_buf, sizeof(fields_buf), json_fields_fmt, ap);
		va_end(ap);
		fprintf(stderr, ",%s", fields_buf);
	}

	fprintf(stderr, "}\n");
	fflush(stderr);

	pthread_mutex_unlock(&event_mutex);
}

char *json_escape(char *buf, size_t buf_size, const char *input)
{
	size_t i = 0;
	size_t o = 0;

	if (!buf || buf_size == 0)
		return buf;

	/* Reserve space for NUL terminator */
	buf_size--;

	if (!input) {
		buf[0] = '\0';
		return buf;
	}

	while (input[i] != '\0' && o < buf_size) {
		unsigned char c = (unsigned char)input[i];

		if (c == '"') {
			if (o + 2 > buf_size)
				break;
			buf[o++] = '\\';
			buf[o++] = '"';
		} else if (c == '\\') {
			if (o + 2 > buf_size)
				break;
			buf[o++] = '\\';
			buf[o++] = '\\';
		} else if (c == '\n') {
			if (o + 2 > buf_size)
				break;
			buf[o++] = '\\';
			buf[o++] = 'n';
		} else if (c == '\r') {
			if (o + 2 > buf_size)
				break;
			buf[o++] = '\\';
			buf[o++] = 'r';
		} else if (c == '\t') {
			if (o + 2 > buf_size)
				break;
			buf[o++] = '\\';
			buf[o++] = 't';
		} else if (c < 0x20) {
			if (o + 6 > buf_size)
				break;
			snprintf(buf + o, 7, "\\u%04x", c);
			o += 6;
		} else {
			buf[o++] = c;
		}
		i++;
	}

	buf[o] = '\0';
	return buf;
}

void event_emit_cert_error(const char *digest, const char *reason)
{
	char buf[512];
	char esc_d[256], esc_r[128];

	json_escape(esc_d, sizeof(esc_d), digest);
	json_escape(esc_r, sizeof(esc_r), reason);
	snprintf(buf, sizeof(buf),
	         "\"digest\":\"%s\",\"reason\":\"%s\"",
	         esc_d, esc_r);
	event_emit("cert_error", buf);
}

void event_emit_error(int code, const char *category,
                      const char *msg)
{
	char buf[512];
	char esc_c[64], esc_m[256];

	json_escape(esc_c, sizeof(esc_c), category);
	json_escape(esc_m, sizeof(esc_m), msg);
	snprintf(buf, sizeof(buf),
	         "\"code\":%d,\"category\":\"%s\",\"message\":\"%s\"",
	         code, esc_c, esc_m);
	event_emit("error", buf);
}

void event_emit_tunnel_up(const char *ip, const char *d1,
                          const char *d2)
{
	char buf[256];

	snprintf(buf, sizeof(buf),
	         "\"local_ip\":\"%s\",\"dns1\":\"%s\",\"dns2\":\"%s\"",
	         ip, d1, d2);
	event_emit("tunnel_up", buf);
}
