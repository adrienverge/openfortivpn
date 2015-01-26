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

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include "log.h"

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

enum log_verbosity loglevel = LOG_INFO;

void increase_verbosity()
{
	if (loglevel < LOG_DEBUG_PACKETS)
		loglevel++;
}
void decrease_verbosity()
{
	if (loglevel > LOG_MUTE)
		loglevel--;
}

void do_log(int verbosity, const char *format, ...)
{
	va_list args;

	pthread_mutex_lock(&mutex);

	switch (verbosity) {
	case LOG_ERROR:
		printf("\033[0;91mERROR:  ");
		break;
	case LOG_WARN:
		printf("\033[0;93mWARN:   ");
		break;
	case LOG_INFO:
		printf("\033[0;97mINFO:   ");
		break;
	case LOG_DEBUG:
		printf("\033[0;90mDEBUG:  ");
		break;
	default:
		printf("\033[0;0m        ");
	}

	va_start(args, format);
	vprintf(format, args);
	va_end(args);

	printf("\033[0;0m");

	pthread_mutex_unlock(&mutex);
}

void do_log_packet(const char *prefix, size_t len, const uint8_t *packet)
{
	char *str, *pos;
	size_t i;

	str = malloc(strlen(prefix) + 3 * len + 1 + 1);
	if (str == NULL) {
		log_error("malloc failed\n");
		return;
	}

	pos = strcpy(str, prefix);
	pos += strlen(str);
	for (i = 0; i < len; i++) {
		pos += sprintf(pos, "%02x ", packet[i]);
	}
	strcpy(pos - 1, "\n");

	printf(str);

	free(str);
}
