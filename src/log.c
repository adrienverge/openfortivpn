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

#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "log.h"

static pthread_mutex_t mutex;

enum log_verbosity loglevel;

static int is_a_tty = 0;

void init_logging()
{
	pthread_mutexattr_t mutexattr;
	loglevel = LOG_INFO;
	is_a_tty = isatty(STDOUT_FILENO);

	pthread_mutexattr_init(&mutexattr);
	pthread_mutexattr_setrobust(&mutexattr, PTHREAD_MUTEX_ROBUST);
	pthread_mutex_init(&mutex, &mutexattr);
}

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
		printf("%sERROR:  ", is_a_tty ? "\033[0;31m" : "");
		break;
	case LOG_WARN:
		printf("%sWARN:   ", is_a_tty ? "\033[0;33m" : "");
		break;
	case LOG_INFO:
		printf("%sINFO:   ", is_a_tty ? "\033[0;97m" : "");
		break;
	case LOG_DEBUG:
		printf("%sDEBUG:  ", is_a_tty ? "\033[0;90m" : "");
		break;
	default:
		printf("        ");
	}

	va_start(args, format);
	vprintf(format, args);
	va_end(args);

	if (is_a_tty)
		printf("\033[0;0m");

	fflush(stdout);

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

	puts(str);

	free(str);
}
