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

#include "log.h"

#include <unistd.h>
#include <pthread.h>
#include <syslog.h>

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static pthread_mutex_t mutex;
static int do_syslog; //static variables are initialized to zero in C99

enum log_verbosity loglevel;

static int is_a_tty; // static variables are initialized to zero in C99

struct log_param_s {
	const char *prefix;
	const char *color_string;
	int syslog_prio;
};

static const struct log_param_s log_params[OFV_LOG_DEBUG_ALL + 1] = {
	{ "        ", "",           LOG_ERR},
	{ "ERROR:  ", "\033[0;31m", LOG_ERR},
	{ "WARN:   ", "\033[0;33m", LOG_WARNING},
	{ "INFO:   ", "",           LOG_INFO},
	{ "DEBUG:  ", "\033[0;90m", LOG_DEBUG},
	{ "DEBUG:  ", "\033[0;90m", LOG_DEBUG},
	{ "DEBUG:  ", "\033[0;90m", LOG_DEBUG},
};

void init_logging(void)
{
	pthread_mutexattr_t mutexattr;
	int e;

	loglevel = OFV_LOG_INFO;
	is_a_tty = isatty(STDOUT_FILENO);

	e = pthread_mutexattr_init(&mutexattr);
	if (e)
		fprintf(stderr, "ERROR:  pthread_mutexattr_init: %s\n",
		        strerror(e));
#ifdef HAVE_PTHREAD_MUTEXATTR_SETROBUST
	e = pthread_mutexattr_setrobust(&mutexattr, PTHREAD_MUTEX_ROBUST);
	if (e)
		fprintf(stderr, "ERROR:  pthread_mutexattr_setrobust: %s\n",
		        strerror(e));
#endif
	e = pthread_mutex_init(&mutex, &mutexattr);
	if (e)
		fprintf(stderr, "ERROR:  pthread_mutex_init: %s\n",
		        strerror(e));
}

void set_syslog(int use_syslog)
{
	if (!use_syslog)
		return;
	do_syslog = use_syslog;
	openlog("openfortivpn", LOG_PID, LOG_DAEMON);
}

void increase_verbosity(void)
{
	if (loglevel < OFV_LOG_DEBUG_ALL)
		loglevel++;
}

void decrease_verbosity(void)
{
	if (loglevel > OFV_LOG_MUTE)
		loglevel--;
}

void do_log(int verbosity, const char *format, ...)
{
	va_list args;
	const struct log_param_s *lp = NULL;
	int e;

	e = pthread_mutex_lock(&mutex);
	if (e)
		fprintf(stderr, "ERROR:  pthread_mutex_lock: %s\n",
		        strerror(e));

	// Use sane default if wrong verbosity specified
	if (verbosity > OFV_LOG_DEBUG_ALL || verbosity < 0)
		verbosity = OFV_LOG_MUTE;
	lp = &log_params[verbosity];

	if (!do_syslog)
		printf("%s%s", is_a_tty ? lp->color_string : "", lp->prefix);

	va_start(args, format);
	if (do_syslog)
		vsyslog(lp->syslog_prio, format, args);
	else
		vprintf(format, args);
	va_end(args);

	if (!do_syslog) {
		if (is_a_tty)
			printf("\033[0;0m");

		fflush(stdout);
	}

	e = pthread_mutex_unlock(&mutex);
	if (e)
		fprintf(stderr, "ERROR:  pthread_mutex_unlock: %s\n",
		        strerror(e));
}

void do_log_packet(const char *prefix, size_t len, const uint8_t *packet)
{
	char *str, *pos;
	size_t i;

	str = malloc(strlen(prefix) + 3 * len + 1 + 1);
	if (str == NULL) {
		log_error("malloc: %s\n", strerror(errno));
		return;
	}

	pos = strcpy(str, prefix);
	pos += strlen(str);
	for (i = 0; i < len; i++)
		pos += sprintf(pos, "%02x ", packet[i]);
	strcpy(pos - 1, "\n");

	if (do_syslog)
		syslog(LOG_DEBUG, "%s", str);
	else
		puts(str);

	free(str);
}
