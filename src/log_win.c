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
 *
 *  Windows logging implementation.
 *  Replaces log.c for Windows builds.
 */

#ifdef _WIN32

#include "log.h"
#include "compat_win32.h"

#include <windows.h>
#include <pthread.h>

#include <stdio.h>
#include <stdarg.h>
#include <string.h>

enum log_verbosity loglevel = OFV_LOG_INFO;

static int do_syslog_flag;
static int use_colors;
static pthread_mutex_t log_mutex;
static HANDLE event_log;

void init_logging(void)
{
	HANDLE hConsole;
	DWORD mode;

	pthread_mutex_init(&log_mutex, NULL);

	/* Enable ANSI escape codes on Windows 10+ */
	hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	if (hConsole != INVALID_HANDLE_VALUE) {
		if (GetConsoleMode(hConsole, &mode)) {
			if (SetConsoleMode(hConsole,
			                   mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING)) {
				use_colors = isatty(fileno(stdout));
			}
		}
	}

	if (!use_colors)
		use_colors = isatty(fileno(stdout));
}

void set_syslog(int do_syslog)
{
	do_syslog_flag = do_syslog;
	if (do_syslog && !event_log)
		event_log = RegisterEventSourceA(NULL, "openfortivpn");
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
	const char *prefix = "";
	const char *color_start = "";
	const char *color_end = "";

	pthread_mutex_lock(&log_mutex);

	switch (verbosity) {
	case OFV_LOG_ERROR:
		prefix = "ERROR:  ";
		if (use_colors) {
			color_start = "\033[0;31m"; /* red */
			color_end = "\033[0;0m";
		}
		break;
	case OFV_LOG_WARN:
		prefix = "WARN:   ";
		if (use_colors) {
			color_start = "\033[0;33m"; /* yellow */
			color_end = "\033[0;0m";
		}
		break;
	case OFV_LOG_INFO:
		prefix = "INFO:   ";
		break;
	case OFV_LOG_DEBUG:
	case OFV_LOG_DEBUG_DETAILS:
	case OFV_LOG_DEBUG_ALL:
		prefix = "DEBUG:  ";
		break;
	}

	fprintf(stdout, "%s%s", color_start, prefix);
	va_start(args, format);
	vfprintf(stdout, format, args);
	va_end(args);
	fprintf(stdout, "%s", color_end);
	fflush(stdout);

	/* Windows Event Log */
	if (do_syslog_flag && event_log) {
		char msg[2048];
		WORD event_type;

		va_start(args, format);
		vsnprintf(msg, sizeof(msg), format, args);
		va_end(args);

		switch (verbosity) {
		case OFV_LOG_ERROR:
			event_type = EVENTLOG_ERROR_TYPE;
			break;
		case OFV_LOG_WARN:
			event_type = EVENTLOG_WARNING_TYPE;
			break;
		default:
			event_type = EVENTLOG_INFORMATION_TYPE;
			break;
		}

		const char *strings[1] = { msg };

		ReportEventA(event_log, event_type, 0, 0, NULL,
		             1, 0, strings, NULL);
	}

	pthread_mutex_unlock(&log_mutex);
}

void do_log_packet(const char *prefix, size_t len, const uint8_t *packet)
{
	pthread_mutex_lock(&log_mutex);

	fprintf(stdout, "%s(%lu bytes) ", prefix, (unsigned long)len);
	for (size_t i = 0; i < len && i < 64; i++)
		fprintf(stdout, "%02x ", packet[i]);
	if (len > 64)
		fprintf(stdout, "...");
	fprintf(stdout, "\n");
	fflush(stdout);

	pthread_mutex_unlock(&log_mutex);
}

#endif /* _WIN32 */
