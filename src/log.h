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

#ifndef _LOG_H
#define _LOG_H

#include <stdint.h>

enum log_verbosity {
	LOG_MUTE,
	LOG_ERROR,
	LOG_WARN,
	LOG_INFO,
	LOG_DEBUG,
	LOG_DEBUG_PACKETS
};

extern enum log_verbosity loglevel;

void init_logging();

void increase_verbosity();
void decrease_verbosity();

void do_log(int verbosity, const char *format, ...);

#define log_level(verbosity, ...) \
	do { \
		if (loglevel >= verbosity) \
			do_log(verbosity, __VA_ARGS__); \
	} while (0)

#define log_error(...) \
	log_level(LOG_ERROR, __VA_ARGS__)
#define log_warn(...) \
	log_level(LOG_WARN, __VA_ARGS__)
#define log_info(...) \
	log_level(LOG_INFO, __VA_ARGS__)
#define log_debug(...) \
	log_level(LOG_DEBUG, __VA_ARGS__)

#define log_packet(...) \
	do { \
		if (loglevel >= LOG_DEBUG_PACKETS) \
			do_log_packet(__VA_ARGS__); \
	} while (0)

void do_log_packet(const char *prefix, size_t len, const uint8_t *packet);

#endif
