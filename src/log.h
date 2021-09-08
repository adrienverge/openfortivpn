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

#ifndef OPENFORTIVPN_LOG_H
#define OPENFORTIVPN_LOG_H

#include <stddef.h>
#include <stdint.h>

// Assign enum values explicitly, we're using them in a lookup
enum log_verbosity {
	OFV_LOG_MUTE  = 0,
	OFV_LOG_ERROR = 1,
	OFV_LOG_WARN  = 2,
	OFV_LOG_INFO  = 3,
	OFV_LOG_DEBUG = 4,
	OFV_LOG_DEBUG_DETAILS = 5,
	OFV_LOG_DEBUG_ALL = 6
};

extern enum log_verbosity loglevel;

void init_logging(void);
void set_syslog(int do_syslog);

void increase_verbosity(void);
void decrease_verbosity(void);

void do_log(int verbosity, const char *format, ...);

#define log_level(verbosity, ...) \
	do { \
		if (loglevel >= verbosity) \
			do_log(verbosity, __VA_ARGS__); \
	} while (0)

#define log_error(...) \
	log_level(OFV_LOG_ERROR, __VA_ARGS__)
#define log_warn(...) \
	log_level(OFV_LOG_WARN, __VA_ARGS__)
#define log_info(...) \
	log_level(OFV_LOG_INFO, __VA_ARGS__)
#define log_debug(...) \
	log_level(OFV_LOG_DEBUG, __VA_ARGS__)
#define log_debug_details(...) \
	log_level(OFV_LOG_DEBUG_DETAILS, __VA_ARGS__)
#define log_debug_all(...) \
	log_level(OFV_LOG_DEBUG_ALL, __VA_ARGS__)

#define log_packet(...) \
	do { \
		if (loglevel >= OFV_LOG_DEBUG_DETAILS) \
			do_log_packet(__VA_ARGS__); \
	} while (0)

void do_log_packet(const char *prefix, size_t len, const uint8_t *packet);

#endif
