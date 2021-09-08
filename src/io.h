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

#ifndef OPENFORTIVPN_IO_H
#define OPENFORTIVPN_IO_H

#include <sys/types.h>
#include <pthread.h>

#include <stddef.h>
#include <stdint.h>

/*
 * For performance reasons, we store the 6-byte header used by the SSL
 * communication right in front of the real PPP packet data. This way,
 * SSL_write can be called directly on packet->content, instead of memcpy'ing
 * the header + data to a temporary buffer.
 */
struct ppp_packet {
	struct ppp_packet *next;
	size_t len; // length of data; actual length is 6 + len
	uint8_t content[];
};
#define pkt_header(packet)	((packet)->content)
#define pkt_data(packet)	((packet)->content + 6)

struct ppp_packet_pool {
	pthread_mutex_t mutex;
	pthread_cond_t new_data;
	struct ppp_packet *list_head;
};

#define init_ppp_packet_pool(pool) \
	do { \
		pthread_mutex_init(&(pool)->mutex, NULL); \
		pthread_cond_init(&(pool)->new_data, NULL); \
		(pool)->list_head = NULL; \
	} while (0)

#define destroy_ppp_packet_pool(pool) \
	pthread_mutex_destroy(&(pool)->mutex)

struct tunnel;

int io_loop(struct tunnel *tunnel);

int get_sig_received(void);

#endif
