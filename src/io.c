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
 *
 *  In addition, as a special exception, the copyright holders give permission
 *  to link the code of portions of this program with the OpenSSL library under
 *  certain conditions as described in each individual source file, and
 *  distribute linked combinations including the two.
 *  You must obey the GNU General Public License in all respects for all of the
 *  code used other than OpenSSL.  If you modify file(s) with this exception,
 *  you may extend this exception to your version of the file(s), but you are
 *  not obligated to do so.  If you do not wish to do so, delete this exception
 *  statement from your version.  If you delete this exception statement from
 *  all source files in the program, then also delete it here.
 */

#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <signal.h>
#ifdef __APPLE__
/* Mac OS X defines sem_init but actually does not implement them */
#include <dispatch/dispatch.h>

typedef dispatch_semaphore_t	sem_t;

#define sem_init(psem,x,val)	*psem = dispatch_semaphore_create(val)
#define sem_post(psem)		dispatch_semaphore_signal(*psem)
#define sem_wait(psem)		dispatch_semaphore_wait(*psem, \
					DISPATCH_TIME_FOREVER)

#define sem_destroy(psem)	dispatch_release(*psem)
#endif

#include "hdlc.h"
#include "log.h"
#include "ssl.h"
#include "tunnel.h"

#define PKT_BUF_SZ 0x1000

static pthread_mutex_t *lockarray;
static void lock_callback(int mode, int type, char *file, int line)
{
	if (mode & CRYPTO_LOCK)
		pthread_mutex_lock(&(lockarray[type]));
	else
		pthread_mutex_unlock(&(lockarray[type]));
}
static unsigned long thread_id()
{
	return (unsigned long) pthread_self();
}
static void init_ssl_locks()
{
	int i;
	lockarray = (pthread_mutex_t *) OPENSSL_malloc(CRYPTO_num_locks() *
	                sizeof(pthread_mutex_t));
	for (i = 0; i < CRYPTO_num_locks(); i++)
		pthread_mutex_init(&(lockarray[i]), NULL);
	CRYPTO_set_id_callback((unsigned long (*)()) thread_id);
	CRYPTO_set_locking_callback((void (*)()) lock_callback);
}
static void destroy_ssl_locks()
{
	int i;
	CRYPTO_set_locking_callback(NULL);
	for (i = 0; i < CRYPTO_num_locks(); i++)
		pthread_mutex_destroy(&(lockarray[i]));
	OPENSSL_free(lockarray);
}

/*
 * Adds a new packet to a pool.
 *
 * Warning: for performance reasons, this function does not check if the packet
 * is already present in the list. If it is, there will be a loop in the list
 * and this will result in an unpredictable behavior.
 */
static void pool_push(struct ppp_packet_pool *pool, struct ppp_packet *new)
{
	struct ppp_packet *current;

	pthread_mutex_lock(&pool->mutex);

	new->next = NULL;
	current = pool->list_head;
	if (current == NULL) {
		pool->list_head = new;
	} else {
		while (current->next != NULL)
			current = current->next;
		current->next = new;
	}

	pthread_cond_signal(&pool->new_data);
	pthread_mutex_unlock(&pool->mutex);
}

/*
 * Gets the first packet from a pool.
 */
static struct ppp_packet *pool_pop(struct ppp_packet_pool *pool)
{
	struct ppp_packet *first = pool->list_head;

	//sem_wait(&pool->sem);
	pthread_mutex_lock(&pool->mutex);
	while (pool->list_head == NULL)
		pthread_cond_wait(&pool->new_data, &pool->mutex);

	first = pool->list_head;
	pool->list_head = first->next;
	first->next = NULL;

	pthread_mutex_unlock(&pool->mutex);

	return first;
}

static sem_t sem_pppd_ready;
static sem_t sem_if_config;
static sem_t sem_stop_io;

/*
 * Thread to read bytes from the pppd pty, convert them to ppp packets and add
 * them to the 'pty_to_ssl' pool.
 */
static void *pppd_read(void *arg)
{
	struct tunnel *tunnel = (struct tunnel *) arg;
	uint8_t buf[PKT_BUF_SZ];
	int first_time = 1;
	off_t off_r, off_w;
	fd_set read_fd;

	FD_ZERO(&read_fd);
	FD_SET(tunnel->pppd_pty, &read_fd);

	log_debug("pppd_read_thread\n");

	// Wait for pppd to be ready
	off_w = 0;
	while (1) {
		ssize_t n;
		int sel;

		sel = select(tunnel->pppd_pty + 1, &read_fd, NULL, NULL, NULL);
		if (sel == -1) {
			log_error("select: %s\n", strerror(errno));
			break;
		} else if (sel == 0) {
			log_warn("select returned 0\n");
			continue;
		}
		n = read(tunnel->pppd_pty, &buf[off_w], PKT_BUF_SZ - off_w);
		if (n == -1) {
			log_error("read: %s\n", strerror(errno));
			break;
		} else if (n == 0) {
			log_warn("read returned %d\n", n);
			continue;
		} else if (first_time) {
			// pppd did talk, now we can write to it if we want
			sem_post(&sem_pppd_ready);
			first_time = 0;
		}
		off_w += n;

		// We have data in the buffer, there may be zero, one or many
		// packets inside.
		off_r = 0;
		while (1) {
			ssize_t frm_len, pktsize;
			struct ppp_packet *packet, *repacket;

			if ((frm_len = hdlc_find_frame(buf, off_w, &off_r))
			    == ERR_HDLC_NO_FRAME_FOUND)
				break;

			pktsize = estimated_decoded_size(frm_len);
			packet = malloc(sizeof(*packet) + 6 + pktsize);
			if (packet == NULL) {
				log_warn("malloc failed.\n");
				break;
			}

			pktsize = hdlc_decode(&buf[off_r], frm_len,
			                      pkt_data(packet), pktsize);
			if (pktsize < 0) {
				log_error("Failed to decode PPP packet from "
				          "HDLC frame (%s).\n",
				          (pktsize == ERR_HDLC_BAD_CHECKSUM ?
				           "bad checksum" :
				           (pktsize == ERR_HDLC_INVALID_FRAME ?
				            "invalid frame" : "unknown")));
				goto exit;
			}
			// Reduce the malloc'ed area now that we know the
			// actual packet length
			repacket = realloc(packet,
			                   sizeof(*packet) + 6 + pktsize);
			if (repacket == NULL) {
				free(packet);
				goto exit;
			}
			packet = repacket;
			packet->len = pktsize;

			log_debug("pppd ---> gateway (%d bytes)\n", packet->len);
			log_packet("pppd:   ", packet->len, pkt_data(packet));
			pool_push(&tunnel->pty_to_ssl_pool, packet);

			off_r += frm_len;
		}

		// Do not discard remaining data
		if (off_r > 0 && off_r < off_w) {
			memmove(buf, &buf[off_r], off_w - off_r);
		}
		off_w = off_w - off_r;
	}

exit:
	// Send message to main thread to stop other threads
	sem_post(&sem_stop_io);
	return NULL;
}

/*
 * Thread to pop packets from the 'ssl_to_pty' pool, and send them to the pppd
 * process through its pty.
 */
static void *pppd_write(void *arg)
{
	struct tunnel *tunnel = (struct tunnel *) arg;
	fd_set write_fd;

	FD_ZERO(&write_fd);
	FD_SET(tunnel->pppd_pty, &write_fd);

	// Write for pppd to talk first, otherwise unpredictable
	sem_wait(&sem_pppd_ready);

	log_debug("pppd_write thread\n");

	while (1) {
		struct ppp_packet *packet;
		ssize_t hdlc_bufsize, len, n, written;
		uint8_t *hdlc_buffer;

		// This waits until a packet has arrived from the gateway
		packet = pool_pop(&tunnel->ssl_to_pty_pool);

		hdlc_bufsize = estimated_encoded_size(packet->len);
		hdlc_buffer = malloc(hdlc_bufsize);
		if (hdlc_buffer == NULL) {
			log_warn("malloc failed.\n");
			break;
		}
		len = hdlc_encode(hdlc_buffer, hdlc_bufsize,
		                  pkt_data(packet), packet->len);
		if (len < 0) {
			log_error("Failed to encode PPP packet into HDLC "
			          "frame.\n");
			goto err_free_buf;
		}

		written = 0;
		while (written < len) {
			int sel;

			sel = select(tunnel->pppd_pty + 1, NULL, &write_fd,
			             NULL, NULL);
			if (sel == -1) {
				log_error("select: %s\n", strerror(errno));
				break;
			} else if (sel == 0) {
				log_warn("select returned 0\n");
				continue;
			}
			n = write(tunnel->pppd_pty, &hdlc_buffer[written],
			          len - written);
			if (n == -1) {
				log_error("write: %s\n", strerror(errno));
#ifdef __APPLE__
				sem_post(&sem_if_config);
#endif
				goto err_free_buf;
			}
			written += n;
		}

		free(hdlc_buffer);
		free(packet);
		continue;
err_free_buf:
		free(hdlc_buffer);
		free(packet);
		break;
	}

	// Send message to main thread to stop other threads
	sem_post(&sem_stop_io);
	return NULL;
}

#define packet_is_ip_plus_dns(packet) \
	((packet)->len >= 12 \
	 && pkt_data(packet)[0] == 0x80 \
	 && pkt_data(packet)[1] == 0x21 \
	 && pkt_data(packet)[2] == 0x02 \
	 && pkt_data(packet)[6] == 0x03)

#define packet_is_end_negociation(packet) \
	((packet)->len == 6 \
	 && pkt_data(packet)[0] == 0x80 \
	 && pkt_data(packet)[1] == 0x21 \
	 && pkt_data(packet)[2] == 0x01 \
	 && pkt_data(packet)[4] == 0x00 \
	 && pkt_data(packet)[5] == 0x04)

static inline void set_tunnel_ips(struct tunnel *tunnel,
                                  struct ppp_packet *packet)
{
	memcpy(&tunnel->ipv4.ip_addr.s_addr, &pkt_data(packet)[8],
	       sizeof(uint32_t));
	if (packet->len >= 18 && pkt_data(packet)[12] == 0x81) {
		memcpy(&tunnel->ipv4.ns1_addr.s_addr, &pkt_data(packet)[14],
		       sizeof(uint32_t));
	}
	if (packet->len >= 24 && pkt_data(packet)[18] == 0x83) {
		memcpy(&tunnel->ipv4.ns2_addr.s_addr, &pkt_data(packet)[20],
		       sizeof(uint32_t));
	}
}

#define printable_char(c) \
    (c == '\t' || c == '\n' || (c >= ' ' && c <= '~'))

static void debug_bad_packet(struct tunnel *tunnel, uint8_t *header)
{
	uint8_t buffer[256];
	int size, i;

	memcpy(buffer, header, 6 * sizeof(uint8_t));

	size = safe_ssl_read(tunnel->ssl_handle, &buffer[6], 256 - 6);
	if (size < 0)
		return;
	size += 6;

	// Print hex dump
	do_log_packet("  (hex) ", size, buffer);

	// then print the raw string, after escaping non-displayable chars
	for (i = 0; i < size; i++)
		if (!printable_char((char) buffer[i]))
			buffer[i] = '.';
	buffer[i] = buffer[256 - 1] = '\0';

	printf("  (raw) %s\n", (char *) buffer);
}

/*
 * Thread to read bytes from the SSL socket, convert them to ppp packets and add
 * them to the 'ssl_to_pty' pool.
 */
static void *ssl_read(void *arg)
{
	struct tunnel *tunnel = (struct tunnel *) arg;
	//uint8_t buf[PKT_BUF_SZ];

	log_debug("ssl_read_thread\n");

	while (1) {
		struct ppp_packet *packet;
		int ret;
		uint8_t header[6];
		uint16_t total, magic, size;

		ret = safe_ssl_read_all(tunnel->ssl_handle, header, 6);
		if (ret < 0) {
			log_debug("Error reading from SSL connection (%s).\n",
			          err_ssl_str(ret));
			goto exit;
		}

		total = header[0] << 8 | header[1];
		magic = header[2] << 8 | header[3];
		size = header[4] << 8 | header[5];
		if (magic != 0x5050 || total != size + 6) {
			log_error("Received bad header from gateway:\n");
			debug_bad_packet(tunnel, header);
			break;
		}

		packet = malloc(sizeof(struct ppp_packet) + 6 + size);
		if (packet == NULL) {
			log_error("malloc failed\n");
			break;
		}
		memcpy(pkt_header(packet), header, 6);
		packet->len = size;

		ret = safe_ssl_read_all(tunnel->ssl_handle, pkt_data(packet),
		                        size);
		if (ret < 0) {
			log_debug("Error reading from SSL connection (%s).\n",
			          err_ssl_str(ret));
			free(packet);
			goto exit;
		}

		log_debug("gateway ---> pppd (%d bytes)\n", packet->len);
		log_packet("gtw:    ", packet->len, pkt_data(packet));
		pool_push(&tunnel->ssl_to_pty_pool, packet);

		if (tunnel->state == STATE_CONNECTING) {
			if (packet_is_ip_plus_dns(packet)) {
				char line[128];
				set_tunnel_ips(tunnel, packet);
				strcpy(line, "[");
				strcat(line, inet_ntoa(tunnel->ipv4.ip_addr));
				strcat(line, "], ns [");
				strcat(line, inet_ntoa(tunnel->ipv4.ns1_addr));
				strcat(line, ", ");
				strcat(line, inet_ntoa(tunnel->ipv4.ns2_addr));
				strcat(line, "]");
				log_info("Got addresses: %s\n", line);
			} else if (packet_is_end_negociation(packet)) {
				sem_post(&sem_if_config);
			}
		}
	}

exit:
	// Send message to main thread to stop other threads
	sem_post(&sem_stop_io);
	return NULL;
}

/*
 * Thread to pop packets from the 'pty_to_ssl' pool, and write them to the SSL
 * socket.
 */
static void *ssl_write(void *arg)
{
	struct tunnel *tunnel = (struct tunnel *) arg;

	log_debug("ssl_write_thread\n");

	while (1) {
		struct ppp_packet *packet;
		int ret;

		// This waits until a packet has arrived from pppd
		packet = pool_pop(&tunnel->pty_to_ssl_pool);

		pkt_header(packet)[0] = (6 + packet->len) >> 8;
		pkt_header(packet)[1] = (6 + packet->len) & 0xff;
		pkt_header(packet)[2] = 0x50;
		pkt_header(packet)[3] = 0x50;
		pkt_header(packet)[4] = packet->len >> 8;
		pkt_header(packet)[5] = packet->len & 0xff;

		do {
			ret = safe_ssl_write(tunnel->ssl_handle,
			                     packet->content, 6 + packet->len);
		} while (ret == 0);
		if (ret < 0) {
			log_debug("Error writing to SSL connection (%s).\n",
			          err_ssl_str(ret));
			free(packet);
			break;
		}
		free(packet);
	}

	// Send message to main thread to stop other threads
	sem_post(&sem_stop_io);
	return NULL;
}

/*
 * Thread to pop packets from the 'pty_to_ssl' pool, and write them to the SSL
 * socket.
 */
static void *if_config(void *arg)
{
	struct tunnel *tunnel = (struct tunnel *) arg;
	int timeout = 60000000; // one minute

	log_debug("if_config thread\n");

	// Wait for the right moment to configure IP interface
	sem_wait(&sem_if_config);

	while (1) {
		if (ppp_interface_is_up(tunnel)) {
			if (tunnel->on_ppp_if_up != NULL)
				if (tunnel->on_ppp_if_up(tunnel))
					goto error;
			tunnel->state = STATE_UP;
			break;
		} else if (timeout == 0) {
			log_error("Timed out waiting for the ppp interface to "
			          "be UP.\n");
			break;
		}
		log_debug("if_config: not ready yet...\n");
		timeout -= 200000;
		usleep(200000);
	}
	if (tunnel->state != STATE_UP)
		goto error;

	return NULL;
error:
	// Send message to main thread to stop other threads
	sem_post(&sem_stop_io);
	return NULL;
}

static void sig_handler(int signo)
{
	if (signo == SIGINT)
		sem_post(&sem_stop_io);
}

int io_loop(struct tunnel *tunnel)
{
	int tcp_nodelay_flag = 1;

	pthread_t pty_read_thread;
	pthread_t pty_write_thread;
	pthread_t ssl_read_thread;
	pthread_t ssl_write_thread;
	pthread_t if_config_thread;

	sem_init(&sem_pppd_ready, 0, 0);
	sem_init(&sem_if_config, 0, 0);
	sem_init(&sem_stop_io, 0, 0);

	init_ppp_packet_pool(&tunnel->ssl_to_pty_pool);
	init_ppp_packet_pool(&tunnel->pty_to_ssl_pool);

	init_ssl_locks();

	/*
	 * I noticed that using TCP_NODELAY (i.e. disabling Nagle's algorithm)
	 * gives much better performance. Probably because setting up the VPN
	 * is sending and receiving many small packets.
	 * A small benchmark gave these results:
	 *   - with TCP_NODELAY:                   ~ 4000 kbit/s
	 *   - without TCP_NODELAY:                ~ 1200 kbit/s
	 *   - forticlientsslvpn from Fortinet:    ~ 3700 kbit/s
	 *   - openfortivpn, Python version:       ~ 2000 kbit/s
	 *     (with or without TCP_NODELAY)
	 */
	setsockopt(tunnel->ssl_socket, IPPROTO_TCP, TCP_NODELAY,
	           (char *) &tcp_nodelay_flag, sizeof(int));

// on osx this prevents the program from being stopped with ctrl-c
#ifndef __APPLE__
	// Disable SIGINT for the future spawned threads
	sigset_t sigset, oldset;
	sigemptyset(&sigset);
	sigaddset(&sigset, SIGINT);
	pthread_sigmask(SIG_BLOCK, &sigset, &oldset);
#endif

	// Set signal handler
	if (signal(SIGINT, sig_handler) == SIG_ERR)
		goto err_signal;

	if (pthread_create(&pty_read_thread, NULL, pppd_read, tunnel))
		goto err_thread;
	if (pthread_create(&pty_write_thread, NULL, pppd_write, tunnel))
		goto err_thread;
	if (pthread_create(&ssl_read_thread, NULL, ssl_read, tunnel))
		goto err_thread;
	if (pthread_create(&ssl_write_thread, NULL, ssl_write, tunnel))
		goto err_thread;
	if (pthread_create(&if_config_thread, NULL, if_config, tunnel))
		goto err_thread;

#ifndef __APPLE__
	// Restore the signal for the main thread
	pthread_sigmask(SIG_SETMASK, &oldset, NULL);
#endif

	// Wait for one of the thread to ask termination
	sem_wait(&sem_stop_io);

	log_info("Cancelling threads...\n");
	pthread_cancel(if_config_thread);
	pthread_cancel(ssl_write_thread);
	pthread_cancel(ssl_read_thread);
	pthread_cancel(pty_write_thread);
	pthread_cancel(pty_read_thread);

	pthread_join(if_config_thread, NULL);
	pthread_join(ssl_write_thread, NULL);
	pthread_join(ssl_read_thread, NULL);
	pthread_join(pty_write_thread, NULL);
	pthread_join(pty_read_thread, NULL);

	destroy_ssl_locks();

	destroy_ppp_packet_pool(&tunnel->pty_to_ssl_pool);
	destroy_ppp_packet_pool(&tunnel->ssl_to_pty_pool);

	sem_destroy(&sem_stop_io);
	sem_destroy(&sem_if_config);
	sem_destroy(&sem_pppd_ready);

	return 0;

err_thread:
err_signal:
	return 1;
}
