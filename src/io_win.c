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
 *  Windows I/O loop implementation.
 *  Replaces io.c for Windows builds, using wintun instead of pppd.
 */

#ifdef _WIN32

#include "tunnel.h"
#include "ppp.h"
#include "wintun.h"
#include "ssl.h"
#include "log.h"

#include <windows.h>
#include <pthread.h>

#include <assert.h>
#include <string.h>

#define PKT_BUF_SZ 0x1000

/* Windows semaphore abstraction (matching io.c pattern) */
typedef HANDLE os_semaphore_t;
#define SEM_INIT(sem, x, value) \
	(*(sem) = CreateSemaphore(NULL, value, LONG_MAX, NULL))
#define SEM_WAIT(sem)      WaitForSingleObject(*(sem), INFINITE)
#define SEM_POST(sem)      ReleaseSemaphore(*(sem), 1, NULL)
#define SEM_DESTROY(sem)   CloseHandle(*(sem))

static os_semaphore_t sem_ppp_ready;
static os_semaphore_t sem_if_config;
static os_semaphore_t sem_stop_io;

/*
 * Shutdown flag: set to 1 when io_loop wants all threads to exit.
 * Threads check this after every blocking call returns an error.
 */
static volatile LONG shutting_down;

/* Global variable to pass signal out of its handler */
volatile long sig_received;

int get_sig_received(void)
{
	return (int)sig_received;
}

static BOOL WINAPI win_ctrl_handler(DWORD ctrl_type)
{
	if (ctrl_type == CTRL_C_EVENT ||
	    ctrl_type == CTRL_BREAK_EVENT ||
	    ctrl_type == CTRL_CLOSE_EVENT) {
		InterlockedExchange(&sig_received, SIGTERM);
		SEM_POST(&sem_stop_io);
		return TRUE;
	}
	return FALSE;
}

/*
 * Packet pool operations.
 *
 * pool_pop blocks until a packet is available. To unblock a thread
 * during shutdown, push a NULL-length poison pill via pool_poison.
 */
static void pool_push(struct ppp_packet_pool *pool,
                      struct ppp_packet *new)
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
 * Returns NULL during shutdown (poison pill received).
 */
static struct ppp_packet *pool_pop(struct ppp_packet_pool *pool)
{
	struct ppp_packet *packet;

	pthread_mutex_lock(&pool->mutex);
	while (pool->list_head == NULL)
		pthread_cond_wait(&pool->new_data, &pool->mutex);
	packet = pool->list_head;
	pool->list_head = packet->next;
	pthread_mutex_unlock(&pool->mutex);

	/* Poison pill: len == 0 and allocated with just the header */
	if (packet->len == 0) {
		free(packet);
		return NULL;
	}

	return packet;
}

/*
 * Push a poison pill to unblock a thread waiting in pool_pop.
 */
static void pool_poison(struct ppp_packet_pool *pool)
{
	struct ppp_packet *pill;

	pill = malloc(sizeof(*pill) + 6);
	if (!pill)
		return;
	pill->len = 0;
	pill->next = NULL;
	pool_push(pool, pill);
}

/*
 * Thread: Read packets from TLS socket, process through PPP.
 * Exits when SSL_read returns an error (socket closed by shutdown).
 */
static void *ssl_read_thread(void *arg)
{
	struct tunnel *tunnel = (struct tunnel *)arg;
	struct ppp_context *ppp_ctx =
	        (struct ppp_context *)tunnel->ppp_ctx;

	log_debug("%s thread\n", __func__);

	while (!InterlockedCompareExchange(&shutting_down, 0, 0)) {
		uint8_t header[6];
		uint16_t total, magic, size;
		int ret;
		struct ppp_packet *packet;
		uint8_t *response, *ip_payload;
		size_t resp_len, ip_len;
		int ppp_ret;

		ret = safe_ssl_read_all(tunnel->ssl_handle, header, 6);
		if (ret < 0)
			break;

		total = (header[0] << 8) | header[1];
		magic = (header[2] << 8) | header[3];
		size  = (header[4] << 8) | header[5];

		if (magic != 0x5050)
			break;

		if (size == 0)
			continue;

		packet = malloc(sizeof(*packet) + 6 + size);
		if (!packet)
			break;
		packet->len = size;

		ret = safe_ssl_read_all(tunnel->ssl_handle,
		                        pkt_data(packet), size);
		if (ret < 0) {
			free(packet);
			break;
		}

		log_debug("gateway ---> tun (%u bytes)\n", size);

		ppp_ret = ppp_process_incoming(ppp_ctx,
		                               pkt_data(packet), size,
		                               &response, &resp_len,
		                               &ip_payload, &ip_len);

		if (ppp_ret == PPP_RET_IP_PACKET) {
			struct ppp_packet *ip_pkt;

			ip_pkt = malloc(sizeof(*ip_pkt) + 6 + ip_len);
			if (ip_pkt) {
				ip_pkt->len = ip_len;
				memcpy(pkt_data(ip_pkt),
				       ip_payload, ip_len);
				pool_push(&tunnel->ssl_to_pty_pool,
				          ip_pkt);
			}
			free(ip_payload);
		} else if (ppp_ret == PPP_RET_NEGOTIATE) {
			SEM_POST(&sem_if_config);
		} else if (ppp_ret == PPP_RET_TERMINATED) {
			free(response);
			free(packet);
			break;
		}

		if (response) {
			struct ppp_packet *resp_pkt;

			resp_pkt = malloc(sizeof(*resp_pkt) + 6 + resp_len);
			if (resp_pkt) {
				resp_pkt->len = resp_len;
				memcpy(pkt_data(resp_pkt),
				       response, resp_len);
				pool_push(&tunnel->pty_to_ssl_pool,
				          resp_pkt);
			}
			free(response);
		}

		free(packet);
	}

	SEM_POST(&sem_stop_io);
	return NULL;
}

/*
 * Thread: Pop PPP packets and write to TLS.
 * Exits when it receives a poison pill (NULL from pool_pop).
 */
static void *ssl_write_thread(void *arg)
{
	struct tunnel *tunnel = (struct tunnel *)arg;

	log_debug("%s thread\n", __func__);

	while (1) {
		struct ppp_packet *packet;
		int ret;

		packet = pool_pop(&tunnel->pty_to_ssl_pool);
		if (!packet)
			break; /* poison pill */

		pkt_header(packet)[0] = (6 + packet->len) >> 8;
		pkt_header(packet)[1] = (6 + packet->len) & 0xff;
		pkt_header(packet)[2] = 0x50;
		pkt_header(packet)[3] = 0x50;
		pkt_header(packet)[4] = packet->len >> 8;
		pkt_header(packet)[5] = packet->len & 0xff;

		do {
			ret = safe_ssl_write(tunnel->ssl_handle,
			                     packet->content,
			                     6 + packet->len);
		} while (ret == 0 &&
		         !InterlockedCompareExchange(
		                 &shutting_down, 0, 0));

		free(packet);
		if (ret < 0)
			break;
	}

	SEM_POST(&sem_stop_io);
	return NULL;
}

/*
 * Thread: Read IP packets from wintun, encapsulate in PPP.
 * Exits when the wintun session is ended (ReceivePacket returns NULL
 * and GetLastError is ERROR_INVALID_DATA after EndSession).
 */
static void *tun_read_thread(void *arg)
{
	struct tunnel *tunnel = (struct tunnel *)arg;
	WINTUN_SESSION_HANDLE session =
	        (WINTUN_SESSION_HANDLE)tunnel->tun_session;
	struct wintun_api *api =
	        (struct wintun_api *)tunnel->tun_adapter;
	HANDLE read_event;

	SEM_WAIT(&sem_ppp_ready);

	log_debug("%s thread\n", __func__);

	read_event = api->GetReadWaitEvent(session);

	while (!InterlockedCompareExchange(&shutting_down, 0, 0)) {
		DWORD pkt_size;
		BYTE *pkt;
		DWORD wait_ret;

		wait_ret = WaitForSingleObject(read_event, 1000);
		if (wait_ret == WAIT_TIMEOUT)
			continue;
		if (wait_ret != WAIT_OBJECT_0)
			break;

		while ((pkt = api->ReceivePacket(session,
		                                 &pkt_size)) != NULL) {
			uint8_t *ppp_data;
			size_t ppp_len;
			struct ppp_packet *packet;

			if (ppp_encapsulate_ip(pkt, pkt_size,
			                       &ppp_data,
			                       &ppp_len) == 0) {
				packet = malloc(sizeof(*packet) +
				                6 + ppp_len);
				if (packet) {
					packet->len = ppp_len;
					memcpy(pkt_data(packet),
					       ppp_data, ppp_len);
					pool_push(
					        &tunnel->pty_to_ssl_pool,
					        packet);
					log_debug(
					        "tun ---> gateway (%lu bytes)\n",
					        (unsigned long)ppp_len);
				}
				free(ppp_data);
			}

			api->ReleaseReceivePacket(session, pkt);
		}

		/*
		 * ReceivePacket returned NULL. If the session was
		 * ended by shutdown, ERROR_INVALID_DATA is set.
		 */
		if (GetLastError() == ERROR_INVALID_DATA)
			break;
	}

	SEM_POST(&sem_stop_io);
	return NULL;
}

/*
 * Thread: Pop IP packets and write to wintun.
 * Exits when it receives a poison pill or AllocateSendPacket fails
 * because the session was ended.
 */
static void *tun_write_thread(void *arg)
{
	struct tunnel *tunnel = (struct tunnel *)arg;
	WINTUN_SESSION_HANDLE session =
	        (WINTUN_SESSION_HANDLE)tunnel->tun_session;
	struct wintun_api *api =
	        (struct wintun_api *)tunnel->tun_adapter;

	SEM_WAIT(&sem_ppp_ready);

	log_debug("%s thread\n", __func__);

	while (1) {
		struct ppp_packet *packet;
		BYTE *buf;

		packet = pool_pop(&tunnel->ssl_to_pty_pool);
		if (!packet)
			break; /* poison pill */

		buf = api->AllocateSendPacket(session,
		                              (DWORD)packet->len);
		if (buf) {
			memcpy(buf, pkt_data(packet), packet->len);
			api->SendPacket(session, buf);
		} else {
			/* Session ended — exit cleanly */
			free(packet);
			break;
		}

		free(packet);
	}

	SEM_POST(&sem_stop_io);
	return NULL;
}

/*
 * Thread: Wait for PPP negotiation, then configure the interface.
 */
static void *if_config_thread(void *arg)
{
	struct tunnel *tunnel = (struct tunnel *)arg;
	int timeout = 60000;

	log_debug("%s thread\n", __func__);

	SEM_WAIT(&sem_if_config);

	/* Unblock tun_read and tun_write */
	SEM_POST(&sem_ppp_ready);
	SEM_POST(&sem_ppp_ready);

	while (timeout > 0) {
		if (ppp_interface_is_up(tunnel)) {
			if (tunnel->on_ppp_if_up != NULL)
				if (tunnel->on_ppp_if_up(tunnel))
					goto error;
			tunnel->state = STATE_UP;
			break;
		}
		Sleep(200);
		timeout -= 200;
	}

	if (tunnel->state != STATE_UP) {
		log_error("Timed out waiting for interface UP.\n");
		goto error;
	}

	return NULL;
error:
	SEM_POST(&sem_stop_io);
	return NULL;
}

int io_loop(struct tunnel *tunnel)
{
	int tcp_nodelay_flag = 1;
	int ret = 0;

	pthread_t tun_read_thr;
	pthread_t tun_write_thr;
	pthread_t ssl_read_thr;
	pthread_t ssl_write_thr;
	pthread_t if_config_thr;

	InterlockedExchange(&shutting_down, 0);

	SEM_INIT(&sem_ppp_ready, 0, 0);
	SEM_INIT(&sem_if_config, 0, 0);
	SEM_INIT(&sem_stop_io, 0, 0);

	init_ppp_packet_pool(&tunnel->ssl_to_pty_pool);
	init_ppp_packet_pool(&tunnel->pty_to_ssl_pool);

	if (setsockopt(tunnel->ssl_socket, IPPROTO_TCP,
	               TCP_NODELAY,
	               (const char *)&tcp_nodelay_flag,
	               sizeof(int))) {
		log_error("setsockopt TCP_NODELAY: %d\n",
		          WSAGetLastError());
		goto err_cleanup;
	}

	SetConsoleCtrlHandler(win_ctrl_handler, TRUE);

	/* Seed PPP negotiation */
	{
		struct ppp_context *ppp_ctx =
		        (struct ppp_context *)tunnel->ppp_ctx;
		uint8_t *start_pkt;
		size_t start_len;

		if (ppp_start_negotiation(ppp_ctx, &start_pkt,
		                          &start_len) == 0) {
			struct ppp_packet *pkt;

			pkt = malloc(sizeof(*pkt) + 6 + start_len);
			if (pkt) {
				pkt->len = start_len;
				memcpy(pkt_data(pkt), start_pkt,
				       start_len);
				pool_push(&tunnel->pty_to_ssl_pool,
				          pkt);
			}
			free(start_pkt);
		}
	}

	/* Create worker threads */
	if (pthread_create(&ssl_read_thr, NULL,
	                   ssl_read_thread, tunnel) ||
	    pthread_create(&ssl_write_thr, NULL,
	                   ssl_write_thread, tunnel) ||
	    pthread_create(&tun_read_thr, NULL,
	                   tun_read_thread, tunnel) ||
	    pthread_create(&tun_write_thr, NULL,
	                   tun_write_thread, tunnel) ||
	    pthread_create(&if_config_thr, NULL,
	                   if_config_thread, tunnel)) {
		log_error("Failed to create I/O threads\n");
		goto err_cleanup;
	}

	/* Block until any thread signals shutdown */
	SEM_WAIT(&sem_stop_io);

	/*
	 * Graceful shutdown sequence:
	 * 1. Set shutdown flag so loops check on next iteration
	 * 2. Close the SSL socket — unblocks ssl_read/ssl_write
	 * 3. End the wintun session — unblocks tun_read/tun_write
	 * 4. Poison the packet pools — unblocks pool_pop waiters
	 * 5. Join all threads (they exit through normal error paths)
	 */
	log_info("Shutting down I/O...\n");
	InterlockedExchange(&shutting_down, 1);

	/* Unblock SSL threads by closing the socket */
	if (tunnel->ssl_handle) {
		SSL_shutdown(tunnel->ssl_handle);
		SSL_free(tunnel->ssl_handle);
		tunnel->ssl_handle = NULL;
	}
	if (tunnel->ssl_socket >= 0) {
		closesocket(tunnel->ssl_socket);
		tunnel->ssl_socket = -1;
	}

	/* Unblock TUN threads by ending the session */
	if (tunnel->tun_session) {
		struct wintun_api *api =
		        (struct wintun_api *)tunnel->tun_adapter;

		api->EndSession(
		        (WINTUN_SESSION_HANDLE)tunnel->tun_session);
		tunnel->tun_session = NULL;
	}

	/* Unblock pool_pop waiters */
	pool_poison(&tunnel->pty_to_ssl_pool);
	pool_poison(&tunnel->ssl_to_pty_pool);

	/* Unblock threads still waiting on semaphores */
	SEM_POST(&sem_ppp_ready);
	SEM_POST(&sem_ppp_ready);
	SEM_POST(&sem_if_config);

	pthread_join(ssl_read_thr, NULL);
	pthread_join(ssl_write_thr, NULL);
	pthread_join(tun_read_thr, NULL);
	pthread_join(tun_write_thr, NULL);
	pthread_join(if_config_thr, NULL);

	log_info("I/O threads stopped.\n");

err_cleanup:
	destroy_ppp_packet_pool(&tunnel->ssl_to_pty_pool);
	destroy_ppp_packet_pool(&tunnel->pty_to_ssl_pool);

	SEM_DESTROY(&sem_ppp_ready);
	SEM_DESTROY(&sem_if_config);
	SEM_DESTROY(&sem_stop_io);

	SetConsoleCtrlHandler(win_ctrl_handler, FALSE);

	return ret;
}

#endif /* _WIN32 */
