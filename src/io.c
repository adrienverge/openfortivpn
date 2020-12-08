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

#include "io.h"
#include "hdlc.h"
#include "ssl.h"
#include "tunnel.h"
#include "log.h"

#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <net/if_ppp.h>

#include <errno.h>
#include <signal.h>
#include <string.h>

#if HAVE_MACH_MACH_H
/* this is typical for mach kernel used on Mac OS X */
#include <mach/mach.h>

/* Mac OS X defines sem_init but actually does not implement them */
typedef semaphore_t os_semaphore_t;

#define SEM_INIT(sem, x, value)	semaphore_create(mach_task_self(), sem, \
								SYNC_POLICY_FIFO, value)
#define SEM_WAIT(sem)			semaphore_wait(*(sem))
#define SEM_POST(sem)			semaphore_signal(*(sem))
#define SEM_DESTROY(sem)		semaphore_destroy(mach_task_self(), *(sem))

#else

#include <semaphore.h>

typedef sem_t os_semaphore_t;

#define SEM_INIT(sem, x, value)	sem_init(sem, x, value)
#define SEM_WAIT(sem)			sem_wait(sem)
#define SEM_POST(sem)			sem_post(sem)
#define SEM_DESTROY(sem)		sem_destroy(sem)

#endif

#define PKT_BUF_SZ 0x1000

#if OPENSSL_VERSION_NUMBER < 0x10100000L
static pthread_mutex_t *lockarray;

static void lock_callback(int mode, int type, const char *file, int line)
{
	if (mode & CRYPTO_LOCK)
		pthread_mutex_lock(&lockarray[type]);
	else
		pthread_mutex_unlock(&lockarray[type]);
}

static unsigned long thread_id(void)
{
	return (unsigned long) pthread_self();
}

static void init_ssl_locks(void)
{
	lockarray = (pthread_mutex_t *) OPENSSL_malloc(CRYPTO_num_locks() *
	                sizeof(pthread_mutex_t));
	for (int i = 0; i < CRYPTO_num_locks(); i++)
		pthread_mutex_init(&lockarray[i], NULL);
	CRYPTO_set_id_callback((unsigned long (*)()) thread_id);
	CRYPTO_set_locking_callback((void (*)()) lock_callback);
}

static void destroy_ssl_locks(void)
{
	CRYPTO_set_locking_callback(NULL);
	for (int i = 0; i < CRYPTO_num_locks(); i++)
		pthread_mutex_destroy(&lockarray[i]);
	OPENSSL_free(lockarray);
	lockarray = NULL;
}
#else
static void init_ssl_locks(void)
{
}

static void destroy_ssl_locks(void)
{
}
#endif

// global variable to pass signal out of its handler
volatile sig_atomic_t sig_received; //static variables are initialized to zero in C99

int get_sig_received(void)
{
	return (int)sig_received;
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
	struct ppp_packet *first;

	pthread_mutex_lock(&pool->mutex);

	while (pool->list_head == NULL)
		pthread_cond_wait(&pool->new_data, &pool->mutex);

	first = pool->list_head;
	pool->list_head = first->next;
	first->next = NULL;

	pthread_mutex_unlock(&pool->mutex);

	return first;
}

static os_semaphore_t sem_pppd_ready;
static os_semaphore_t sem_if_config;
static os_semaphore_t sem_stop_io;

struct lcp_header {
	uint8_t   code;
#define LCP_CONF_REQUEST    1
#define LCP_CONF_ACK        2
#define LCP_CONF_NAK        3
#define LCP_CONF_REJECT     4
#define LCP_TERM_REQUEST    5
#define LCP_TERM_ACK        6
#define LCP_CODE_REJECT     7
#define LCP_PROT_REJECT     8
#define LCP_ECHO_REQUEST    9
#define LCP_ECHO_REPLY      10
#define LCP_DISCARD         11
	uint8_t   id;
	uint16_t length;
};

const char *lcp_code_name[] = {
	"",
	"Configure-Request",
	"Configure-Ack",
	"Configure-Nak",
	"Configure-Reject",
	"Terminate-Request",
	"Terminate-Ack",
	"Code-Reject",
	"Protocol-Reject",
	"Echo-Request",
	"Echo-Reply",
	"Discard-Request",
};
struct lcp_conf_request {
	struct lcp_header header;
};
struct conf_option {
	uint8_t   type;
#define LCP_COPT_MRU      1
#define LCP_COPT_ACCM     2
#define LCP_COPT_AUTH     3
#define LCP_COPT_QUALITY  4
#define LCP_COPT_MAGIC    5
#define LCP_COPT_PFC      7
#define LCP_COPT_ACFC     8
	uint8_t   length;
	uint8_t   data[];
};
static void *co_data(struct conf_option *co)
{
	return co->data;
}

struct conf_option_list {
	struct conf_option *head;
	struct conf_option *tail;
};

struct lcp_option_conf {
	int flag;
#define LCP_OF_VALID   0x10000
	int len;
	const char *name;
};
int default_mru = 1534;
const struct lcp_option_conf lcp_valid_options[256] = {
	[0] = {           0, 0, "RESERVED",                   },
	[1] = {LCP_OF_VALID, 4, "MRU",                        },		/* RFC 1661 */
	[2] = {LCP_OF_VALID, 6, "Async-Control-Character-Map",},		/* RFC 1172 */
	[3] = {LCP_OF_VALID, 4, "Auth-Protocol",              },
	[4] = {LCP_OF_VALID, 4, "Quality-Protocol",           },
	[5] = {LCP_OF_VALID, 6, "Magic-Num",                  },
	[6] = {LCP_OF_VALID, 6, "Link-Quality-Monitoring",    },		/* RFC 1172 */
	[7] = {LCP_OF_VALID, 2, "Protocol-Field-Comp",        },
	[8] = {LCP_OF_VALID, 2, "Addr&Ctrl-Field-Comp",       },          
};
struct lcp_option_value {
	int flag;
#define LCP_OF_DEFAULT 0x20000
#define LCP_OF_DISABLE 0x00100
#define LCP_OF_LINK    0x000FF
	int len;
	union {
		int boolean;
		int number;
	} u;
	void *extra;
};
int magic_seed = 0x64696E67;
/*
struct conf_option lcp_default[256] = {
	[1] = {LCP_OF_DEFAULT, {.number = 1500}, },
	[2] = {LCP_OF_DEFAULT, {.number = 0xFFFFFFFF}, },
	[3] = {LCP_OF_DEFAULT | LCP_OF_DISABLE, },
	[4] = {LCP_OF_DEFAULT | LCP_OF_DISABLE, },
	[5] = {LCP_OF_DEFAULT | LCP_OF_DISABLE, },
	[6] = {LCP_OF_DEFAULT | LCP_OF_DISABLE, },
	[7] = {LCP_OF_DEFAULT | LCP_OF_DISABLE, },
	[8] = {LCP_OF_DEFAULT | LCP_OF_DISABLE, },
};
*/
struct conf_option *lcp_self[256] = {
	NULL,
};
struct conf_option *lcp_peer[256] = {
	NULL,
};

static int lcp_id = 0;
int conf_option_get(struct conf_option **options, int type, void *data, int len)
{
	struct conf_option *opt = options[type];
	if (opt != NULL) {
		int copy = opt->length - 2;
		if (copy > len) {
			copy = len;
		}
		memcpy(data, opt->data, copy);
		return 0;
	}
	return -1;
}
int conf_option_set(struct conf_option **options, int type, int len, void *data)
{
	struct conf_option *opt = options[type];
	if (len == 0) {
		options[type] = NULL;
		free(opt);
		return 0;
	}

	if (opt == NULL) {
		opt = malloc(len);
	} else if (opt->length != len) {
		opt = realloc(opt, len);
	}
	if (opt != NULL) {
		options[type] = opt;
		opt->type = type;
		opt->length = len;
		if (len > 2) {
			memcpy(opt->data, data, len - 2);
		}
	}
	return (opt == NULL) ? -1 : 0;
}
struct conf_option *conf_option_init(struct conf_option_list *optlist)
{
	int header = sizeof(struct lcp_header) + sizeof(uint16_t);
	optlist->head = malloc(header + default_mru);
	if (optlist->head) {
		memset(optlist->head, 0, header + default_mru);
		optlist->head = (struct conf_option *)(((uint8_t *)optlist->head) + header);
		optlist->tail = optlist->head;
	}
	return optlist->head;
}
int conf_option_encode(struct conf_option_list *optlist, int type, int len, void *data)
{
	optlist->tail->type = type;
	optlist->tail->length = len;
	if (len > 2) {
		memcpy(optlist->tail->data, data, len - 2);
	}
	optlist->tail = (struct conf_option *)(optlist->tail->data + len - 2);
	return 0;
}
int conf_option_length(struct conf_option_list *optlist)
{
	int len = 0;
	if (optlist) {
		len = (uint8_t *)optlist->tail - (uint8_t *)optlist->head;
	}
	return len;
}
int conf_option_free(struct conf_option_list *optlist)
{
	if (optlist->head != NULL) {
		int header = sizeof(struct lcp_header) + sizeof(uint16_t);
		free((uint8_t *)optlist->head - header);
		optlist->head = optlist->tail = NULL;
	}
	return 0;
}
int lcp_option_send(struct tunnel *tunnel, int id, int code, struct conf_option_list *optlist, int force)
{
	int ret = -1;
	if (optlist && optlist->head) {
		uint8_t *head = (uint8_t *)optlist->head;
		struct lcp_header *header = ((struct lcp_header *)head) - 1;
		unsigned short *ppp_type = ((unsigned short *)header) - 1;
		int len = conf_option_length(optlist);
		int hdrlen = sizeof(struct lcp_header) + sizeof(uint16_t);

		if (len > 0 || force) {
			ssize_t pktsize;
			struct ppp_packet *packet = NULL;

			*ppp_type = htons(PPP_LCP);
			header->code = code;
			header->id = id ? id : lcp_id ++;
			header->length = htons(len + sizeof(*header));

			pktsize = hdrlen + len;
			packet = malloc(sizeof(*packet) + 6 + pktsize);
			if (packet == NULL) {
				goto out;
			}
			packet->len = pktsize;
			memcpy(pkt_data(packet), ppp_type, pktsize);

			log_debug("%s ---> gateway (%lu bytes)\n", PPP_DAEMON,
				  packet->len);
#if HAVE_USR_SBIN_PPPD
			log_packet("pppd:   ", packet->len, pkt_data(packet));
#else
			log_packet("ppp:   ", packet->len, pkt_data(packet));
#endif
			pool_push(&tunnel->pty_to_ssl_pool, packet);
		}
		ret = 0;
	}

out:
	return ret;
}
int conf_request(struct tunnel *tunnel)
{
	int ret = 0;
	struct conf_option_list request;
	uint16_t mru = htons(default_mru);
	int magic = htonl(magic_seed);
	conf_option_init(&request);
	conf_option_encode(&request, LCP_COPT_MRU, 4, &mru);
	conf_option_encode(&request, LCP_COPT_MAGIC, 6, &magic);
	ret = lcp_option_send(tunnel, 0, LCP_CONF_REQUEST, &request, 1);
	conf_option_free(&request);
	return ret;
}
int lcp_packet(struct tunnel *tunnel, void *packet, int len)
{
	struct lcp_header *header = packet;

	log_debug("packet %s\n", lcp_code_name[header->code]);
	switch (header->code) {
	case LCP_CONF_REQUEST:
	{
		int olen = ntohs(header->length);
		struct conf_option *co = NULL;
		struct conf_option_list ack;
		struct conf_option_list nack;
		struct conf_option_list reject;
		conf_option_init(&ack);
		conf_option_init(&nack);
		conf_option_init(&reject);
		olen -= sizeof(struct lcp_header);
		co = (struct conf_option *)(header + 1);
		while (olen > 0) {
			char buff[128];
			char *p = buff;
			p += sprintf(p, "option %s: ", lcp_valid_options[co->type].name);
			switch (co->type) {
			case LCP_COPT_ACCM:
				p += sprintf(p, "%x", ntohl(*(uint32_t *)co_data(co)));
				conf_option_set(lcp_peer, co->type, co->length, co_data(co));
				conf_option_encode(&ack, co->type, co->length, co_data(co));
				break;
			case LCP_COPT_AUTH:
				switch (ntohs(*(uint16_t *)co_data(co))) {
				case PPP_CHAP:
				{
					struct {
						uint16_t chap;
						uint8_t  algo;
					} *payload = (typeof(*payload) *)co_data(co);
					p += sprintf(p, "CHAP %d", payload->algo);
					break;
				}
				default:
					p += sprintf(p, "%x", ntohs(*(uint16_t *)co_data(co)));
					break;
				}
				conf_option_set(lcp_peer, co->type, co->length, co_data(co));
				conf_option_encode(&ack, co->type, co->length, co_data(co));
				break;
			case LCP_COPT_MAGIC:
				p += sprintf(p, "%x", ntohl(*(uint32_t *)co_data(co)));
				conf_option_set(lcp_peer, co->type, co->length, co_data(co));
				conf_option_encode(&ack, co->type, co->length, co_data(co));
				break;
			case LCP_COPT_PFC:
			case LCP_COPT_ACFC:
				conf_option_set(lcp_peer, co->type, co->length, co_data(co));
				conf_option_encode(&ack, co->type, co->length, co_data(co));
				break;
			default:
				conf_option_encode(&reject, co->type, co->length, co_data(co));
				break;
			}
			log_debug("%s\n", buff);
			olen -= co->length;
			co = (struct conf_option *)((uint8_t *)co + co->length);
		}
		if (header->code == LCP_CONF_REQUEST) {
			int ret = -1;
			ret = lcp_option_send(tunnel, header->id, LCP_CONF_ACK, &ack, 0);
			if (ret < 0) {
				log_error("send conf_ack failed %d: %s\n", errno, strerror(errno));
				exit(1);
			}
			ret = lcp_option_send(tunnel, header->id, LCP_CONF_NAK, &nack, 0);
			if (ret < 0) {
				log_error("send conf_ack failed %d: %s\n", errno, strerror(errno));
				exit(1);
			}
			ret = lcp_option_send(tunnel, header->id, LCP_CONF_REJECT, &reject, 0);
			if (ret < 0) {
				log_error("send conf_ack failed %d: %s\n", errno, strerror(errno));
				exit(1);
			}
			switch (tunnel->tun_state) {
			case TUN_PPP_LCP:
				log_debug("\n\nmove to establishment phase\n");
				tunnel->tun_state = TUN_PPP_IPCP;
			default:
				break;
			}
		}
		conf_option_free(&ack);
		conf_option_free(&nack);
		conf_option_free(&reject);

		break;
	}
	case LCP_CONF_ACK:
	{
		int olen = ntohs(header->length);
		struct conf_option *co = NULL;
		olen -= sizeof(struct lcp_header);
		co = (struct conf_option *)(header + 1);
		while (olen > 0) {
			char buff[128];
			char *p = buff;
			conf_option_set(lcp_self, co->type, co->length, co_data(co));
			p += sprintf(p, "option %s: ", lcp_valid_options[co->type].name);
			switch (co->type) {
			case LCP_COPT_MRU:
				p += sprintf(p, "%d", ntohs(*(uint16_t *)co_data(co)));
				break;
			case LCP_COPT_ACCM:
				p += sprintf(p, "%x", ntohl(*(uint32_t *)co_data(co)));
				break;
			case LCP_COPT_AUTH:
				p += sprintf(p, "%x", ntohs(*(uint16_t *)co_data(co)));
				break;
			case LCP_COPT_MAGIC:
				p += sprintf(p, "%x", ntohl(*(uint32_t *)co_data(co)));
				break;
			case LCP_COPT_PFC:
			case LCP_COPT_ACFC:
				break;
			default:
				break;
			}
			log_debug("%s\n", buff);
			olen -= co->length;
			co = (struct conf_option *)((uint8_t *)co + co->length);
		}

		if (tunnel->tun_state == TUN_PPP_LCP) {
			log_debug("\n\nentering authenticate phase\n");
			tunnel->tun_state = TUN_PPP_IPCP;
		}
		break;
	}
	case LCP_CONF_NAK:
	{
		int olen = ntohs(header->length);
		struct conf_option *co = NULL;
		olen -= sizeof(struct lcp_header);
		co = (struct conf_option *)(header + 1);
		while (olen > 0) {
			char buff[128];
			char *p = buff;
			conf_option_set(lcp_self, co->type, 0, NULL);
			p += sprintf(p, "option %s: ", lcp_valid_options[co->type].name);
			switch (co->type) {
			case LCP_COPT_MRU:
				p += sprintf(p, "%d", ntohs(*(uint16_t *)co_data(co)));
				break;
			case LCP_COPT_ACCM:
				p += sprintf(p, "%x", ntohl(*(uint32_t *)co_data(co)));
				break;
			case LCP_COPT_AUTH:
				p += sprintf(p, "%x", ntohs(*(uint16_t *)co_data(co)));
				break;
			case LCP_COPT_MAGIC:
				p += sprintf(p, "%x", ntohl(*(uint32_t *)co_data(co)));
				break;
			case LCP_COPT_PFC:
			case LCP_COPT_ACFC:
				break;
			default:
				break;
			}
			log_debug("%s\n", buff);
			olen -= co->length;
			co = (struct conf_option *)((uint8_t *)co + co->length);
		}
		break;
	}
	case LCP_CONF_REJECT:
	{
		int olen = ntohs(header->length);
		struct conf_option *co = NULL;
		olen -= sizeof(struct lcp_header);
		co = (struct conf_option *)(header + 1);
		while (olen > 0) {
			char buff[128];
			char *p = buff;
			conf_option_set(lcp_self, co->type, 0, NULL);
			p += sprintf(p, "option %s: ", lcp_valid_options[co->type].name);
			switch (co->type) {
			case LCP_COPT_MRU:
				p += sprintf(p, "%d", ntohs(*(uint16_t *)co_data(co)));
				break;
			case LCP_COPT_ACCM:
				p += sprintf(p, "%x", ntohl(*(uint32_t *)co_data(co)));
				break;
			case LCP_COPT_AUTH:
				p += sprintf(p, "%x", ntohs(*(uint16_t *)co_data(co)));
				break;
			case LCP_COPT_MAGIC:
				p += sprintf(p, "%x", ntohl(*(uint32_t *)co_data(co)));
				break;
			case LCP_COPT_PFC:
			case LCP_COPT_ACFC:
				break;
			default:
				break;
			}
			log_debug("%s\n", buff);
			olen -= co->length;
			co = (struct conf_option *)((uint8_t *)co + co->length);
		}
		break;
	}
	case LCP_TERM_REQUEST:
		break;
	case LCP_TERM_ACK:
		break;
	case LCP_CODE_REJECT:
		break;
	case LCP_PROT_REJECT:
		break;
	case LCP_ECHO_REQUEST:
		break;
	case LCP_ECHO_REPLY:
		break;
	case LCP_DISCARD:
		break;
	default:
		/* ignore */
		break;
	}

	return 0;
}

struct ipcp_header {
	uint8_t   code;
#define IPCP_CONF_REQUEST    1
#define IPCP_CONF_ACK        2
#define IPCP_CONF_NAK        3
#define IPCP_CONF_REJECT     4
#define IPCP_TERM_REQUEST    5
#define IPCP_TERM_ACK        6
#define IPCP_CODE_REJECT     7
	uint8_t   id;
	uint16_t length;
};

#define IPCP_COPT_ADDRESSES      1
#define IPCP_COPT_COMPRESS       2
#define IPCP_COPT_ADDRESS        3
#define IPCP_COPT_PRIMARY_DNS    129
#define IPCP_COPT_SECONDARY_DNS  131
const char *ipcp_valid_options[256] = {
	[0] = "",
	[1] = "IPCP Option addresses",
	[2] = "IPCP Option compress",
	[3] = "IPCP Option address",
	[129] = "IPCP Option primary dns",
	[131] = "IPCP Option secondary dns",
};

const char *ipcp_code_name[] = {
	"",
	"IPCP Configure-Request",
	"IPCP Configure-Ack",
	"IPCP Configure-Nak",
	"IPCP Configure-Reject",
	"IPCP Terminate-Request",
	"IPCP Terminate-Ack",
	"IPCP Code-Reject",
};

int nroutes = 0;
char **routes = NULL;

uint32_t ip_address = 0;
uint32_t peer_address = 0;
uint32_t primary_dns = 0;
uint32_t secondary_dns = 0;

int ipcp_add_route(struct tunnel *tunnel, uint32_t dst, uint32_t mask, uint32_t gw)
{
	int ret = 0;
	struct rtentry rt;
	struct sockaddr_in *sin = NULL;

	memset(&rt, 0, sizeof(rt));
	rt.rt_dev = tunnel->tun_iface;
	rt.rt_flags = RTF_GATEWAY;

	sin = (struct sockaddr_in *)&rt.rt_dst;
	sin->sin_family = AF_INET;
	sin->sin_port = 0;
	sin->sin_addr.s_addr = dst & htonl(mask);

	sin = (struct sockaddr_in *)&rt.rt_gateway;
	sin->sin_family = AF_INET;
	sin->sin_port = 0;
	sin->sin_addr.s_addr = gw;

	sin = (struct sockaddr_in *)&rt.rt_genmask;
	sin->sin_family = AF_INET;
	sin->sin_port = 0;
	sin->sin_addr.s_addr = htonl(mask);

	int sd = socket(AF_INET, SOCK_DGRAM, 0);
	ret = ioctl(sd, SIOCADDRT, &rt);
	if (ret == 0) {
		log_debug("route add success\n");
	} else {
		log_error("route add failed %d: %s\n", errno, strerror(errno));
	}
	close(sd);

	return ret;
}
int ipcp_option_send(struct tunnel *tunnel, int id, int code, struct conf_option_list *optlist, int force)
{
	int ret = -1;
	if (optlist && optlist->head) {
		uint8_t *packet = (uint8_t *)optlist->head;
		struct ipcp_header *header = ((struct ipcp_header *)packet) - 1;
		unsigned short *ppp_type = ((unsigned short *)header) - 1;
		int len = conf_option_length(optlist);
		int hdrlen = sizeof(struct ipcp_header) + sizeof(uint16_t);

		if (len > 0 || force) {
			ssize_t pktsize;
			struct ppp_packet *packet = NULL;

			*ppp_type = htons(PPP_IPCP);
			header->code = code;
			header->id = id ? id : lcp_id ++;
			header->length = htons(len + sizeof(*header));
			log_debug("send ipcp %d\n", len);

			pktsize = hdrlen + len;
			packet = malloc(sizeof(*packet) + 6 + pktsize);
			if (packet == NULL) {
				goto out;
			}
			packet->len = pktsize;
			memcpy(pkt_data(packet), ppp_type, pktsize);

			log_debug("%s ---> gateway (%lu bytes)\n", PPP_DAEMON,
				  packet->len);
#if HAVE_USR_SBIN_PPPD
			log_packet("pppd:   ", packet->len, pkt_data(packet));
#else
			log_packet("ppp:   ", packet->len, pkt_data(packet));
#endif
			pool_push(&tunnel->pty_to_ssl_pool, packet);
		}
		ret = 0;
	}

out:
	return ret;
}
int ipcp_packet(struct tunnel *tunnel, void *packet, int len)
{
	int ret = 0;
	struct ipcp_header *header = packet;

	log_debug("packet %s\n", ipcp_code_name[header->code]);
	switch (header->code) {
	case IPCP_CONF_REQUEST:
	{
		int olen = ntohs(header->length);
		struct conf_option *co = NULL;
		struct conf_option_list ack;
		struct conf_option_list nack;
		struct conf_option_list reject;
		struct conf_option_list request;
		conf_option_init(&ack);
		conf_option_init(&nack);
		conf_option_init(&reject);
		conf_option_init(&request);
		olen -= sizeof(struct ipcp_header);
		co = (struct conf_option *)(header + 1);
		while (olen > 0) {
			char buff[128];
			char *p = buff;
			p += sprintf(p, "option %s: ", ipcp_valid_options[co->type]);
			switch (co->type) {
			case IPCP_COPT_ADDRESSES:
				p += sprintf(p, "%x", ntohl(*(uint32_t *)co_data(co)));
				conf_option_encode(&ack, co->type, co->length, co_data(co));
				break;
			case IPCP_COPT_COMPRESS:
				conf_option_encode(&ack, co->type, co->length, co_data(co));
				break;
			case IPCP_COPT_ADDRESS:
				p += sprintf(p, "%x", ntohl(*(uint32_t *)co_data(co)));
				conf_option_encode(&ack, co->type, co->length, co_data(co));
				peer_address = *(uint32_t *)co_data(co);
				break;
			default:
				break;
			}
			log_debug("%s\n", buff);
			olen -= co->length;
			co = (struct conf_option *)((uint8_t *)co + co->length);
		}
		if (header->code == IPCP_CONF_REQUEST) {
			int ret = -1;
			ret = ipcp_option_send(tunnel, header->id, IPCP_CONF_ACK, &ack, 0);
			if (ret < 0) {
				log_debug("send conf_ack failed %d: %s\n", errno, strerror(errno));
				exit(1);
			}
			ret = ipcp_option_send(tunnel, header->id, IPCP_CONF_NAK, &nack, 0);
			if (ret < 0) {
				log_debug("send conf_ack failed %d: %s\n", errno, strerror(errno));
				exit(1);
			}
			ret = ipcp_option_send(tunnel, header->id, IPCP_CONF_REJECT, &reject, 0);
			if (ret < 0) {
				log_debug("send conf_ack failed %d: %s\n", errno, strerror(errno));
				exit(1);
			}

			do {
				uint32_t compress = htonl(0x002d0f01);
				conf_option_encode(&request, IPCP_COPT_ADDRESS, 6, &ip_address);
				conf_option_encode(&request, IPCP_COPT_COMPRESS, 6, &compress);
				// conf_option_encode(&request, IPCP_COPT_PRIMARY_DNS, 6, &primary_dns);
				// conf_option_encode(&request, IPCP_COPT_SECONDARY_DNS, 6, &secondary_dns);
				ret = ipcp_option_send(tunnel, 0, IPCP_CONF_REQUEST, &request, 0);
				if (ret < 0) {
					log_debug("send conf_ack failed %d: %s\n", errno, strerror(errno));
					exit(1);
				}
			} while (0);
		}
		conf_option_free(&ack);
		conf_option_free(&nack);
		conf_option_free(&reject);
		conf_option_free(&request);

		break;
	}
	case IPCP_CONF_ACK:
	{
		int olen = ntohs(header->length);
		struct conf_option *co = NULL;
		olen -= sizeof(struct lcp_header);
		co = (struct conf_option *)(header + 1);
		while (olen > 0) {
			char buff[128];
			char *p = buff;
			p += sprintf(p, "option %s: ", ipcp_valid_options[co->type]);
			switch (co->type) {
			case IPCP_COPT_ADDRESSES:
				p += sprintf(p, "%x", ntohl(*(uint32_t *)co_data(co)));
				break;
			case IPCP_COPT_COMPRESS:
				break;
			case IPCP_COPT_ADDRESS:
				p += sprintf(p, "%x", ntohl(*(uint32_t *)co_data(co)));
				ip_address = *(uint32_t *)co_data(co);
				break;
			case IPCP_COPT_PRIMARY_DNS:
				p += sprintf(p, "%x", ntohl(*(uint32_t *)co_data(co)));
				primary_dns = *(uint32_t *)co_data(co);
				break;
			case IPCP_COPT_SECONDARY_DNS:
				p += sprintf(p, "%x", ntohl(*(uint32_t *)co_data(co)));
				secondary_dns = *(uint32_t *)co_data(co);
				break;
			default:
				break;
			}
			log_debug("%s\n", buff);
			olen -= co->length;
			co = (struct conf_option *)((uint8_t *)co + co->length);
		}

		int tun_ifup(char *ifname, uint32_t ip_addr, uint32_t peer_addr);
		tun_ifup(tunnel->tun_iface, ip_address, peer_address);
		ipv4_set_tunnel_routes(tunnel);
		break;
	}
	case IPCP_CONF_NAK:
	{
		int send_request = 0;
		int olen = ntohs(header->length);
		struct conf_option *co = NULL;
		olen -= sizeof(struct lcp_header);
		co = (struct conf_option *)(header + 1);
		while (olen > 0) {
			char buff[128];
			char *p = buff;
			p += sprintf(p, "option %s: ", ipcp_valid_options[co->type]);
			switch (co->type) {
			case IPCP_COPT_ADDRESSES:
				p += sprintf(p, "%x", ntohl(*(uint32_t *)co_data(co)));
				break;
			case IPCP_COPT_COMPRESS:
				break;
			case IPCP_COPT_ADDRESS:
				p += sprintf(p, "%x", ntohl(*(uint32_t *)co_data(co)));
				if (ip_address != *(uint32_t *)co_data(co)) {
					ip_address = *(uint32_t *)co_data(co);
					send_request = 1;
				}
				break;
			case IPCP_COPT_PRIMARY_DNS:
				p += sprintf(p, "%x", ntohl(*(uint32_t *)co_data(co)));
				if (primary_dns != *(uint32_t *)co_data(co)) {
					primary_dns = *(uint32_t *)co_data(co);
					send_request = 1;
				}
				break;
			case IPCP_COPT_SECONDARY_DNS:
				p += sprintf(p, "%x", ntohl(*(uint32_t *)co_data(co)));
				if (secondary_dns != *(uint32_t *)co_data(co)) {
					secondary_dns = *(uint32_t *)co_data(co);
					send_request = 1;
				}
				break;
			default:
				break;
			}
			log_debug("%s\n", buff);
			olen -= co->length;
			co = (struct conf_option *)((uint8_t *)co + co->length);
		}

		if (send_request) {
			struct conf_option_list request;
			conf_option_init(&request);
			conf_option_encode(&request, IPCP_COPT_ADDRESS, 6, &ip_address);
			// conf_option_encode(&request, IPCP_COPT_PRIMARY_DNS, 6, &primary_dns);
			// conf_option_encode(&request, IPCP_COPT_SECONDARY_DNS, 6, &secondary_dns);
			ret = ipcp_option_send(tunnel, 0, IPCP_CONF_REQUEST, &request, 0);
			if (ret < 0) {
				log_debug("send conf_ack failed %d: %s\n", errno, strerror(errno));
				exit(1);
			}
			conf_option_free(&request);
		}
		break;
	}
	case IPCP_CONF_REJECT:
	{
		int olen = ntohs(header->length);
		struct conf_option *co = NULL;
		olen -= sizeof(struct lcp_header);
		co = (struct conf_option *)(header + 1);
		while (olen > 0) {
			char buff[128];
			char *p = buff;
			p += sprintf(p, "option %s: ", ipcp_valid_options[co->type]);
			switch (co->type) {
			case IPCP_COPT_ADDRESSES:
				p += sprintf(p, "%x", ntohl(*(uint32_t *)co_data(co)));
				break;
			case IPCP_COPT_COMPRESS:
				break;
			case IPCP_COPT_ADDRESS:
				p += sprintf(p, "%x", ntohl(*(uint32_t *)co_data(co)));
				break;
			case IPCP_COPT_PRIMARY_DNS:
				p += sprintf(p, "%x", ntohl(*(uint32_t *)co_data(co)));
				break;
			case IPCP_COPT_SECONDARY_DNS:
				p += sprintf(p, "%x", ntohl(*(uint32_t *)co_data(co)));
				break;
			default:
				break;
			}
			log_debug("%s\n", buff);
			olen -= co->length;
			co = (struct conf_option *)((uint8_t *)co + co->length);
		}

		do {
			struct conf_option_list request;
			conf_option_init(&request);
			conf_option_encode(&request, IPCP_COPT_ADDRESS, 6, &ip_address);
			// conf_option_encode(&request, IPCP_COPT_PRIMARY_DNS, 6, &primary_dns);
			// conf_option_encode(&request, IPCP_COPT_SECONDARY_DNS, 6, &secondary_dns);
			ret = ipcp_option_send(tunnel, 0, IPCP_CONF_REQUEST, &request, 0);
			if (ret < 0) {
				log_debug("send conf_ack failed %d: %s\n", errno, strerror(errno));
				exit(1);
			}
		} while (0);
		break;
	}
	case IPCP_TERM_REQUEST:
		break;
	case IPCP_TERM_ACK:
		break;
	case IPCP_CODE_REJECT:
		break;
	default:
		/* ignore */
		break;
	}

	return 0;
}


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

	log_debug("%s thread\n", __func__);

	if (tunnel->use_tun) {
		switch (tunnel->tun_state) {
		case TUN_PPP_LCP:
			conf_request(tunnel);
			break;
		case TUN_PPP_IPCP:
		case TUN_PPP_SESSION:
			break;
		}
	}

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
			log_warn("read returned %ld\n", n);
			break;
		} else if (first_time) {
			// pppd did talk, now we can write to it if we want
			SEM_POST(&sem_pppd_ready);
			first_time = 0;
		}
		if (tunnel->use_tun) {
			ssize_t pktsize;
			struct ppp_packet *packet = NULL;

			pktsize = n + 2;
			packet = malloc(sizeof(*packet) + 6 + pktsize);
			if (packet == NULL) {
				goto exit;
			}
			packet->len = pktsize;
			pkt_data(packet)[0] = 0x00;
			pkt_data(packet)[1] = 0x21;
			memcpy(pkt_data(packet) + 2, buf, n);

			log_debug("%s ---> gateway (%lu bytes)\n", PPP_DAEMON,
				  packet->len);
#if HAVE_USR_SBIN_PPPD
			log_packet("pppd:   ", packet->len, pkt_data(packet));
#else
			log_packet("ppp:   ", packet->len, pkt_data(packet));
#endif
			pool_push(&tunnel->pty_to_ssl_pool, packet);
			continue;
		}

		off_w += n;

		// We have data in the buffer, there may be zero, one or many
		// packets inside.
		off_r = 0;
		while (1) {
			ssize_t frm_len, pktsize;
			struct ppp_packet *packet, *repacket;

			frm_len = hdlc_find_frame(buf, off_w, &off_r);
			if (frm_len == ERR_HDLC_NO_FRAME_FOUND)
				break;

			pktsize = estimated_decoded_size(frm_len);
			packet = malloc(sizeof(*packet) + 6 + pktsize);
			if (packet == NULL) {
				log_error("malloc: %s\n", strerror(errno));
				break;
			}

			pktsize = hdlc_decode(&buf[off_r], frm_len,
			                      pkt_data(packet), pktsize);
			if (pktsize < 0) {
				log_error("Failed to decode PPP packet from HDLC frame (%s).\n",
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

			log_debug("%s ---> gateway (%lu bytes)\n", PPP_DAEMON,
			          packet->len);
#if HAVE_USR_SBIN_PPPD
			log_packet("pppd:   ", packet->len, pkt_data(packet));
#else
			log_packet("ppp:   ", packet->len, pkt_data(packet));
#endif
			pool_push(&tunnel->pty_to_ssl_pool, packet);

			off_r += frm_len;
		}

		// Do not discard remaining data
		if (off_r > 0 && off_r < off_w)
			memmove(buf, &buf[off_r], off_w - off_r);
		off_w = off_w - off_r;
	}

exit:
	// Send message to main thread to stop other threads
	SEM_POST(&sem_stop_io);
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
	SEM_WAIT(&sem_pppd_ready);

	log_debug("%s thread\n", __func__);

	while (1) {
		struct ppp_packet *packet;
		ssize_t hdlc_bufsize, len, n, written;
		uint8_t *hdlc_buffer;

		// This waits until a packet has arrived from the gateway
		packet = pool_pop(&tunnel->ssl_to_pty_pool);

		if (tunnel->use_tun) {
			void *pkt_type = pkt_data(packet);

			hdlc_bufsize = len = packet->len;
			switch (ntohs(*(uint16_t *)pkt_type)) {
			case PPP_LCP:
				lcp_packet(tunnel, pkt_data(packet) + 2, len - 2);
				continue;
			case PPP_IPCP:
				ipcp_packet(tunnel, pkt_data(packet) + 2, len - 2);
				continue;
			case PPP_IP:
			case PPP_IPV6:
				break;
			default:
				goto out_free_packet;
			}

			hdlc_buffer = malloc(packet->len);
			if (hdlc_buffer == NULL) {
				log_error("malloc: %s\n", strerror(errno));
				break;
			}

			memcpy(hdlc_buffer, pkt_data(packet) + 2, packet->len - 2);
		} else {
			hdlc_bufsize = estimated_encoded_size(packet->len);
			hdlc_buffer = malloc(hdlc_bufsize);
			if (hdlc_buffer == NULL) {
				log_error("malloc: %s\n", strerror(errno));
				break;
			}
			len = hdlc_encode(hdlc_buffer, hdlc_bufsize,
					  pkt_data(packet), packet->len);
			if (len < 0) {
				log_error("Failed to encode PPP packet into HDLC frame.\n");
				goto err_free_buf;
			}
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
			// retry on repeatable failure
			if (n == -1) {
				if (errno == EAGAIN) {
					continue;
				} else {
					log_error("write: %s\n", strerror(errno));
					goto err_free_buf;
				}
			}
			written += n;
		}

		free(hdlc_buffer);
out_free_packet:
		free(packet);
		continue;
err_free_buf:
		free(hdlc_buffer);
		free(packet);
		break;
	}

	// Send message to main thread to stop other threads
	SEM_POST(&sem_stop_io);
	return NULL;
}

#define packet_is_ip_plus_dns(packet) \
	((packet)->len >= 12 \
	 && pkt_data(packet)[0] == 0x80 \
	 && pkt_data(packet)[1] == 0x21 \
	 && pkt_data(packet)[2] == 0x02 \
	 && pkt_data(packet)[6] == 0x03)

#define packet_is_end_negociation(packet) \
	(((packet)->len == 6 \
	  && pkt_data(packet)[0] == 0x80 \
	  && pkt_data(packet)[1] == 0x21 \
	  && pkt_data(packet)[2] == 0x01 \
	  && pkt_data(packet)[4] == 0x00 \
	  && pkt_data(packet)[5] == 0x04) || \
	 ((packet)->len >= 12 \
	  && pkt_data(packet)[0] == 0x80 \
	  && pkt_data(packet)[1] == 0x21 \
	  && pkt_data(packet)[2] == 0x02))

static inline void set_tunnel_ips(struct tunnel *tunnel,
                                  struct ppp_packet *packet)
{
	memcpy(&tunnel->ipv4.ip_addr.s_addr, &pkt_data(packet)[8],
	       sizeof(uint32_t));
	if (packet->len >= 18 && pkt_data(packet)[12] == 0x81
	    && tunnel->config->pppd_use_peerdns) {
		memcpy(&tunnel->ipv4.ns1_addr.s_addr, &pkt_data(packet)[14],
		       sizeof(uint32_t));
	}
	if (packet->len >= 24 && pkt_data(packet)[18] == 0x83
	    && tunnel->config->pppd_use_peerdns) {
		memcpy(&tunnel->ipv4.ns2_addr.s_addr, &pkt_data(packet)[20],
		       sizeof(uint32_t));
	}
}

#define printable_char(c) \
	(c == '\t' || c == '\n' || (c >= ' ' && c <= '~'))

static void debug_bad_packet(struct tunnel *tunnel, uint8_t *header)
{
	uint8_t buffer[256];
	int size;

	memcpy(buffer, header, 6 * sizeof(uint8_t));

	size = safe_ssl_read(tunnel->ssl_handle, &buffer[6], 256 - 6);
	if (size < 0)
		return;
	size += 6;

	// Print hex dump
	do_log_packet("  (hex) ", size, buffer);

	// then print the raw string, after escaping non-displayable chars
	for (int i = 0; i < size; i++)
		if (!printable_char((char) buffer[i]))
			buffer[i] = '.';
	buffer[size] = buffer[256 - 1] = '\0';

	printf("  (raw) %s\n", (const char *) buffer);
}

/*
 * Thread to read bytes from the TLS socket, convert them to ppp packets and add
 * them to the 'ssl_to_pty' pool.
 */
static void *ssl_read(void *arg)
{
	struct tunnel *tunnel = (struct tunnel *) arg;
	//uint8_t buf[PKT_BUF_SZ];

	log_debug("%s thread\n", __func__);

	while (1) {
		struct ppp_packet *packet;
		int ret;
		uint8_t header[6];
		static const char http_header[6] = "HTTP/1";
		uint16_t total, magic, size;

		ret = safe_ssl_read_all(tunnel->ssl_handle, header, 6);
		if (ret < 0) {
			log_debug("Error reading from TLS connection (%s).\n",
			          err_ssl_str(ret));
			break;
		}

		if (memcmp(header, http_header, 6) == 0) {
			/*
			 * When the TLS-VPN portal has not been set up to allow
			 * tunnel mode for VPN clients, while it allows web mode
			 * for web browsers, it returns an HTTP error instead of
			 * a PPP packet:
			 * HTTP/1.1 403 Forbidden
			 */
			log_error("Could not authenticate to the gateway. Please make sure tunnel mode is allowed by the gateway, check the realm, etc.\n");
			break;
		}

		total = (uint16_t)(header[0]) << 8 | header[1];
		magic = (uint16_t)(header[2]) << 8 | header[3];
		size = (uint16_t)(header[4]) << 8 | header[5];
		if (magic != 0x5050 || total < 7 || total - 6 != size) {
			log_error("Received bad header from gateway:\n");
			debug_bad_packet(tunnel, header);
			break;
		}

		packet = malloc(sizeof(struct ppp_packet) + 6 + size);
		if (packet == NULL) {
			log_error("malloc: %s\n", strerror(errno));
			break;
		}
		memcpy(pkt_header(packet), header, 6);
		packet->len = size;

		ret = safe_ssl_read_all(tunnel->ssl_handle, pkt_data(packet),
		                        size);
		if (ret < 0) {
			log_debug("Error reading from TLS connection (%s).\n",
			          err_ssl_str(ret));
			free(packet);
			break;
		}

		log_debug("gateway ---> %s (%lu bytes)\n", PPP_DAEMON, packet->len);
		log_packet("gtw:    ", packet->len, pkt_data(packet));
		pool_push(&tunnel->ssl_to_pty_pool, packet);

		if (tunnel->state == STATE_CONNECTING) {
			if (packet_is_ip_plus_dns(packet)) {
				char line[ARRAY_SIZE("[xxx.xxx.xxx.xxx], ns [xxx.xxx.xxx.xxx, xxx.xxx.xxx.xxx], ns_suffix []") + MAX_DOMAIN_LENGTH];

				set_tunnel_ips(tunnel, packet);

				if (tunnel->use_tun) {
					int tun_ifup(char *ifname, uint32_t ip_addr, uint32_t peer_addr);
					tun_ifup(tunnel->tun_iface, tunnel->ipv4.ip_addr.s_addr, 0);
				}
				strcpy(line, "[");
				strncat(line, inet_ntoa(tunnel->ipv4.ip_addr), 15);
				strcat(line, "], ns [");
				strncat(line, inet_ntoa(tunnel->ipv4.ns1_addr), 15);
				strcat(line, ", ");
				strncat(line, inet_ntoa(tunnel->ipv4.ns2_addr), 15);
				if (tunnel->ipv4.dns_suffix) {
					strcat(line, "], ns_suffix [");
					strncat(line, tunnel->ipv4.dns_suffix,
					        MAX_DOMAIN_LENGTH);
				}
				strcat(line, "]");
				log_info("Got addresses: %s\n", line);
			}
			if (packet_is_end_negociation(packet)) {
				log_info("Negotiation complete.\n");
				SEM_POST(&sem_if_config);
			}
		}
	}

	// Send message to main thread to stop other threads
	SEM_POST(&sem_stop_io);
	return NULL;
}

/*
 * Thread to pop packets from the 'pty_to_ssl' pool, and write them to the TLS
 * socket.
 */
static void *ssl_write(void *arg)
{
	struct tunnel *tunnel = (struct tunnel *) arg;

	log_debug("%s thread\n", __func__);

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
			log_debug("Error writing to TLS connection (%s).\n",
			          err_ssl_str(ret));
			free(packet);
			break;
		}
		free(packet);
	}

	// Send message to main thread to stop other threads
	SEM_POST(&sem_stop_io);
	return NULL;
}

/*
 * Thread to pop packets from the 'pty_to_ssl' pool, and write them to the TLS
 * socket.
 */
static void *if_config(void *arg)
{
	struct tunnel *tunnel = (struct tunnel *) arg;
	int timeout = 60000000; // one minute

	log_debug("%s thread\n", __func__);

	// Wait for the right moment to configure IP interface
	SEM_WAIT(&sem_if_config);

	while (1) {
		if (ppp_interface_is_up(tunnel)) {
			if (tunnel->on_ppp_if_up != NULL)
				if (tunnel->on_ppp_if_up(tunnel))
					goto error;
			tunnel->state = STATE_UP;
			break;
		} else if (timeout == 0) {
			log_error("Timed out waiting for the ppp interface to be UP.\n");
			break;
		}
		log_debug("%s: not ready yet...\n", __func__);
		timeout -= 200000;
		usleep(200000);
	}
	if (tunnel->state != STATE_UP)
		goto error;

	return NULL;
error:
	// Send message to main thread to stop other threads
	SEM_POST(&sem_stop_io);
	return NULL;
}

static void sig_handler(int signo)
{
	sig_received = signo;
	if (signo == SIGINT || signo == SIGTERM)
		SEM_POST(&sem_stop_io);
}

int io_loop(struct tunnel *tunnel)
{
	int tcp_nodelay_flag = 1;
	int ret = 0;		// keep track of pthread_* return value
	int fatal = 0;		// indicate a fatal error during pthread_* calls

	pthread_t pty_read_thread;
	pthread_t pty_write_thread;
	pthread_t ssl_read_thread;
	pthread_t ssl_write_thread;
	pthread_t if_config_thread;

	SEM_INIT(&sem_pppd_ready, 0, 0);
	SEM_INIT(&sem_if_config, 0, 0);
	SEM_INIT(&sem_stop_io, 0, 0);

	init_ppp_packet_pool(&tunnel->ssl_to_pty_pool);
	init_ppp_packet_pool(&tunnel->pty_to_ssl_pool);

	init_ssl_locks();

	init_hdlc();

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
	if (setsockopt(tunnel->ssl_socket, IPPROTO_TCP, TCP_NODELAY,
	               (const char *) &tcp_nodelay_flag, sizeof(int))) {
		log_error("setsockopt TCP_NODELAY: %s\n", strerror(errno));
		goto err_sockopt;
	}

// on osx this prevents the program from being stopped with ctrl-c
#if !HAVE_MACH_MACH_H
	// Disable SIGINT and SIGTERM for the future spawned threads
	sigset_t sigset, oldset;

	sigemptyset(&sigset);
	sigaddset(&sigset, SIGINT);
	sigaddset(&sigset, SIGTERM);
	pthread_sigmask(SIG_BLOCK, &sigset, &oldset);
#endif

	// Set signal handler
	if (signal(SIGINT, sig_handler) == SIG_ERR ||
	    signal(SIGTERM, sig_handler) == SIG_ERR)
		goto err_signal;

	// Ignore SIGHUP
	if (signal(SIGHUP, SIG_IGN) == SIG_ERR)
		goto err_signal;

	// create all workers, stop on first error and bail out
	ret = pthread_create(&pty_read_thread, NULL, pppd_read, tunnel);
	if (ret != 0) {
		log_debug("Error creating pty_read_thread: %s\n", strerror(ret));
		goto err_thread;
	}

	ret = pthread_create(&pty_write_thread, NULL, pppd_write, tunnel);
	if (ret != 0) {
		log_debug("Error creating pty_write_thread: %s\n", strerror(ret));
		goto err_thread;
	}

	ret = pthread_create(&ssl_read_thread, NULL, ssl_read, tunnel);
	if (ret != 0) {
		log_debug("Error creating ssl_read_thread: %s\n", strerror(ret));
		goto err_thread;
	}

	ret = pthread_create(&ssl_write_thread, NULL, ssl_write, tunnel);
	if (ret != 0) {
		log_debug("Error creating ssl_write_thread: %s\n", strerror(ret));
		goto err_thread;
	}

	ret = pthread_create(&if_config_thread, NULL, if_config, tunnel);
	if (ret != 0) {
		log_debug("Error creating if_config_thread: %s\n", strerror(ret));
		goto err_thread;
	}

#if !HAVE_MACH_MACH_H
	// Restore the signal for the main thread
	pthread_sigmask(SIG_SETMASK, &oldset, NULL);
#endif

	// Wait for one of the thread to ask termination
	SEM_WAIT(&sem_stop_io);

	log_info("Cancelling threads...\n");
	// no goto err_thread here, try to cancel all threads
	ret = pthread_cancel(if_config_thread);
	if (ret != 0)
		log_debug("Error canceling if_config_thread: %s\n", strerror(ret));

	ret = pthread_cancel(ssl_write_thread);
	if (ret != 0)
		log_debug("Error canceling ssl_write_thread: %s\n", strerror(ret));

	ret = pthread_cancel(ssl_read_thread);
	if (ret != 0)
		log_debug("Error canceling safe_ssl_read_thread: %s\n", strerror(ret));

	ret = pthread_cancel(pty_write_thread);
	if (ret != 0)
		log_debug("Error canceling pty_write_thread: %s\n", strerror(ret));

	ret = pthread_cancel(pty_read_thread);
	if (ret != 0)
		log_debug("Error canceling pty_read_thread: %s\n", strerror(ret));

	log_info("Cleanup, joining threads...\n");
	// failure to clean is a possible zombie thread, consider it fatal
	ret = pthread_join(if_config_thread, NULL);
	if (ret != 0) {
		log_debug("Error joining if_config_thread: %s\n", strerror(ret));
		fatal = 1;
	}

	ret = pthread_join(ssl_write_thread, NULL);
	if (ret != 0) {
		log_debug("Error joining ssl_write_thread: %s\n", strerror(ret));
		fatal = 1;
	}

	ret = pthread_join(ssl_read_thread, NULL);
	if (ret != 0) {
		log_debug("Error joining ssl_read_thread: %s\n", strerror(ret));
		fatal = 1;
	}

	ret = pthread_join(pty_write_thread, NULL);
	if (ret != 0) {
		log_debug("Error joining pty_write_thread: %s\n", strerror(ret));
		fatal = 1;
	}

	ret = pthread_join(pty_read_thread, NULL);
	if (ret != 0) {
		log_debug("Error joining pty_read_thread: %s\n", strerror(ret));
		fatal = 1;
	}

	destroy_ssl_locks();

	destroy_ppp_packet_pool(&tunnel->pty_to_ssl_pool);
	destroy_ppp_packet_pool(&tunnel->ssl_to_pty_pool);

	SEM_DESTROY(&sem_stop_io);
	SEM_DESTROY(&sem_if_config);
	SEM_DESTROY(&sem_pppd_ready);

	// should we have detected a fatal error
	if (fatal)
		goto err_thread;

	return 0;

err_thread:
err_signal:
err_sockopt:
	return 1;
}
