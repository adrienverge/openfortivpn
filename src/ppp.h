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
 */

#ifndef OPENFORTIVPN_PPP_H
#define OPENFORTIVPN_PPP_H

#include <stdint.h>
#include <stddef.h>

/* PPP Protocol IDs */
#define PPP_PROTO_LCP   0xc021
#define PPP_PROTO_IPCP  0x8021
#define PPP_PROTO_IP    0x0021

/* PPP Control Codes (RFC 1661) */
#define PPP_CODE_CONF_REQ     1
#define PPP_CODE_CONF_ACK     2
#define PPP_CODE_CONF_NAK     3
#define PPP_CODE_CONF_REJ     4
#define PPP_CODE_TERM_REQ     5
#define PPP_CODE_TERM_ACK     6
#define PPP_CODE_CODE_REJ     7
#define PPP_CODE_PROTO_REJ    8
#define PPP_CODE_ECHO_REQ     9
#define PPP_CODE_ECHO_REP    10

/* LCP Option Types (RFC 1661) */
#define LCP_OPT_MRU          1
#define LCP_OPT_ACCM         2
#define LCP_OPT_AUTH          3
#define LCP_OPT_MAGIC        5
#define LCP_OPT_PFC          7   /* Protocol-Field-Compression */
#define LCP_OPT_ACFC         8   /* Address-and-Control-Field-Compression */

/* IPCP Option Types (RFC 1332) */
#define IPCP_OPT_IP_ADDR     3
#define IPCP_OPT_DNS_PRI   129   /* 0x81 - Primary DNS */
#define IPCP_OPT_DNS_SEC   131   /* 0x83 - Secondary DNS */

/* PPP State Machine States */
enum ppp_state {
	PPP_STATE_INITIAL,
	PPP_STATE_LCP_SENT,
	PPP_STATE_LCP_OPEN,
	PPP_STATE_IPCP_SENT,
	PPP_STATE_IPCP_OPEN,
	PPP_STATE_TERMINATED
};

/* Return codes for ppp_process_incoming */
#define PPP_RET_OK           0   /* Processed, may have response */
#define PPP_RET_IP_PACKET    1   /* Extracted an IP data packet */
#define PPP_RET_NEGOTIATE    2   /* Negotiation complete (IPCP open) */
#define PPP_RET_TERMINATED  -1   /* Peer requested termination */
#define PPP_RET_ERROR       -2   /* Protocol error */

struct ppp_context {
	enum ppp_state state;
	uint8_t lcp_identifier;      /* Sequence counter for LCP */
	uint8_t ipcp_identifier;     /* Sequence counter for IPCP */
	uint16_t mru;                /* Maximum Receive Unit */
	uint32_t asyncmap;           /* Async-Control-Character-Map */
	uint32_t magic_number;       /* Magic number for loop detection */
	uint32_t local_ip;           /* Assigned local IP (network order) */
	uint32_t peer_ip;            /* Peer IP (network order) */
	uint32_t dns_primary;        /* Primary DNS (network order) */
	uint32_t dns_secondary;      /* Secondary DNS (network order) */
	int negotiation_complete;    /* Non-zero when IPCP is open */
};

/*
 * Initialize a PPP context with default parameters matching
 * the existing pppd configuration in tunnel.c:
 *   MRU=1354, ACCM=0, no auth, no compression.
 */
void ppp_init(struct ppp_context *ctx);

/*
 * Generate the initial LCP Config-Request to begin negotiation.
 *
 * @param ctx       PPP context
 * @param out_data  Output buffer (caller must free)
 * @param out_len   Length of output data
 * @return          0 on success, -1 on error
 *
 * The output is a raw PPP packet (2-byte protocol + payload),
 * suitable for wrapping in the Fortinet 6-byte TLS header.
 */
int ppp_start_negotiation(struct ppp_context *ctx,
                          uint8_t **out_data, size_t *out_len);

/*
 * Process an incoming PPP packet from the gateway.
 *
 * @param ctx         PPP context
 * @param ppp_data    Incoming PPP packet data (protocol field + payload)
 * @param ppp_len     Length of incoming data
 * @param response    Output: response packet to send back (caller must free, may be NULL)
 * @param resp_len    Output: length of response
 * @param ip_payload  Output: extracted IP payload for IP data packets (caller must free)
 * @param ip_len      Output: length of IP payload
 * @return            PPP_RET_* code
 *
 * During negotiation (LCP/IPCP), response packets are generated.
 * After negotiation completes, IP data packets (protocol 0x0021) are
 * extracted and returned via ip_payload.
 */
int ppp_process_incoming(struct ppp_context *ctx,
                         const uint8_t *ppp_data, size_t ppp_len,
                         uint8_t **response, size_t *resp_len,
                         uint8_t **ip_payload, size_t *ip_len);

/*
 * Wrap an outgoing IP packet in PPP framing (protocol 0x0021).
 *
 * @param ip_data   Raw IP packet data
 * @param ip_len    Length of IP packet
 * @param ppp_data  Output: PPP-encapsulated packet (caller must free)
 * @param ppp_len   Output: length of PPP packet
 * @return          0 on success, -1 on error
 */
int ppp_encapsulate_ip(const uint8_t *ip_data, size_t ip_len,
                       uint8_t **ppp_data, size_t *ppp_len);

#endif /* OPENFORTIVPN_PPP_H */
