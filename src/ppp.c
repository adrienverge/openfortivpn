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

#include "ppp.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>

/*
 * Build a PPP control packet with protocol, code, identifier, and options.
 * Allocates output buffer; caller must free.
 */
static int build_control_packet(uint16_t protocol, uint8_t code, uint8_t id,
                                const uint8_t *options, size_t opt_len,
                                uint8_t **out, size_t *out_len)
{
	/* PPP packet: 2 bytes protocol + 1 code + 1 id + 2 length + options */
	size_t pkt_len = 2 + 4 + opt_len;
	uint16_t ctrl_len = (uint16_t)(4 + opt_len);
	uint8_t *pkt;

	pkt = malloc(pkt_len);
	if (!pkt)
		return -1;

	pkt[0] = (uint8_t)(protocol >> 8);
	pkt[1] = (uint8_t)(protocol & 0xff);
	pkt[2] = code;
	pkt[3] = id;
	pkt[4] = (uint8_t)(ctrl_len >> 8);
	pkt[5] = (uint8_t)(ctrl_len & 0xff);

	if (options && opt_len > 0)
		memcpy(&pkt[6], options, opt_len);

	*out = pkt;
	*out_len = pkt_len;
	return 0;
}

/*
 * Build an LCP Echo-Reply from an Echo-Request.
 * Echo-Reply has our magic number at bytes 6-9 of the control payload.
 */
static int build_echo_reply(uint8_t id, uint32_t magic,
                            uint8_t **out, size_t *out_len)
{
	/* protocol(2) + code(1) + id(1) + length(2) + magic(4) = 10 */
	size_t pkt_len = 10;
	uint8_t *pkt;

	pkt = malloc(pkt_len);
	if (!pkt)
		return -1;

	pkt[0] = (uint8_t)(PPP_PROTO_LCP >> 8);
	pkt[1] = (uint8_t)(PPP_PROTO_LCP & 0xff);
	pkt[2] = PPP_CODE_ECHO_REP;
	pkt[3] = id;
	pkt[4] = 0;
	pkt[5] = 8; /* length = 4 (header) + 4 (magic) */
	pkt[6] = (uint8_t)(magic >> 24);
	pkt[7] = (uint8_t)(magic >> 16);
	pkt[8] = (uint8_t)(magic >> 8);
	pkt[9] = (uint8_t)(magic);

	*out = pkt;
	*out_len = pkt_len;
	return 0;
}

void ppp_init(struct ppp_context *ctx)
{
	memset(ctx, 0, sizeof(*ctx));
	ctx->state = PPP_STATE_INITIAL;
	ctx->lcp_identifier = 1;
	ctx->ipcp_identifier = 1;
	ctx->mru = 1354;      /* Matches tunnel.c pppd args */
	ctx->asyncmap = 0;     /* default-asyncmap */
	ctx->magic_number = (uint32_t)time(NULL) ^ 0xDEADBEEF;
	ctx->negotiation_complete = 0;
}

int ppp_start_negotiation(struct ppp_context *ctx,
                          uint8_t **out_data, size_t *out_len)
{
	/*
	 * LCP Config-Request options:
	 * - MRU (type 1, len 4): 1354
	 * - ACCM (type 2, len 6): 0x00000000
	 * - Magic Number (type 5, len 6): random
	 */
	uint8_t options[16];
	size_t off = 0;

	/* MRU option */
	options[off++] = LCP_OPT_MRU;
	options[off++] = 4;
	options[off++] = (uint8_t)(ctx->mru >> 8);
	options[off++] = (uint8_t)(ctx->mru & 0xff);

	/* ACCM option */
	options[off++] = LCP_OPT_ACCM;
	options[off++] = 6;
	options[off++] = 0;
	options[off++] = 0;
	options[off++] = 0;
	options[off++] = 0;

	/* Magic Number option */
	options[off++] = LCP_OPT_MAGIC;
	options[off++] = 6;
	options[off++] = (uint8_t)(ctx->magic_number >> 24);
	options[off++] = (uint8_t)(ctx->magic_number >> 16);
	options[off++] = (uint8_t)(ctx->magic_number >> 8);
	options[off++] = (uint8_t)(ctx->magic_number);

	ctx->state = PPP_STATE_LCP_SENT;

	return build_control_packet(PPP_PROTO_LCP, PPP_CODE_CONF_REQ,
	                            ctx->lcp_identifier++, options, off,
	                            out_data, out_len);
}

/*
 * Handle an incoming LCP packet.
 * Returns 0 on success, sets *response if a reply is needed.
 */
static int handle_lcp(struct ppp_context *ctx,
                      const uint8_t *payload, size_t payload_len,
                      uint8_t **response, size_t *resp_len)
{
	uint8_t code, id;
	uint16_t pkt_length;

	*response = NULL;
	*resp_len = 0;

	if (payload_len < 4)
		return PPP_RET_ERROR;

	code = payload[0];
	id = payload[1];
	pkt_length = ((uint16_t)payload[2] << 8) | payload[3];

	if (pkt_length > payload_len)
		return PPP_RET_ERROR;

	switch (code) {
	case PPP_CODE_CONF_REQ: {
		/*
		 * Peer's Config-Request. We accept most options.
		 * Reject PFC (7) and ACFC (8) since we don't use compression,
		 * and reject AUTH (3) since auth is done at HTTP level.
		 */
		const uint8_t *opts = &payload[4];
		size_t opts_len = pkt_length - 4;
		uint8_t *reject_buf = NULL;
		size_t reject_len = 0;
		size_t pos = 0;

		/* First pass: identify options to reject */
		while (pos < opts_len) {
			uint8_t opt_type, opt_len_val;

			if (pos + 2 > opts_len)
				break;
			opt_type = opts[pos];
			opt_len_val = opts[pos + 1];
			if (opt_len_val < 2 || pos + opt_len_val > opts_len)
				break;

			if (opt_type == LCP_OPT_AUTH ||
			    opt_type == LCP_OPT_PFC ||
			    opt_type == LCP_OPT_ACFC) {
				/* Add to reject list */
				uint8_t *tmp = realloc(reject_buf,
				                       reject_len + opt_len_val);
				if (!tmp) {
					free(reject_buf);
					return PPP_RET_ERROR;
				}
				reject_buf = tmp;
				memcpy(&reject_buf[reject_len],
				       &opts[pos], opt_len_val);
				reject_len += opt_len_val;
			}
			pos += opt_len_val;
		}

		if (reject_len > 0) {
			/* Send Config-Reject with the unwanted options */
			int ret = build_control_packet(PPP_PROTO_LCP,
			                               PPP_CODE_CONF_REJ, id,
			                               reject_buf, reject_len,
			                               response, resp_len);
			free(reject_buf);
			return ret < 0 ? PPP_RET_ERROR : PPP_RET_OK;
		}
		free(reject_buf);

		/* Accept all options: send Config-Ack with the same options */
		return build_control_packet(PPP_PROTO_LCP,
		                            PPP_CODE_CONF_ACK, id,
		                            opts, opts_len,
		                            response, resp_len) < 0
		       ? PPP_RET_ERROR : PPP_RET_OK;
	}

	case PPP_CODE_CONF_ACK:
		/* Peer accepted our LCP config */
		if (ctx->state == PPP_STATE_LCP_SENT ||
		    ctx->state == PPP_STATE_INITIAL) {
			ctx->state = PPP_STATE_LCP_OPEN;

			/* Now start IPCP negotiation */
			uint8_t ipcp_opts[18];
			size_t off = 0;

			/* IP-Address: request 0.0.0.0 (let peer assign) */
			ipcp_opts[off++] = IPCP_OPT_IP_ADDR;
			ipcp_opts[off++] = 6;
			ipcp_opts[off++] = (uint8_t)(ctx->local_ip >> 24);
			ipcp_opts[off++] = (uint8_t)(ctx->local_ip >> 16);
			ipcp_opts[off++] = (uint8_t)(ctx->local_ip >> 8);
			ipcp_opts[off++] = (uint8_t)(ctx->local_ip);

			/* Primary DNS */
			ipcp_opts[off++] = IPCP_OPT_DNS_PRI;
			ipcp_opts[off++] = 6;
			ipcp_opts[off++] = (uint8_t)(ctx->dns_primary >> 24);
			ipcp_opts[off++] = (uint8_t)(ctx->dns_primary >> 16);
			ipcp_opts[off++] = (uint8_t)(ctx->dns_primary >> 8);
			ipcp_opts[off++] = (uint8_t)(ctx->dns_primary);

			/* Secondary DNS */
			ipcp_opts[off++] = IPCP_OPT_DNS_SEC;
			ipcp_opts[off++] = 6;
			ipcp_opts[off++] = (uint8_t)(ctx->dns_secondary >> 24);
			ipcp_opts[off++] = (uint8_t)(ctx->dns_secondary >> 16);
			ipcp_opts[off++] = (uint8_t)(ctx->dns_secondary >> 8);
			ipcp_opts[off++] = (uint8_t)(ctx->dns_secondary);

			ctx->state = PPP_STATE_IPCP_SENT;

			return build_control_packet(PPP_PROTO_IPCP,
			                            PPP_CODE_CONF_REQ,
			                            ctx->ipcp_identifier++,
			                            ipcp_opts, off,
			                            response, resp_len) < 0
			       ? PPP_RET_ERROR : PPP_RET_OK;
		}
		return PPP_RET_OK;

	case PPP_CODE_CONF_NAK:
		/*
		 * Peer wants us to change some LCP options.
		 * Re-send Config-Request with the nak'd values.
		 */
		return build_control_packet(PPP_PROTO_LCP,
		                            PPP_CODE_CONF_REQ,
		                            ctx->lcp_identifier++,
		                            &payload[4], pkt_length - 4,
		                            response, resp_len) < 0
		       ? PPP_RET_ERROR : PPP_RET_OK;

	case PPP_CODE_CONF_REJ: {
		/*
		 * Peer rejected some of our options. Re-send without them.
		 * For simplicity, send a minimal config with just MRU.
		 */
		uint8_t min_opts[4];

		min_opts[0] = LCP_OPT_MRU;
		min_opts[1] = 4;
		min_opts[2] = (uint8_t)(ctx->mru >> 8);
		min_opts[3] = (uint8_t)(ctx->mru & 0xff);

		return build_control_packet(PPP_PROTO_LCP,
		                            PPP_CODE_CONF_REQ,
		                            ctx->lcp_identifier++,
		                            min_opts, 4,
		                            response, resp_len) < 0
		       ? PPP_RET_ERROR : PPP_RET_OK;
	}

	case PPP_CODE_TERM_REQ:
		/* Peer wants to terminate. Send Term-Ack. */
		ctx->state = PPP_STATE_TERMINATED;
		if (build_control_packet(PPP_PROTO_LCP, PPP_CODE_TERM_ACK,
		                         id, NULL, 0,
		                         response, resp_len) < 0)
			return PPP_RET_ERROR;
		return PPP_RET_TERMINATED;

	case PPP_CODE_TERM_ACK:
		ctx->state = PPP_STATE_TERMINATED;
		return PPP_RET_TERMINATED;

	case PPP_CODE_ECHO_REQ:
		return build_echo_reply(id, ctx->magic_number,
		                        response, resp_len) < 0
		       ? PPP_RET_ERROR : PPP_RET_OK;

	case PPP_CODE_ECHO_REP:
		/* Just ignore echo replies */
		return PPP_RET_OK;

	case PPP_CODE_CODE_REJ:
	case PPP_CODE_PROTO_REJ:
		/* Log and ignore */
		return PPP_RET_OK;

	default:
		return PPP_RET_OK;
	}
}

/*
 * Handle an incoming IPCP packet.
 */
static int handle_ipcp(struct ppp_context *ctx,
                       const uint8_t *payload, size_t payload_len,
                       uint8_t **response, size_t *resp_len)
{
	uint8_t code, id;
	uint16_t pkt_length;

	*response = NULL;
	*resp_len = 0;

	if (payload_len < 4)
		return PPP_RET_ERROR;

	code = payload[0];
	id = payload[1];
	pkt_length = ((uint16_t)payload[2] << 8) | payload[3];

	if (pkt_length > payload_len)
		return PPP_RET_ERROR;

	switch (code) {
	case PPP_CODE_CONF_REQ: {
		/*
		 * Peer's IPCP Config-Request. Accept it as-is.
		 * Extract peer IP if present.
		 */
		const uint8_t *opts = &payload[4];
		size_t opts_len = pkt_length - 4;
		size_t pos = 0;

		while (pos < opts_len) {
			uint8_t opt_type, opt_len_val;

			if (pos + 2 > opts_len)
				break;
			opt_type = opts[pos];
			opt_len_val = opts[pos + 1];
			if (opt_len_val < 2 || pos + opt_len_val > opts_len)
				break;

			if (opt_type == IPCP_OPT_IP_ADDR && opt_len_val >= 6)
				memcpy(&ctx->peer_ip, &opts[pos + 2], 4);
			pos += opt_len_val;
		}

		/* Send Config-Ack */
		return build_control_packet(PPP_PROTO_IPCP,
		                            PPP_CODE_CONF_ACK, id,
		                            opts, opts_len,
		                            response, resp_len) < 0
		       ? PPP_RET_ERROR : PPP_RET_OK;
	}

	case PPP_CODE_CONF_ACK:
		/* Peer accepted our IPCP config - negotiation complete */
		if (ctx->state == PPP_STATE_IPCP_SENT) {
			ctx->state = PPP_STATE_IPCP_OPEN;
			ctx->negotiation_complete = 1;
			return PPP_RET_NEGOTIATE;
		}
		return PPP_RET_OK;

	case PPP_CODE_CONF_NAK: {
		/*
		 * Peer is suggesting different values for our IPCP options.
		 * Parse the nak'd options to get the assigned IP/DNS.
		 */
		const uint8_t *opts = &payload[4];
		size_t opts_len = pkt_length - 4;
		size_t pos = 0;

		while (pos < opts_len) {
			uint8_t opt_type, opt_len_val;

			if (pos + 2 > opts_len)
				break;
			opt_type = opts[pos];
			opt_len_val = opts[pos + 1];
			if (opt_len_val < 2 || pos + opt_len_val > opts_len)
				break;

			if (opt_type == IPCP_OPT_IP_ADDR && opt_len_val >= 6)
				memcpy(&ctx->local_ip, &opts[pos + 2], 4);
			else if (opt_type == IPCP_OPT_DNS_PRI && opt_len_val >= 6)
				memcpy(&ctx->dns_primary, &opts[pos + 2], 4);
			else if (opt_type == IPCP_OPT_DNS_SEC && opt_len_val >= 6)
				memcpy(&ctx->dns_secondary, &opts[pos + 2], 4);

			pos += opt_len_val;
		}

		/* Re-send IPCP Config-Request with the suggested values */
		uint8_t ipcp_opts[18];
		size_t off = 0;

		ipcp_opts[off++] = IPCP_OPT_IP_ADDR;
		ipcp_opts[off++] = 6;
		memcpy(&ipcp_opts[off], &ctx->local_ip, 4);
		off += 4;

		ipcp_opts[off++] = IPCP_OPT_DNS_PRI;
		ipcp_opts[off++] = 6;
		memcpy(&ipcp_opts[off], &ctx->dns_primary, 4);
		off += 4;

		ipcp_opts[off++] = IPCP_OPT_DNS_SEC;
		ipcp_opts[off++] = 6;
		memcpy(&ipcp_opts[off], &ctx->dns_secondary, 4);
		off += 4;

		return build_control_packet(PPP_PROTO_IPCP,
		                            PPP_CODE_CONF_REQ,
		                            ctx->ipcp_identifier++,
		                            ipcp_opts, off,
		                            response, resp_len) < 0
		       ? PPP_RET_ERROR : PPP_RET_OK;
	}

	case PPP_CODE_CONF_REJ: {
		/*
		 * Peer rejected some IPCP options. Re-send without them.
		 * Typically DNS options may be rejected.
		 */
		const uint8_t *rej_opts = &payload[4];
		size_t rej_len = pkt_length - 4;
		uint8_t ipcp_opts[18];
		size_t off = 0;
		int ip_rejected = 0;
		int dns_pri_rejected = 0;
		int dns_sec_rejected = 0;
		size_t pos = 0;

		/* Determine which options were rejected */
		while (pos < rej_len) {
			uint8_t opt_type, opt_len_val;

			if (pos + 2 > rej_len)
				break;
			opt_type = rej_opts[pos];
			opt_len_val = rej_opts[pos + 1];
			if (opt_len_val < 2 || pos + opt_len_val > rej_len)
				break;

			if (opt_type == IPCP_OPT_IP_ADDR)
				ip_rejected = 1;
			else if (opt_type == IPCP_OPT_DNS_PRI)
				dns_pri_rejected = 1;
			else if (opt_type == IPCP_OPT_DNS_SEC)
				dns_sec_rejected = 1;

			pos += opt_len_val;
		}

		/* Rebuild request without rejected options */
		if (!ip_rejected) {
			ipcp_opts[off++] = IPCP_OPT_IP_ADDR;
			ipcp_opts[off++] = 6;
			memcpy(&ipcp_opts[off], &ctx->local_ip, 4);
			off += 4;
		}
		if (!dns_pri_rejected) {
			ipcp_opts[off++] = IPCP_OPT_DNS_PRI;
			ipcp_opts[off++] = 6;
			memcpy(&ipcp_opts[off], &ctx->dns_primary, 4);
			off += 4;
		}
		if (!dns_sec_rejected) {
			ipcp_opts[off++] = IPCP_OPT_DNS_SEC;
			ipcp_opts[off++] = 6;
			memcpy(&ipcp_opts[off], &ctx->dns_secondary, 4);
			off += 4;
		}

		return build_control_packet(PPP_PROTO_IPCP,
		                            PPP_CODE_CONF_REQ,
		                            ctx->ipcp_identifier++,
		                            ipcp_opts, off,
		                            response, resp_len) < 0
		       ? PPP_RET_ERROR : PPP_RET_OK;
	}

	case PPP_CODE_TERM_REQ:
		ctx->state = PPP_STATE_TERMINATED;
		if (build_control_packet(PPP_PROTO_IPCP, PPP_CODE_TERM_ACK,
		                         id, NULL, 0,
		                         response, resp_len) < 0)
			return PPP_RET_ERROR;
		return PPP_RET_TERMINATED;

	case PPP_CODE_TERM_ACK:
		ctx->state = PPP_STATE_TERMINATED;
		return PPP_RET_TERMINATED;

	default:
		return PPP_RET_OK;
	}
}

int ppp_process_incoming(struct ppp_context *ctx,
                         const uint8_t *ppp_data, size_t ppp_len,
                         uint8_t **response, size_t *resp_len,
                         uint8_t **ip_payload, size_t *ip_len)
{
	uint16_t protocol;

	*response = NULL;
	*resp_len = 0;
	*ip_payload = NULL;
	*ip_len = 0;

	if (ppp_len < 2)
		return PPP_RET_ERROR;

	protocol = ((uint16_t)ppp_data[0] << 8) | ppp_data[1];

	switch (protocol) {
	case PPP_PROTO_LCP:
		return handle_lcp(ctx, &ppp_data[2], ppp_len - 2,
		                  response, resp_len);

	case PPP_PROTO_IPCP:
		return handle_ipcp(ctx, &ppp_data[2], ppp_len - 2,
		                   response, resp_len);

	case PPP_PROTO_IP: {
		/* Raw IP data packet - extract the IP payload */
		size_t data_len = ppp_len - 2;

		if (data_len == 0)
			return PPP_RET_OK;

		*ip_payload = malloc(data_len);
		if (!*ip_payload)
			return PPP_RET_ERROR;
		memcpy(*ip_payload, &ppp_data[2], data_len);
		*ip_len = data_len;
		return PPP_RET_IP_PACKET;
	}

	default: {
		size_t rej_data_len = ppp_len;
		/*
		 * Unknown protocol. Send Protocol-Reject (LCP Code 8)
		 * containing the rejected protocol and packet data.
		 * Limit reject data per RFC 1661.
		 */
		if (rej_data_len > 1500)
			rej_data_len = 1500;
		return build_control_packet(PPP_PROTO_LCP,
		                            PPP_CODE_PROTO_REJ,
		                            ctx->lcp_identifier++,
		                            ppp_data, rej_data_len,
		                            response, resp_len) < 0
		       ? PPP_RET_ERROR : PPP_RET_OK;
	}
	}
}

int ppp_encapsulate_ip(const uint8_t *ip_data, size_t ip_len,
                       uint8_t **ppp_data, size_t *ppp_len)
{
	size_t total_len = 2 + ip_len;
	uint8_t *pkt;

	pkt = malloc(total_len);
	if (!pkt)
		return -1;

	/* PPP protocol field for IPv4 */
	pkt[0] = (uint8_t)(PPP_PROTO_IP >> 8);
	pkt[1] = (uint8_t)(PPP_PROTO_IP & 0xff);

	memcpy(&pkt[2], ip_data, ip_len);

	*ppp_data = pkt;
	*ppp_len = total_len;
	return 0;
}
