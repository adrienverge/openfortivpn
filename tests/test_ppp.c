/*
 * Unit tests for the PPP state machine (ppp.c).
 *
 * Tests LCP and IPCP negotiation flows using synthetic PPP packets
 * that mirror what a FortiGate VPN gateway sends.
 */

#include "ppp.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int tests_run;
static int tests_passed;

#define TEST(name) \
	do { \
		tests_run++; \
		printf("  %-50s", name); \
	} while (0)

#define PASS() \
	do { \
		tests_passed++; \
		printf("[PASS]\n"); \
	} while (0)

#define FAIL(msg) \
	printf("[FAIL] %s\n", msg)

#define ASSERT(cond, msg) \
	do { \
		if (!(cond)) { \
			FAIL(msg); \
			return; \
		} \
	} while (0)

/*
 * Test: ppp_init sets correct defaults.
 */
static void test_ppp_init(void)
{
	struct ppp_context ctx;

	TEST("ppp_init sets defaults");
	ppp_init(&ctx);
	ASSERT(ctx.state == PPP_STATE_INITIAL, "state should be INITIAL");
	ASSERT(ctx.mru == 1354, "MRU should be 1354");
	ASSERT(ctx.asyncmap == 0, "ACCM should be 0");
	ASSERT(ctx.local_ip == 0, "local_ip should be 0");
	ASSERT(ctx.negotiation_complete == 0, "negotiation should not be complete");
	PASS();
}

/*
 * Test: ppp_start_negotiation sends an LCP Config-Request.
 */
static void test_start_negotiation(void)
{
	struct ppp_context ctx;
	uint8_t *out;
	size_t out_len;
	int ret;

	TEST("ppp_start_negotiation sends LCP Config-Request");
	ppp_init(&ctx);
	ret = ppp_start_negotiation(&ctx, &out, &out_len);
	ASSERT(ret == 0, "should return 0");
	ASSERT(out != NULL, "output should not be NULL");
	ASSERT(out_len >= 6, "output should be at least 6 bytes");

	/* Check protocol = LCP (0xc021) */
	ASSERT(out[0] == 0xc0 && out[1] == 0x21, "protocol should be LCP");
	/* Check code = Config-Request (1) */
	ASSERT(out[2] == PPP_CODE_CONF_REQ, "code should be Config-Request");
	/* Check state transition */
	ASSERT(ctx.state == PPP_STATE_LCP_SENT, "state should be LCP_SENT");

	free(out);
	PASS();
}

/*
 * Test: Process a peer LCP Config-Request and respond with Config-Ack.
 */
static void test_lcp_config_req_ack(void)
{
	struct ppp_context ctx;
	uint8_t *response, *ip_payload;
	size_t resp_len, ip_len;
	int ret;

	/* Simulated peer LCP Config-Request:
	 * protocol=0xc021, code=1, id=1, length=8
	 * Options: MRU=1500 (type 1, len 4, value 0x05DC)
	 */
	uint8_t lcp_conf_req[] = {
		0xc0, 0x21,             /* LCP protocol */
		0x01,                   /* Config-Request */
		0x01,                   /* Identifier */
		0x00, 0x08,             /* Length = 8 (4 header + 4 option) */
		0x01, 0x04, 0x05, 0xDC  /* MRU option: type=1, len=4, MRU=1500 */
	};

	TEST("LCP Config-Request -> Config-Ack");
	ppp_init(&ctx);
	ctx.state = PPP_STATE_LCP_SENT;

	ret = ppp_process_incoming(&ctx, lcp_conf_req, sizeof(lcp_conf_req),
	                           &response, &resp_len, &ip_payload, &ip_len);
	ASSERT(ret == PPP_RET_OK, "should return OK");
	ASSERT(response != NULL, "should generate response");
	ASSERT(response[0] == 0xc0 && response[1] == 0x21, "response should be LCP");
	ASSERT(response[2] == PPP_CODE_CONF_ACK, "response should be Config-Ack");
	ASSERT(response[3] == 0x01, "identifier should match request");
	ASSERT(ip_payload == NULL, "no IP payload expected");

	free(response);
	PASS();
}

/*
 * Test: Reject LCP Auth option.
 */
static void test_lcp_reject_auth(void)
{
	struct ppp_context ctx;
	uint8_t *response, *ip_payload;
	size_t resp_len, ip_len;
	int ret;

	/* LCP Config-Request with Auth option (type 3)
	 * Length = 4 (header) + 4 (MRU) + 4 (Auth) = 12
	 */
	uint8_t lcp_with_auth[] = {
		0xc0, 0x21,
		0x01, 0x02, 0x00, 0x0c,
		0x01, 0x04, 0x05, 0xDC, /* MRU=1500 */
		0x03, 0x04, 0xc0, 0x23  /* Auth: PAP (0xc023) */
	};

	TEST("LCP Config-Request with Auth -> Config-Reject");
	ppp_init(&ctx);
	ctx.state = PPP_STATE_LCP_SENT;

	ret = ppp_process_incoming(&ctx, lcp_with_auth, sizeof(lcp_with_auth),
	                           &response, &resp_len, &ip_payload, &ip_len);
	ASSERT(ret == PPP_RET_OK, "should return OK");
	ASSERT(response != NULL, "should generate response");
	ASSERT(response[2] == PPP_CODE_CONF_REJ, "should be Config-Reject");

	free(response);
	PASS();
}

/*
 * Test: LCP Config-Ack triggers IPCP negotiation start.
 */
static void test_lcp_ack_starts_ipcp(void)
{
	struct ppp_context ctx;
	uint8_t *response, *ip_payload;
	size_t resp_len, ip_len;
	int ret;

	/* Peer sends LCP Config-Ack for our request */
	uint8_t lcp_conf_ack[] = {
		0xc0, 0x21,
		0x02,       /* Config-Ack */
		0x01,       /* Identifier (matching our request) */
		0x00, 0x04  /* Length = 4 (header only, all options accepted) */
	};

	TEST("LCP Config-Ack triggers IPCP Config-Request");
	ppp_init(&ctx);
	ctx.state = PPP_STATE_LCP_SENT;

	ret = ppp_process_incoming(&ctx, lcp_conf_ack, sizeof(lcp_conf_ack),
	                           &response, &resp_len, &ip_payload, &ip_len);
	ASSERT(ret == PPP_RET_OK, "should return OK");
	ASSERT(ctx.state == PPP_STATE_IPCP_SENT, "state should be IPCP_SENT");
	ASSERT(response != NULL, "should generate IPCP Config-Request");
	ASSERT(response[0] == 0x80 && response[1] == 0x21, "should be IPCP");
	ASSERT(response[2] == PPP_CODE_CONF_REQ, "should be Config-Request");

	free(response);
	PASS();
}

/*
 * Test: IPCP Config-Nak with assigned IP triggers re-request.
 */
static void test_ipcp_nak_assigns_ip(void)
{
	struct ppp_context ctx;
	uint8_t *response, *ip_payload;
	size_t resp_len, ip_len;
	int ret;

	/*
	 * IPCP Config-Nak with:
	 * - IP-Address: 10.0.1.100
	 * - Primary DNS: 8.8.8.8
	 * - Secondary DNS: 8.8.4.4
	 */
	uint8_t ipcp_nak[] = {
		0x80, 0x21,
		0x03,                    /* Config-Nak */
		0x01,                    /* Identifier */
		0x00, 0x16,              /* Length = 22 */
		0x03, 0x06, 0x0a, 0x00, 0x01, 0x64,  /* IP: 10.0.1.100 */
		0x81, 0x06, 0x08, 0x08, 0x08, 0x08,  /* DNS1: 8.8.8.8 */
		0x83, 0x06, 0x08, 0x08, 0x04, 0x04   /* DNS2: 8.8.4.4 */
	};

	TEST("IPCP Config-Nak assigns IP and DNS");
	ppp_init(&ctx);
	ctx.state = PPP_STATE_IPCP_SENT;

	ret = ppp_process_incoming(&ctx, ipcp_nak, sizeof(ipcp_nak),
	                           &response, &resp_len, &ip_payload, &ip_len);
	ASSERT(ret == PPP_RET_OK, "should return OK");
	ASSERT(response != NULL, "should generate re-request");
	ASSERT(response[0] == 0x80 && response[1] == 0x21, "should be IPCP");
	ASSERT(response[2] == PPP_CODE_CONF_REQ, "should be Config-Request");

	/* Verify the IP was stored */
	{
		uint8_t expected_ip[] = {0x0a, 0x00, 0x01, 0x64};
		uint8_t expected_dns1[] = {0x08, 0x08, 0x08, 0x08};
		uint8_t expected_dns2[] = {0x08, 0x08, 0x04, 0x04};

		ASSERT(memcmp(&ctx.local_ip, expected_ip, 4) == 0,
		       "local_ip should be 10.0.1.100");
		ASSERT(memcmp(&ctx.dns_primary, expected_dns1, 4) == 0,
		       "DNS1 should be 8.8.8.8");
		ASSERT(memcmp(&ctx.dns_secondary, expected_dns2, 4) == 0,
		       "DNS2 should be 8.8.4.4");
	}

	free(response);
	PASS();
}

/*
 * Test: IPCP Config-Ack completes negotiation.
 */
static void test_ipcp_ack_completes(void)
{
	struct ppp_context ctx;
	uint8_t *response, *ip_payload;
	size_t resp_len, ip_len;
	int ret;

	uint8_t ipcp_ack[] = {
		0x80, 0x21,
		0x02,       /* Config-Ack */
		0x02,       /* Identifier */
		0x00, 0x04  /* Length */
	};

	TEST("IPCP Config-Ack completes negotiation");
	ppp_init(&ctx);
	ctx.state = PPP_STATE_IPCP_SENT;

	ret = ppp_process_incoming(&ctx, ipcp_ack, sizeof(ipcp_ack),
	                           &response, &resp_len, &ip_payload, &ip_len);
	ASSERT(ret == PPP_RET_NEGOTIATE, "should return NEGOTIATE");
	ASSERT(ctx.state == PPP_STATE_IPCP_OPEN, "state should be IPCP_OPEN");
	ASSERT(ctx.negotiation_complete == 1, "negotiation should be complete");

	free(response);
	PASS();
}

/*
 * Test: IP data packet extraction after negotiation.
 */
static void test_ip_packet_extraction(void)
{
	struct ppp_context ctx;
	uint8_t *response, *ip_payload;
	size_t resp_len, ip_len;
	int ret;

	/* Minimal fake IP packet (just header bytes for testing) */
	uint8_t ip_data_pkt[] = {
		0x00, 0x21,                         /* IP protocol */
		0x45, 0x00, 0x00, 0x14,             /* IP header: ver=4, IHL=5, len=20 */
		0x00, 0x01, 0x00, 0x00,             /* ID=1, flags=0 */
		0x40, 0x06, 0x00, 0x00,             /* TTL=64, proto=TCP */
		0x0a, 0x00, 0x01, 0x64,             /* Src: 10.0.1.100 */
		0xc0, 0xa8, 0x01, 0x01              /* Dst: 192.168.1.1 */
	};

	TEST("IP data packet extraction");
	ppp_init(&ctx);
	ctx.state = PPP_STATE_IPCP_OPEN;
	ctx.negotiation_complete = 1;

	ret = ppp_process_incoming(&ctx, ip_data_pkt, sizeof(ip_data_pkt),
	                           &response, &resp_len, &ip_payload, &ip_len);
	ASSERT(ret == PPP_RET_IP_PACKET, "should return IP_PACKET");
	ASSERT(ip_payload != NULL, "ip_payload should not be NULL");
	ASSERT(ip_len == sizeof(ip_data_pkt) - 2, "ip_len should be packet minus protocol field");
	ASSERT(ip_payload[0] == 0x45, "first byte should be IP version+IHL");
	ASSERT(response == NULL, "no response for IP data");

	free(ip_payload);
	PASS();
}

/*
 * Test: IP packet encapsulation.
 */
static void test_ip_encapsulation(void)
{
	uint8_t ip_data[] = {0x45, 0x00, 0x00, 0x14, 0x00, 0x01};
	uint8_t *ppp_data;
	size_t ppp_len;
	int ret;

	TEST("IP packet encapsulation");
	ret = ppp_encapsulate_ip(ip_data, sizeof(ip_data), &ppp_data, &ppp_len);
	ASSERT(ret == 0, "should return 0");
	ASSERT(ppp_len == sizeof(ip_data) + 2, "length should include protocol field");
	ASSERT(ppp_data[0] == 0x00 && ppp_data[1] == 0x21, "protocol should be 0x0021");
	ASSERT(memcmp(&ppp_data[2], ip_data, sizeof(ip_data)) == 0, "data should match");

	free(ppp_data);
	PASS();
}

/*
 * Test: LCP Echo-Request generates Echo-Reply.
 */
static void test_lcp_echo(void)
{
	struct ppp_context ctx;
	uint8_t *response, *ip_payload;
	size_t resp_len, ip_len;
	int ret;

	uint8_t echo_req[] = {
		0xc0, 0x21,
		0x09,                                /* Echo-Request */
		0x05,                                /* Identifier */
		0x00, 0x08,                          /* Length = 8 */
		0x12, 0x34, 0x56, 0x78               /* Magic number */
	};

	TEST("LCP Echo-Request -> Echo-Reply");
	ppp_init(&ctx);
	ctx.state = PPP_STATE_LCP_OPEN;

	ret = ppp_process_incoming(&ctx, echo_req, sizeof(echo_req),
	                           &response, &resp_len, &ip_payload, &ip_len);
	ASSERT(ret == PPP_RET_OK, "should return OK");
	ASSERT(response != NULL, "should generate Echo-Reply");
	ASSERT(response[2] == PPP_CODE_ECHO_REP, "should be Echo-Reply");
	ASSERT(response[3] == 0x05, "identifier should match");

	free(response);
	PASS();
}

/*
 * Test: LCP Terminate-Request generates Terminate-Ack.
 */
static void test_lcp_terminate(void)
{
	struct ppp_context ctx;
	uint8_t *response, *ip_payload;
	size_t resp_len, ip_len;
	int ret;

	uint8_t term_req[] = {
		0xc0, 0x21,
		0x05,       /* Terminate-Request */
		0x03,       /* Identifier */
		0x00, 0x04  /* Length */
	};

	TEST("LCP Terminate-Request -> Terminate-Ack");
	ppp_init(&ctx);
	ctx.state = PPP_STATE_LCP_OPEN;

	ret = ppp_process_incoming(&ctx, term_req, sizeof(term_req),
	                           &response, &resp_len, &ip_payload, &ip_len);
	ASSERT(ret == PPP_RET_TERMINATED, "should return TERMINATED");
	ASSERT(ctx.state == PPP_STATE_TERMINATED, "state should be TERMINATED");
	ASSERT(response != NULL, "should generate Terminate-Ack");
	ASSERT(response[2] == PPP_CODE_TERM_ACK, "should be Terminate-Ack");

	free(response);
	PASS();
}

/*
 * Test: Unknown protocol triggers Protocol-Reject.
 */
static void test_unknown_protocol(void)
{
	struct ppp_context ctx;
	uint8_t *response, *ip_payload;
	size_t resp_len, ip_len;
	int ret;

	uint8_t unknown_proto[] = {
		0xAB, 0xCD,            /* Unknown protocol */
		0x01, 0x02, 0x03, 0x04 /* Some data */
	};

	TEST("Unknown protocol -> Protocol-Reject");
	ppp_init(&ctx);
	ctx.state = PPP_STATE_LCP_OPEN;

	ret = ppp_process_incoming(&ctx, unknown_proto, sizeof(unknown_proto),
	                           &response, &resp_len, &ip_payload, &ip_len);
	ASSERT(ret == PPP_RET_OK, "should return OK");
	ASSERT(response != NULL, "should generate Protocol-Reject");
	ASSERT(response[0] == 0xc0 && response[1] == 0x21, "should be LCP");
	ASSERT(response[2] == PPP_CODE_PROTO_REJ, "should be Protocol-Reject");

	free(response);
	PASS();
}

/*
 * Test: Full negotiation flow (LCP + IPCP).
 */
static void test_full_negotiation(void)
{
	struct ppp_context ctx;
	uint8_t *response, *ip_payload, *start_pkt;
	size_t resp_len, ip_len, start_len;
	int ret;

	TEST("Full LCP + IPCP negotiation flow");
	ppp_init(&ctx);

	/* Step 1: Start negotiation (sends LCP Config-Request) */
	ret = ppp_start_negotiation(&ctx, &start_pkt, &start_len);
	ASSERT(ret == 0, "start should succeed");
	ASSERT(ctx.state == PPP_STATE_LCP_SENT, "should be LCP_SENT");
	free(start_pkt);

	/* Step 2: Peer sends LCP Config-Request (we ack)
	 * Length = 4 (header) + 4 (MRU) = 8
	 */
	uint8_t peer_lcp_req[] = {
		0xc0, 0x21, 0x01, 0x01, 0x00, 0x08,
		0x01, 0x04, 0x05, 0xDC /* MRU=1500 */
	};
	ret = ppp_process_incoming(&ctx, peer_lcp_req, sizeof(peer_lcp_req),
	                           &response, &resp_len, &ip_payload, &ip_len);
	ASSERT(ret == PPP_RET_OK && response != NULL, "should ack peer LCP");
	ASSERT(response[2] == PPP_CODE_CONF_ACK, "should be Config-Ack");
	free(response);

	/* Step 3: Peer sends LCP Config-Ack (our LCP req accepted) -> triggers IPCP */
	uint8_t peer_lcp_ack[] = {
		0xc0, 0x21, 0x02, 0x01, 0x00, 0x04
	};
	ret = ppp_process_incoming(&ctx, peer_lcp_ack, sizeof(peer_lcp_ack),
	                           &response, &resp_len, &ip_payload, &ip_len);
	ASSERT(ret == PPP_RET_OK, "should handle LCP ack");
	ASSERT(ctx.state == PPP_STATE_IPCP_SENT, "should be IPCP_SENT");
	ASSERT(response != NULL, "should send IPCP Config-Request");
	free(response);

	/* Step 4: Peer IPCP Config-Nak with assigned addresses */
	uint8_t peer_ipcp_nak[] = {
		0x80, 0x21, 0x03, 0x01, 0x00, 0x16,
		0x03, 0x06, 0x0a, 0x00, 0x01, 0x64,  /* IP: 10.0.1.100 */
		0x81, 0x06, 0x08, 0x08, 0x08, 0x08,  /* DNS1: 8.8.8.8 */
		0x83, 0x06, 0x08, 0x08, 0x04, 0x04   /* DNS2: 8.8.4.4 */
	};
	ret = ppp_process_incoming(&ctx, peer_ipcp_nak, sizeof(peer_ipcp_nak),
	                           &response, &resp_len, &ip_payload, &ip_len);
	ASSERT(ret == PPP_RET_OK, "should handle IPCP Nak");
	ASSERT(response != NULL, "should re-send IPCP request");
	free(response);

	/* Step 5: Peer sends IPCP Config-Ack -> negotiation complete */
	uint8_t peer_ipcp_ack[] = {
		0x80, 0x21, 0x02, 0x02, 0x00, 0x04
	};
	ret = ppp_process_incoming(&ctx, peer_ipcp_ack, sizeof(peer_ipcp_ack),
	                           &response, &resp_len, &ip_payload, &ip_len);
	ASSERT(ret == PPP_RET_NEGOTIATE, "should signal negotiation complete");
	ASSERT(ctx.state == PPP_STATE_IPCP_OPEN, "should be IPCP_OPEN");
	ASSERT(ctx.negotiation_complete == 1, "negotiation should be flagged complete");
	free(response);

	/* Step 6: Peer sends IP data packet */
	uint8_t ip_data[] = {
		0x00, 0x21,
		0x45, 0x00, 0x00, 0x14, 0x00, 0x01, 0x00, 0x00,
		0x40, 0x06, 0x00, 0x00, 0x0a, 0x00, 0x01, 0x64,
		0xc0, 0xa8, 0x01, 0x01
	};
	ret = ppp_process_incoming(&ctx, ip_data, sizeof(ip_data),
	                           &response, &resp_len, &ip_payload, &ip_len);
	ASSERT(ret == PPP_RET_IP_PACKET, "should extract IP packet");
	ASSERT(ip_len == sizeof(ip_data) - 2, "IP length should match");
	free(ip_payload);
	free(response);

	PASS();
}

int main(void)
{
	printf("PPP State Machine Tests\n");
	printf("========================\n\n");

	test_ppp_init();
	test_start_negotiation();
	test_lcp_config_req_ack();
	test_lcp_reject_auth();
	test_lcp_ack_starts_ipcp();
	test_ipcp_nak_assigns_ip();
	test_ipcp_ack_completes();
	test_ip_packet_extraction();
	test_ip_encapsulation();
	test_lcp_echo();
	test_lcp_terminate();
	test_unknown_protocol();
	test_full_negotiation();

	printf("\n========================\n");
	printf("Results: %d/%d passed\n", tests_passed, tests_run);

	return (tests_passed == tests_run) ? 0 : 1;
}
