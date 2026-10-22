/*
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include "../src/http_status.h"

#include <stdio.h>

static int test_status_code(void)
{
	struct test_case {
		const char *response;
		int expected;
	};
	static const struct test_case cases[] = {
		{ "HTTP/1.1 401 Unauthorized\r\n", 401 },
		{ "HTTP/1.1 401 Authorization Required\r\n", 401 },
		{ "HTTP/1.0 407 Proxy Authentication Required\r\n", 407 },
		{ "HTTP/1.1 200 OK\r\n", 200 },
		{ "HTTP/1.1 200 Fine\r\n", 200 },
		{ "HTTP/1.1 401Unauthorized\r\n", -1 },
		{ "HTTP/1.1 4010 Invalid\r\n", -1 },
		{ "HTTP/1.1 41 Invalid\r\n", -1 },
		{ "HTTP/1.1 000 Invalid\r\n", -1 },
		{ "HTTP/1.1 600 Invalid\r\n", -1 },
		{ "not an HTTP status line", -1 },
	};

	for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		int actual = http_response_status_code(cases[i].response);

		if (actual != cases[i].expected) {
			fprintf(stderr, "status case %zu: expected %d, got %d\n",
			        i, cases[i].expected, actual);
			return -1;
		}
	}

	return 0;
}


int main(void)
{
	if (test_status_code() != 0)
		return 1;

	puts("HTTP status parser tests passed");
	return 0;
}
