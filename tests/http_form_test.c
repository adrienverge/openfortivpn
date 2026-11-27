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

#include "../src/http_form.h"

#include <stdio.h>
#include <string.h>

static int test_otp_form(void)
{
	char buffer[2048];
	char too_small[8];
	static const char expected[] =
		"username=user%20name&realm=realm%20one&reqid=req42&"
		"polid=policy1&grp=Group%20One%20%26%20Two&"
		"portal=Portal%20Name&peer=peer1&"
		"code=123456&code2=&magic=a%2Bb";

	if (http_build_otp_form(buffer, sizeof(buffer), "user%20name",
	                        "realm%20one", "req42", "policy1",
	                        "Group One & Two", "Portal Name", "peer1",
	                        "code=123456&code2=&magic=a%2Bb") != 0) {
		fputs("failed to build synthetic 2FA form\n", stderr);
		return -1;
	}
	if (strcmp(buffer, expected) != 0) {
		fprintf(stderr, "unexpected synthetic 2FA form: %s\n", buffer);
		return -1;
	}
	if (http_build_otp_form(too_small, sizeof(too_small), "u", "r", "i",
	                        "p", "g", "t", "e", "code=1") == 0) {
		fputs("too-small destination was accepted\n", stderr);
		return -1;
	}

	return 0;
}


int main(void)
{
	if (test_otp_form() != 0)
		return 1;

	puts("2FA form encoding tests passed");
	return 0;
}
