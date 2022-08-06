/*
 * Copyright (C) 2014 by Gregor Pintar <grpintar@gmail.com>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "test.h"

int test_result = 0;

void test_pass(const char *test)
{
	(void)test;

	#ifdef VERBOSE
	fputs(test, stdout);
	puts(": PASS");
	#endif
}

void test_fail(const char *test)
{
	fputs(test, stdout);
	puts(": FAIL");
	//exit(1);
	test_result = 1;
}

void test_error(const char *test)
{
	perror(test);
	exit(-1);
	//test_result = -1;
}

void test_cmp(const char *test, const void *s1, const void *s2, size_t len)
{
	if(memcmp(s1, s2, len)) test_fail(test);
	else test_pass(test);
}
