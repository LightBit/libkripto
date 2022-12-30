/*
 * Copyright (C) 2022 by Gregor Pintar <grpintar@gmail.com>
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

#ifndef TEST_TEST_H
#define TEST_TEST_H

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <stdarg.h>

void test_vpass(const char *file, unsigned int line, const char *msg, va_list args);
void test_pass(const char *file, unsigned int line, const char *msg, ...);
void test_vfail(const char *file, unsigned int line, const char *msg, va_list args);
void test_fail(const char *file, unsigned int line, const char *msg, ...);
void test_error(const char *file, unsigned int line, const char *msg, ...);
void test_cmp(const void *s1, const void *s2, size_t bytes, const char *file, unsigned int line, const char *msg, ...);

#define TEST_PASS(...) test_pass(__FILE__, __LINE__, __VA_ARGS__)
#define TEST_FAIL(...) test_fail(__FILE__, __LINE__, __VA_ARGS__)
#define TEST_ERROR(...) test_error(__FILE__, __LINE__, __VA_ARGS__)
#define TEST_CMP(S1, S2, BYTES, ...) test_cmp(S1, S2, BYTES, __FILE__, __LINE__, __VA_ARGS__)

int test_result = 0;

void test_vpass(const char *file, unsigned int line, const char *msg, va_list args)
{
	#ifdef VERBOSE
	printf("%s: %u: ", file, line);
	vprintf(msg, args);
	printf(": PASS\n");
	#else
	(void)file;
	(void)line;
	(void)msg;
	(void)args;
	#endif
}

void test_pass(const char *file, unsigned int line, const char *msg, ...)
{
	va_list args;
	va_start(args, msg);
	test_vpass(file, line, msg, args);
	va_end(args);
}

void test_vfail(const char *file, unsigned int line, const char *msg, va_list args)
{
	fprintf(stderr, "%s: %u: ", file, line);
	vfprintf(stderr, msg, args);
	fprintf(stderr, ": FAIL\n");

	test_result = 1;
}

void test_fail(const char *file, unsigned int line, const char *msg, ...)
{
	va_list args;
	va_start(args, msg);
	test_vfail(file, line, msg, args);
	va_end(args);
}

void test_error(const char *file, unsigned int line, const char *msg, ...)
{
	fprintf(stderr, "%s: %u: ", file, line);

	va_list args;
	va_start(args, msg);
	vfprintf(stderr, msg, args);
	va_end(args);

	fprintf(stderr, ": %s\n", strerror(errno));

	exit(-1);
}

void test_cmp(const void *s1, const void *s2, size_t bytes, const char *file, unsigned int line, const char *msg, ...)
{
	va_list args;
	va_start(args, msg);

	if(memcmp(s1, s2, bytes))
	{
		#ifdef VERBOSE
		printf("%s: %u: ", file, line);
		vprintf(msg, args);
		printf(": FAIL: ");
		for(unsigned int i = 0; i < bytes; i++)
		{
			printf("\\x%.2X", ((const unsigned char *)s1)[i]);
		}
		printf(" != ");
		for(unsigned int i = 0; i < bytes; i++)
		{
			printf("\\x%.2X", ((const unsigned char *)s2)[i]);
		}
		printf("\n");
		#else
		test_vfail(file, line, msg, args);
		#endif
	}
	else
	{
		test_vpass(file, line, msg, args);
	}

	va_end(args);
}

#endif
