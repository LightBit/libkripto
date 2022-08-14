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

#include <kripto/hash.h>
#include <kripto/hash/tiger.h>

#include "test.h"

int main(void)
{
	const struct vector vectors[4] =
	{
		{
			.message = "",
			.message_len = 0,
			.message_repeat = 1,
			.salt_len = 0,
			.rounds = 0,
			.hash = "\x32\x93\xAC\x63\x0C\x13\xF0\x24\x5F\x92\xBB\xB1\x76\x6E\x16\x16\x7A\x4E\x58\x49\x2D\xDE\x73\xF3",
			.hash_len = 20
		},
		{
			.message = "a",
			.message_len = 1,
			.message_repeat = 1,
			.salt_len = 0,
			.rounds = 0,
			.hash = "\x77\xBE\xFB\xEF\x2E\x7E\xF8\xAB\x2E\xC8\xF9\x3B\xF5\x87\xA7\xFC\x61\x3E\x24\x7F\x5F\x24\x78\x09",
			.hash_len = 20
		},
		{
			.message = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
			.message_len = 62,
			.message_repeat = 1,
			.salt_len = 0,
			.rounds = 0,
			.hash = "\x8D\xCE\xA6\x80\xA1\x75\x83\xEE\x50\x2B\xA3\x8A\x3C\x36\x86\x51\x89\x0F\xFB\xCC\xDC\x49\xA8\xCC",
			.hash_len = 20
		},
		{
			.message = "a",
			.message_len = 1,
			.message_repeat = 1000000,
			.salt_len = 0,
			.rounds = 0,
			.hash = "\x6D\xB0\xE2\x72\x9C\xBE\xAD\x93\xD7\x15\xC6\xA7\xD3\x63\x02\xE9\xB3\xCE\xE0\xD2\xBC\x31\x4B\x41",
			.hash_len = 20
		}
	};

	return TEST(kripto_hash_tiger, vectors, 4);
}
