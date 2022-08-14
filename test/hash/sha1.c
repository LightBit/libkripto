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
#include <kripto/hash/sha1.h>

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
			.hash = "\xDA\x39\xA3\xEE\x5E\x6B\x4B\x0D\x32\x55\xBF\xEF\x95\x60\x18\x90\xAF\xD8\x07\x09",
			.hash_len = 20
		},
		{
			.message = "a",
			.message_len = 1,
			.message_repeat = 1,
			.salt_len = 0,
			.rounds = 0,
			.hash = "\x86\xF7\xE4\x37\xFA\xA5\xA7\xFC\xE1\x5D\x1D\xDC\xB9\xEA\xEA\xEA\x37\x76\x67\xB8",
			.hash_len = 20
		},
		{
			.message = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
			.message_len = 62,
			.message_repeat = 1,
			.salt_len = 0,
			.rounds = 0,
			.hash = "\x76\x1C\x45\x7B\xF7\x3B\x14\xD2\x7E\x9E\x92\x65\xC4\x6F\x4B\x4D\xDA\x11\xF9\x40",
			.hash_len = 20
		},
		{
			.message = "a",
			.message_len = 1,
			.message_repeat = 1000000,
			.salt_len = 0,
			.rounds = 0,
			.hash = "\x34\xAA\x97\x3C\xD4\xC4\xDA\xA4\xF6\x1E\xEB\x2B\xDB\xAD\x27\x31\x65\x34\x01\x6F",
			.hash_len = 20
		}
	};

	return TEST(kripto_hash_sha1, vectors, 4);
}
