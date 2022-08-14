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
#include <kripto/hash/md5.h>

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
			.hash = "\xD4\x1D\x8C\xD9\x8F\x00\xB2\x04\xE9\x80\x09\x98\xEC\xF8\x42\x7E",
			.hash_len = 16
		},
		{
			.message = "a",
			.message_len = 1,
			.message_repeat = 1,
			.salt_len = 0,
			.rounds = 0,
			.hash = "\x0C\xC1\x75\xB9\xC0\xF1\xB6\xA8\x31\xC3\x99\xE2\x69\x77\x26\x61",
			.hash_len = 16
		},
		{
			.message = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
			.message_len = 62,
			.message_repeat = 1,
			.salt_len = 0,
			.rounds = 0,
			.hash = "\xD1\x74\xAB\x98\xD2\x77\xD9\xF5\xA5\x61\x1C\x2C\x9F\x41\x9D\x9F",
			.hash_len = 16
		},
		{
			.message = "a",
			.message_len = 1,
			.message_repeat = 1000000,
			.salt_len = 0,
			.rounds = 0,
			.hash = "\x77\x07\xD6\xAE\x4E\x02\x7C\x70\xEE\xA2\xA9\x35\xC2\x29\x6F\x21",
			.hash_len = 16
		}
	};

	return TEST(kripto_hash_md5, vectors, 4);
}
