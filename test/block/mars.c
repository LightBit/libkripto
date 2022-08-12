/*
 * Copyright (C) 2022 by Gregor Pintar <grpintar@gmail.com>
 *
 * Permission to use, copy, modify, and/or distribute this software
 * for any purpose with or without fee is hereby granted.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <kripto/block.h>
#include <kripto/block/mars.h>

#include "test.h"

int main(void)
{
	const struct vector vectors[3] =
	{
		{
			.key_len = 16,
			.tweak_len = 0,
			.rounds = 0,
			.iterations = 1,
			.key = "\xD6\xC7\x50\x9B\x6E\xAD\xB6\x13\xBA\xD6\x81\xEF\xE2\x85\xCF\x20",
			.pt = "\x24\x4B\x2E\xFC\x4C\xEA\x68\x37\x26\xD2\x3F\x96\xF9\x4B\x8F\x45",
			.ct = "\x7F\x8F\xEC\xA0\xCF\xBD\x2C\x42\x3B\x4A\x41\xDE\x9F\xD2\xAD\xDC"
		},
		{
			.key_len = 24,
			.tweak_len = 0,
			.rounds = 0,
			.iterations = 1,
			.key = "\x4E\x8E\x31\x76\x4C\x12\x24\x99\x85\xFF\x40\xF5\x88\x68\xC6\x21\xB3\xDB\xB6\x21\x8D\x45\x91\xC5",
			.pt = "\x85\xFF\x40\xF5\x88\x68\xC6\x21\xB3\xDB\xB6\x21\x8D\x45\x91\xC5",
			.ct = "\x5C\x95\xC4\xE3\xB8\xF2\x26\xA0\xF6\x02\x1F\x75\xFF\xED\x2A\x0A"
		},
		{
			.key_len = 32,
			.tweak_len = 0,
			.rounds = 0,
			.iterations = 1,
			.key = "\x94\xF0\x35\x13\x89\xD8\xED\xA5\xBE\xBD\x9A\xC8\x82\x43\x5C\x68\x4C\x95\x98\xEC\x84\x52\x55\xAE\xF3\x9A\x79\x7C\xB1\xF8\xBF\x59",
			.pt = "\x4C\x95\x98\xEC\x84\x52\x55\xAE\xF3\x9A\x79\x7C\xB1\xF8\xBF\x59",
			.ct = "\x60\xF9\xF1\xC7\xAD\xB6\x93\x0A\x99\x94\x01\xD9\xEC\x2B\x38\x37"
		}
	};

	return TEST(kripto_block_mars, vectors, 3);
}
