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
#include <kripto/block/skipjack.h>

#include "test.h"

int main(void)
{
	const struct vector vectors[2] =
	{
		{
			.key_len = 10,
			.tweak_len = 0,
			.rounds = 0,
			.iterations = 1000,
			.key = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09",
			.pt = "\x00\x11\x22\x33\x44\x55\x66\x77",
			.ct = "\x0C\x1F\xD5\xD4\x5C\x24\x3E\x87"
		},
		{
			.key_len = 10,
			.tweak_len = 0,
			.rounds = 0,
			.iterations = 1,
			.key = "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
			.pt = "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
			.ct = "\x08\x72\xA2\x6E\x61\x5D\xC3\x08"
		}
	};

	return TEST(kripto_block_skipjack, vectors, 2);
}
