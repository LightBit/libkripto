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
			.iterations = 1,
			.key = "\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00",
			.pt = "\x00\x00\x00\x00\x00\x00\x00\x00",
			.ct = "\x7A\x00\xE4\x94\x41\x46\x1F\x5A"
		},
		{
			.key_len = 10,
			.tweak_len = 0,
			.rounds = 0,
			.iterations = 1,
			.key = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01",
			.pt = "\x00\x00\x00\x00\x00\x00\x00\x00",
			.ct = "\x74\xD0\xE7\xC2\xE3\xB4\x50\xA8"
		}
	};

	return TEST(kripto_block_skipjack, vectors, 2);
}
