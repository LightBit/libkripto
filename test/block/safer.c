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
#include <kripto/block/safer.h>
#include <kripto/block/safer_sk.h>

#include "test.h"

int main(void)
{
	const struct vector vectors[1] =
	{
		{
			.key_len = 8,
			.tweak_len = 0,
			.rounds = 0,
			.iterations = 1,
			.key = "\x08\x07\x06\x05\x04\x03\x02\x01",
			.pt = "\x01\x02\x03\x04\x05\x06\x07\x08",
			.ct = "\xC8\xF2\x9C\xDD\x87\x78\x3E\xD9"
		}
	};
	const struct vector sk_vectors[2] =
	{
		{
			.key_len = 8,
			.tweak_len = 0,
			.rounds = 0,
			.iterations = 1,
			.key = "\x01\x02\x03\x04\x05\x06\x07\x08",
			.pt = "\x01\x02\x03\x04\x05\x06\x07\x08",
			.ct = "\x5F\xCE\x9B\xA2\x05\x84\x38\xC7"
		},
		{
			.key_len = 16,
			.tweak_len = 0,
			.rounds = 0,
			.iterations = 1,
			.key = "\x01\x02\x03\x04\x05\x06\x07\x08\x00\x00\x00\x00\x00\x00\x00\x00",
			.pt = "\x01\x02\x03\x04\x05\x06\x07\x08",
			.ct = "\xFF\x78\x11\xE4\xB3\xA7\x2E\x71"
		}
	};

	return TEST(kripto_block_safer, vectors, 1) |
		TEST(kripto_block_safer_sk, sk_vectors, 2);
}
