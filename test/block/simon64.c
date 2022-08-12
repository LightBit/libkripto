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
#include <kripto/block/simon64.h>

#include "test.h"

int main(void)
{
	const struct vector vectors[2] =
	{
		{
			.key_len = 12,
			.tweak_len = 0,
			.rounds = 0,
			.iterations = 1,
			.key = "\x00\x01\x02\x03\x08\x09\x0A\x0B\x10\x11\x12\x13",
			.pt = "\x63\x6C\x69\x6E\x67\x20\x72\x6F",
			.ct = "\xC8\x8F\x1A\x11\x7F\xE2\xA2\x5C"
		},
		{
			.key_len = 16,
			.tweak_len = 0,
			.rounds = 0,
			.iterations = 1,
			.key = "\x00\x01\x02\x03\x08\x09\x0A\x0B\x10\x11\x12\x13\x18\x19\x1A\x1B",
			.pt = "\x75\x6E\x64\x20\x6C\x69\x6B\x65",
			.ct = "\x7A\xA0\xDF\xB9\x20\xFC\xC8\x44"
		}
	};

	return TEST(kripto_block_simon64, vectors, 2);
}
