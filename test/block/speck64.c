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
#include <kripto/block/speck64.h>

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
			.pt = "\x65\x61\x6E\x73\x20\x46\x61\x74",
			.ct = "\x6C\x94\x75\x41\xEC\x52\x79\x9F"
		},
		{
			.key_len = 16,
			.tweak_len = 0,
			.rounds = 0,
			.iterations = 1,
			.key = "\x00\x01\x02\x03\x08\x09\x0A\x0B\x10\x11\x12\x13\x18\x19\x1A\x1B",
			.pt = "\x2D\x43\x75\x74\x74\x65\x72\x3B",
			.ct = "\x8B\x02\x4E\x45\x48\xA5\x6F\x8C"
		}
	};

	return TEST(kripto_block_speck64, vectors, 2);
}
