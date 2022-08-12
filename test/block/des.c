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
#include <kripto/block/des.h>

#include "test.h"

int main(void)
{
	const struct vector vectors[6] =
	{
		{
			.key_len = 8,
			.tweak_len = 0,
			.rounds = 0,
			.iterations = 1000,
			.key = "\x00\x01\x02\x03\x04\x05\x06\x07",
			.pt = "\x00\x11\x22\x33\x44\x55\x66\x77",
			.ct = "\x12\x53\x5C\xB0\xF7\x7E\xE7\x7C"
		},
		{
			.key_len = 8,
			.tweak_len = 0,
			.rounds = 0,
			.iterations = 1,
			.key = "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
			.pt = "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
			.ct = "\x73\x59\xB2\x16\x3E\x4E\xDC\x58"
		},
		{
			.key_len = 16,
			.tweak_len = 0,
			.rounds = 0,
			.iterations = 1000,
			.key = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F",
			.pt = "\x00\x11\x22\x33\x44\x55\x66\x77",
			.ct = "\x04\xF4\x03\x2E\xDB\xF3\xA8\x2E"
		},
		{
			.key_len = 16,
			.tweak_len = 0,
			.rounds = 0,
			.iterations = 1,
			.key = "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
			.pt = "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
			.ct = "\x73\x59\xB2\x16\x3E\x4E\xDC\x58"
		},
		{
			.key_len = 24,
			.tweak_len = 0,
			.rounds = 0,
			.iterations = 1000,
			.key = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17",
			.pt = "\x00\x11\x22\x33\x44\x55\x66\x77",
			.ct = "\xE3\x59\x81\x76\x85\x0E\x73\x6F"
		},
		{
			.key_len = 24,
			.tweak_len = 0,
			.rounds = 0,
			.iterations = 1,
			.key = "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
			.pt = "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
			.ct = "\x73\x59\xB2\x16\x3E\x4E\xDC\x58"
		}
	};

	return TEST(kripto_block_des, vectors, 6);
}
