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

#include <kripto/block.h>
#include <kripto/block/noekeon.h>

#include "test.h"

int main(void)
{
	const struct vector vectors[4] =
	{
		{
			.key_len = 16,
			.tweak_len = 0,
			.rounds = 0,
			.iterations = 1,
			.key = "\x2B\xD6\x45\x9F\x82\xC5\xB3\x00\x95\x2C\x49\x10\x48\x81\xFF\x48",
			.pt = "\x47\x65\xF3\xDA\x10\xCD\x3D\x04\x73\x86\x77\x42\xB5\xE5\xCC\x3C",
			.ct = "\xEA\x02\x47\x14\xAD\x5C\x4D\x84\xEA\x02\x47\x14\xAD\x5C\x4D\x84"
		},
		{
			.key_len = 16,
			.tweak_len = 0,
			.rounds = 0,
			.iterations = 1,
			.key = "\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
			.pt = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
			.ct = "\xEA\x65\x52\xBA\x79\x35\x46\xC2\x61\xE4\xB3\xE9\x04\x33\xF5\xA2"
		},
		{
			.key_len = 16,
			.tweak_len = 0,
			.rounds = 0,
			.iterations = 1,
			.key = "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
			.pt = "\x45\xE2\x70\x43\x4B\xB9\x92\xB5\x2C\xD8\xBF\xE5\x64\xB7\xE7\xD7",
			.ct = "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"
		},
		{
			.key_len = 16,
			.tweak_len = 0,
			.rounds = 0,
			.iterations = 1000,
			.key = "\x00\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00",
			.pt = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
			.ct = "\x51\x78\x6E\xC1\x49\x29\x20\xDE\x80\x5B\x4A\x20\xB7\x3E\x8E\x3F"
		}
	};

	return TEST(kripto_block_noekeon, vectors, 4);
}
