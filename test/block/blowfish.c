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
#include <kripto/block/blowfish.h>

#include "test.h"

int main(void)
{
	const struct vector vectors[3] =
	{
		{
			.key_len = 24,
			.tweak_len = 0,
			.rounds = 0,
			.iterations = 1,
			.key = "\xF0\xE1\xD2\xC3\xB4\xA5\x96\x87\x78\x69\x5A\x4B\x3C\x2D\x1E\x0F\x00\x11\x22\x33\x44\x55\x66\x77",
			.pt = "\xFE\xDC\xBA\x98\x76\x54\x32\x10",
			.ct = "\x05\x04\x4B\x62\xFA\x52\xD0\x80"
		},
		{
			.key_len = 8,
			.tweak_len = 0,
			.rounds = 0,
			.iterations = 1,
			.key = "\x01\x23\x45\x67\x89\xAB\xCD\xEF",
			.pt = "\x11\x11\x11\x11\x11\x11\x11\x11",
			.ct = "\x61\xF9\xC3\x80\x22\x81\xB0\x96"
		},
		{
			.key_len = 8,
			.tweak_len = 0,
			.rounds = 0,
			.iterations = 1,
			.key = "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
			.pt = "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
			.ct = "\x51\x86\x6F\xD5\xB8\x5E\xCB\x8A"
		}
	};

	return TEST(kripto_block_blowfish, vectors, 3);
}
