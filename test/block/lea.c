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
#include <kripto/block/lea.h>

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
			.key = "\x0F\x1E\x2D\x3C\x4B\x5A\x69\x78\x87\x96\xA5\xB4\xC3\xD2\xE1\xF0",
			.pt = "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F",
			.ct = "\x9F\xC8\x4E\x35\x28\xC6\xC6\x18\x55\x32\xC7\xA7\x04\x64\x8B\xFD"
		},
		{
			.key_len = 24,
			.tweak_len = 0,
			.rounds = 0,
			.iterations = 1,
			.key = "\x0F\x1E\x2D\x3C\x4B\x5A\x69\x78\x87\x96\xA5\xB4\xC3\xD2\xE1\xF0\xF0\xE1\xD2\xC3\xB4\xA5\x96\x87",
			.pt = "\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2A\x2B\x2C\x2D\x2E\x2F",
			.ct = "\x6F\xB9\x5E\x32\x5A\xAD\x1B\x87\x8C\xDC\xF5\x35\x76\x74\xC6\xF2"
		},
		{
			.key_len = 32,
			.tweak_len = 0,
			.rounds = 0,
			.iterations = 1,
			.key = "\x0F\x1E\x2D\x3C\x4B\x5A\x69\x78\x87\x96\xA5\xB4\xC3\xD2\xE1\xF0\xF0\xE1\xD2\xC3\xB4\xA5\x96\x87\x78\x69\x5A\x4B\x3C\x2D\x1E\x0F",
			.pt = "\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3A\x3B\x3C\x3D\x3E\x3F",
			.ct = "\xD6\x51\xAF\xF6\x47\xB1\x89\xC1\x3A\x89\x00\xCA\x27\xF9\xE1\x97"
		}
	};

	return TEST(kripto_block_lea, vectors, 3);
}
