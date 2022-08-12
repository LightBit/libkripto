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
#include <kripto/block/seed.h>

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
			.key = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F",
			.pt = "\x4E\x5E\xB5\x14\x82\x1A\x9A\xA5\x60\xA7\xD4\xAB\x9A\x69\x22\x54",
			.ct = "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF"
		},
		{
			.key_len = 16,
			.tweak_len = 0,
			.rounds = 0,
			.iterations = 1,
			.key = "\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
			.pt = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
			.ct = "\x48\x30\x62\x6E\xF5\x7F\x09\x46\x65\x4E\x1C\xE4\xC2\xDD\xDC\x6F"
		},
		{
			.key_len = 16,
			.tweak_len = 0,
			.rounds = 0,
			.iterations = 1,
			.key = "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
			.pt = "\xAB\x76\xDD\xC0\xDA\xBE\xA4\x32\x8D\x50\x94\x36\xFD\x7F\x49\x88",
			.ct = "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"
		},
		{
			.key_len = 16,
			.tweak_len = 0,
			.rounds = 0,
			.iterations = 1000,
			.key = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x40",
			.pt = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
			.ct = "\x80\xF2\x21\x1F\xB2\x04\x41\x43\x87\x21\x7A\xAF\x1C\x47\xBA\xFC"
		}
	};

	return TEST(kripto_block_seed, vectors, 4);
}
