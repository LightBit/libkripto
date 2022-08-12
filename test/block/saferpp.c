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
#include <kripto/block/saferpp.h>

#include "test.h"

int main(void)
{
	const struct vector vectors[4] =
	{
		{
			.key_len = 16,
			.tweak_len = 0,
			.rounds = 0,
			.iterations = 1000,
			.key = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F",
			.pt = "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF",
			.ct = "\x13\x82\x2B\x35\x73\x34\x20\xA1\x59\x32\x6A\x10\xB5\xEF\xE9\x5A"
		},
		{
			.key_len = 16,
			.tweak_len = 0,
			.rounds = 0,
			.iterations = 1,
			.key = "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
			.pt = "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
			.ct = "\x30\x2B\xBA\x91\x56\xBB\xCB\x2B\xF6\xD9\xC7\xC0\x70\x86\xFB\x4D"
		},
		{
			.key_len = 32,
			.tweak_len = 0,
			.rounds = 0,
			.iterations = 1000,
			.key = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F",
			.pt = "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF",
			.ct = "\x87\x79\x4A\x45\x29\x95\xEB\x74\xF7\x27\xE0\xE8\xDA\xD1\xD7\x96"
		},
		{
			.key_len = 32,
			.tweak_len = 0,
			.rounds = 0,
			.iterations = 1,
			.key = "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
			.pt = "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
			.ct = "\x64\x21\xD4\x84\xEB\x3A\xF1\x8F\x71\xA6\xF2\xCD\x1B\x07\x00\x3B"
		}
	};

	return TEST(kripto_block_saferpp, vectors, 4);
}
