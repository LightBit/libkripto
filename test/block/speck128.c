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
#include <kripto/block/speck128.h>

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
			.key = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F",
			.pt = "\x20\x6D\x61\x64\x65\x20\x69\x74\x20\x65\x71\x75\x69\x76\x61\x6C",
			.ct = "\x18\x0D\x57\x5C\xDF\xFE\x60\x78\x65\x32\x78\x79\x51\x98\x5D\xA6"
		},
		{
			.key_len = 24,
			.tweak_len = 0,
			.rounds = 0,
			.iterations = 1,
			.key = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17",
			.pt = "\x65\x6E\x74\x20\x74\x6F\x20\x43\x68\x69\x65\x66\x20\x48\x61\x72",
			.ct = "\x86\x18\x3C\xE0\x5D\x18\xBC\xF9\x66\x55\x13\x13\x3A\xCF\xE4\x1B"
		},
		{
			.key_len = 32,
			.tweak_len = 0,
			.rounds = 0,
			.iterations = 1,
			.key = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F",
			.pt = "\x70\x6F\x6F\x6E\x65\x72\x2E\x20\x49\x6E\x20\x74\x68\x6F\x73\x65",
			.ct = "\x43\x8F\x18\x9C\x8D\xB4\xEE\x4E\x3E\xF5\xC0\x05\x04\x01\x09\x41"
		}
	};

	return TEST(kripto_block_speck128, vectors, 3);
}
