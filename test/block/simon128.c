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
#include <kripto/block/simon128.h>

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
			.pt = "\x20\x74\x72\x61\x76\x65\x6C\x6C\x65\x72\x73\x20\x64\x65\x73\x63",
			.ct = "\xBC\x0B\x4E\xF8\x2A\x83\xAA\x65\x3F\xFE\x54\x1E\x1E\x1B\x68\x49"
		},
		{
			.key_len = 24,
			.tweak_len = 0,
			.rounds = 0,
			.iterations = 1,
			.key = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17",
			.pt = "\x72\x69\x62\x65\x20\x77\x68\x65\x6E\x20\x74\x68\x65\x72\x65\x20",
			.ct = "\x5B\xB8\x97\x25\x6E\x8D\x9C\x6C\x4F\x0D\xDC\xFC\xEF\x61\xAC\xC4"
		},
		{
			.key_len = 32,
			.tweak_len = 0,
			.rounds = 0,
			.iterations = 1,
			.key = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F",
			.pt = "\x69\x73\x20\x61\x20\x73\x69\x6D\x6F\x6F\x6D\x20\x69\x6E\x20\x74",
			.ct = "\x68\xB8\xE7\xEF\x87\x2A\xF7\x3B\xA0\xA3\xC8\xAF\x79\x55\x2B\x8D"
		}
	};

	return TEST(kripto_block_simon128, vectors, 3);
}
