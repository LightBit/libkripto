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
#include <kripto/block/twofish.h>

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
			.key = "\x9F\x58\x9F\x5C\xF6\x12\x2C\x32\xB6\xBF\xEC\x2F\x2A\xE8\xC3\x5A",
			.pt = "\xD4\x91\xDB\x16\xE7\xB1\xC3\x9E\x86\xCB\x08\x6B\x78\x9F\x54\x19",
			.ct = "\x01\x9F\x98\x09\xDE\x17\x11\x85\x8F\xAA\xC3\xA3\xBA\x20\xFB\xC3"
		},
		{
			.key_len = 24,
			.tweak_len = 0,
			.rounds = 0,
			.iterations = 1,
			.key = "\x88\xB2\xB2\x70\x6B\x10\x5E\x36\xB4\x46\xBB\x6D\x73\x1A\x1E\x88\xEF\xA7\x1F\x78\x89\x65\xBD\x44",
			.pt = "\x39\xDA\x69\xD6\xBA\x49\x97\xD5\x85\xB6\xDC\x07\x3C\xA3\x41\xB2",
			.ct = "\x18\x2B\x02\xD8\x14\x97\xEA\x45\xF9\xDA\xAC\xDC\x29\x19\x3A\x65"
		},
		{
			.key_len = 32,
			.tweak_len = 0,
			.rounds = 0,
			.iterations = 1,
			.key = "\xD4\x3B\xB7\x55\x6E\xA3\x2E\x46\xF2\xA2\x82\xB7\xD4\x5B\x4E\x0D\x57\xFF\x73\x9D\x4D\xC9\x2C\x1B\xD7\xFC\x01\x70\x0C\xC8\x21\x6F",
			.pt = "\x90\xAF\xE9\x1B\xB2\x88\x54\x4F\x2C\x32\xDC\x23\x9B\x26\x35\xE6",
			.ct = "\x6C\xB4\x56\x1C\x40\xBF\x0A\x97\x05\x93\x1C\xB6\xD4\x08\xE7\xFA"
		}
	};

	return TEST(kripto_block_twofish, vectors, 3);
}
