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
#include <kripto/block/threefish256.h>

#include "test.h"

int main(void)
{
	const struct vector vectors[1] =
	{
		{
			.key_len = 32,
			.tweak_len = 16,
			.rounds = 0,
			.iterations = 1,
			.key = "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2A\x2B\x2C\x2D\x2E\x2F",
			.tweak = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F",
			.pt = "\xFF\xFE\xFD\xFC\xFB\xFA\xF9\xF8\xF7\xF6\xF5\xF4\xF3\xF2\xF1\xF0\xEF\xEE\xED\xEC\xEB\xEA\xE9\xE8\xE7\xE6\xE5\xE4\xE3\xE2\xE1\xE0",
			.ct = "\xE0\xD0\x91\xFF\x0E\xEA\x8F\xDF\xC9\x81\x92\xE6\x2E\xD8\x0A\xD5\x9D\x86\x5D\x08\x58\x8D\xF4\x76\x65\x70\x56\xB5\x95\x5E\x97\xDF"
		}
	};

	return TEST(kripto_block_threefish256, vectors, 1);
}
