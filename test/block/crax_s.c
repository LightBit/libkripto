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
#include <kripto/block/crax_s.h>

#include "test.h"

int main(void)
{
	const struct vector vectors[1] =
	{
		{
			/* generated with reference code */
			.key_len = 16,
			.tweak_len = 0,
			.rounds = 0,
			.iterations = 1,
			.key = "\x85\xAE\x72\x42\x54\x90\xC6\xF9\xE0\xC1\xD0\x04\x2E\x38\x68\x02",
			.pt = "\x4D\x2E\x0B\xB6\xBB\xC6\x33\x2F",
			.ct = "\x00\x78\xB2\xCA\xF2\x40\x2F\xAF"
		}
	};

	return TEST(kripto_block_crax_s, vectors, 1);
}
