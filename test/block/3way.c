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
#include <kripto/block/3way.h>

#include "test.h"

int main(void)
{
	const struct vector vectors[1] =
	{
		{
			.key_len = 12,
			.tweak_len = 0,
			.rounds = 0,
			.iterations = 1,
			.key = "\xD2\xF0\x5B\x5E\xD6\x14\x41\x38\xCA\xB9\x20\xCD",
			.pt = "\x40\x59\xC7\x6E\x83\xAE\x9D\xC4\xAD\x21\xEC\xF7",
			.ct = "\x47\x8E\xA8\x71\x6B\x13\xF1\x7C\x15\xB1\x55\xED"
		}
	};

	return TEST(kripto_block_3way, vectors, 1);
}
