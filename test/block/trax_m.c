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
#include <kripto/block/trax_m.h>

#include "test.h"

int main(void)
{
	const struct vector vectors[1] =
	{
		{
			/* self generated */
			.key_len = 16,
			.tweak_len = 8,
			.rounds = 0,
			.iterations = 1,
			.key = "\xDF\x63\x98\x04\x13\x2F\xCC\xAE\x5E\xA5\xCE\xD2\x9C\xDB\xA8\x6D",
			.tweak = "\x44\x11\x30\x12\xF3\x73\xC1\xAC",
			.pt = "\xC9\x99\x2F\x80\x38\x62\x3E\x86\xBA\xF8\xE5\x46\x79\xC6\xDB\x90",
			.ct = "\x73\x8F\x76\x7F\xE3\x20\xD4\x17\xC1\x6B\x86\x73\x15\x9A\x6D\xAE"
		}
	};

	return TEST(kripto_block_trax_m, vectors, 1);
}
