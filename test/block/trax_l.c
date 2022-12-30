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
#include <kripto/block/trax_l.h>

#include "test.h"

int main(void)
{
	const struct vector vectors[1] =
	{
		{
			/* generated with reference code */
			.key_len = 32,
			.tweak_len = 16,
			.rounds = 0,
			.iterations = 1,
			.key = "\xDF\x63\x98\x04\x13\x2F\xCC\xAE\x5E\xA5\xCE\xD2\x9C\xDB\xA8\x6D\xE5\xFD\xF0\x50\x4B\x2C\xF0\x5F\x56\x80\x8B\x95\xD4\xD8\xCA\x96",
			.tweak = "\x44\x11\x30\x12\xF3\x73\xC1\xAC\xEB\x9C\xED\x50\xEB\xD4\xF0\x31",
			.pt = "\xC9\x99\x2F\x80\x38\x62\x3E\x86\xBA\xF8\xE5\x46\x79\xC6\xDB\x90\x25\xD3\x85\x89\xE4\xDC\x47\x98\x6B\xE9\x0B\xB8\x39\x0B\x5D\xD0",
			.ct = "\x6E\x60\xA4\x04\x84\x5F\x39\x26\x24\x91\x2B\x84\x2F\xF3\xAD\x8E\x05\xCB\x37\x9B\xEB\x55\x7B\x9F\x90\xAA\x99\xC6\x48\x5F\xCE\x3B"
		}
	};

	return TEST(kripto_block_trax_l, vectors, 1);
}
