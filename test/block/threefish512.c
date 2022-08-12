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
#include <kripto/block/threefish512.h>

#include "test.h"

int main(void)
{
	const struct vector vectors[1] =
	{
		{
			.key_len = 64,
			.tweak_len = 16,
			.rounds = 0,
			.iterations = 1,
			.key = "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2A\x2B\x2C\x2D\x2E\x2F\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3A\x3B\x3C\x3D\x3E\x3F\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4A\x4B\x4C\x4D\x4E\x4F",
			.tweak = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F",
			.pt = "\xFF\xFE\xFD\xFC\xFB\xFA\xF9\xF8\xF7\xF6\xF5\xF4\xF3\xF2\xF1\xF0\xEF\xEE\xED\xEC\xEB\xEA\xE9\xE8\xE7\xE6\xE5\xE4\xE3\xE2\xE1\xE0\xDF\xDE\xDD\xDC\xDB\xDA\xD9\xD8\xD7\xD6\xD5\xD4\xD3\xD2\xD1\xD0\xCF\xCE\xCD\xCC\xCB\xCA\xC9\xC8\xC7\xC6\xC5\xC4\xC3\xC2\xC1\xC0",
			.ct = "\x86\x9A\xE1\x22\x10\xE5\x1D\x3B\x07\x36\x39\x9F\x2A\xCB\x40\x0D\xE2\x30\x60\x0B\x13\xE6\x2F\x1D\xF7\x59\x6A\x14\x62\x32\xD2\x81\xDF\xBF\x12\x7A\x65\x57\x1B\x9A\x79\x89\x06\xC7\x19\x67\x83\x94\xC5\x0D\x99\x51\x38\xFD\x83\xF2\xBF\xA5\x4A\x3B\xC3\x50\xD2\xF0"
		}
	};

	return TEST(kripto_block_threefish512, vectors, 1);
}
