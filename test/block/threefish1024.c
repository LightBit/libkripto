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
#include <kripto/block/threefish1024.h>

#include "test.h"

int main(void)
{
	const struct vector vectors[1] =
	{
		{
			.key_len = 128,
			.tweak_len = 16,
			.rounds = 0,
			.iterations = 1,
			.key = "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2A\x2B\x2C\x2D\x2E\x2F\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3A\x3B\x3C\x3D\x3E\x3F\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4A\x4B\x4C\x4D\x4E\x4F\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5A\x5B\x5C\x5D\x5E\x5F\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6A\x6B\x6C\x6D\x6E\x6F\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7A\x7B\x7C\x7D\x7E\x7F\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8A\x8B\x8C\x8D\x8E\x8F",
			.tweak = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F",
			.pt = "\xFF\xFE\xFD\xFC\xFB\xFA\xF9\xF8\xF7\xF6\xF5\xF4\xF3\xF2\xF1\xF0\xEF\xEE\xED\xEC\xEB\xEA\xE9\xE8\xE7\xE6\xE5\xE4\xE3\xE2\xE1\xE0\xDF\xDE\xDD\xDC\xDB\xDA\xD9\xD8\xD7\xD6\xD5\xD4\xD3\xD2\xD1\xD0\xCF\xCE\xCD\xCC\xCB\xCA\xC9\xC8\xC7\xC6\xC5\xC4\xC3\xC2\xC1\xC0\xBF\xBE\xBD\xBC\xBB\xBA\xB9\xB8\xB7\xB6\xB5\xB4\xB3\xB2\xB1\xB0\xAF\xAE\xAD\xAC\xAB\xAA\xA9\xA8\xA7\xA6\xA5\xA4\xA3\xA2\xA1\xA0\x9F\x9E\x9D\x9C\x9B\x9A\x99\x98\x97\x96\x95\x94\x93\x92\x91\x90\x8F\x8E\x8D\x8C\x8B\x8A\x89\x88\x87\x86\x85\x84\x83\x82\x81\x80",
			.ct = "\x44\xE6\x6B\x31\x25\xAA\x43\x42\x61\xAD\xBE\xF4\xC3\x10\x10\x1C\xEF\x1D\x18\x52\x72\xB4\x31\x32\xD6\xE6\x7E\x75\x69\x2B\x28\x51\xA7\xE3\xAC\xF8\xDF\xD3\xD6\xC6\xDF\xEA\x27\x24\x15\x0D\x28\x7E\x8C\x2B\xAB\xFF\x27\xE9\x71\xFA\xC1\x63\x78\x1B\xE1\x81\xF2\xBF\x57\x2A\xB8\x48\x62\x25\x9E\xF8\xFA\x62\x8A\x77\xA6\x1D\x12\x8F\x2F\x15\x17\xBD\x51\x85\x92\xFE\x93\x82\xFF\x67\x0D\x84\x8A\xDA\xB3\x15\x82\xDC\xCF\x36\xC2\xC6\x07\x15\x3A\xAE\x34\xA2\x85\x3F\xF0\xC1\x4C\xF4\x62\xC9\x03\xCC\x28\x60\x73\x4A\xE5\x0C\x04\xB1"
		}
	};

	return TEST(kripto_block_threefish1024, vectors, 1);
}
