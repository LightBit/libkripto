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
#include <kripto/block/aes.h>
#include <kripto/stream.h>
#include <kripto/stream/ctr.h>

#include "test.h"

int main(void)
{
	/* https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf */
	const struct vector aes_vectors[2] =
	{
		{
			.rounds = 0,
			.key = "\x2B\x7E\x15\x16\x28\xAE\xD2\xA6\xAB\xF7\x15\x88\x09\xCF\x4F\x3C",
			.key_len = 16,
			.iv = "\xF0\xF1\xF2\xF3\xF4\xF5\xF6\xF7\xF8\xF9\xFA\xFB\xFC\xFD\xFE\xFF",
			.iv_len = 16,
			.pt = "\x6B\xC1\xBE\xE2\x2E\x40\x9F\x96\xE9\x3D\x7E\x11\x73\x93\x17\x2A",
			.pt_len = 16,
			.ct = "\x87\x4D\x61\x91\xB6\x20\xE3\x26\x1B\xEF\x68\x64\x99\x0D\xB6\xCE",
			.ct_len = 16
		},
		{
			.rounds = 0,
			.key = "\x2B\x7E\x15\x16\x28\xAE\xD2\xA6\xAB\xF7\x15\x88\x09\xCF\x4F\x3C",
			.key_len = 16,
			.iv = "\xF0\xF1\xF2\xF3\xF4\xF5\xF6\xF7\xF8\xF9\xFA\xFB\xFC\xFD\xFE\xFF",
			.iv_len = 16,
			.pt = "\x6B\xC1\xBE\xE2\x2E\x40\x9F\x96\xE9\x3D\x7E\x11\x73\x93\x17\x2A\xAE\x2D\x8A\x57\x1E\x03\xAC\x9C\x9E\xB7\x6F\xAC\x45\xAF\x8E\x51\x30\xC8\x1C\x46\xA3\x5C\xE4\x11\xE5\xFB\xC1\x19\x1A\x0A\x52\xEF\xF6\x9F\x24\x45\xDF\x4F\x9B\x17\xAD\x2B\x41\x7B\xE6\x6C",
			.pt_len = 62,
			.ct = "\x87\x4D\x61\x91\xB6\x20\xE3\x26\x1B\xEF\x68\x64\x99\x0D\xB6\xCE\x98\x06\xF6\x6B\x79\x70\xFD\xFF\x86\x17\x18\x7B\xB9\xFF\xFD\xFF\x5A\xE4\xDF\x3E\xDB\xD5\xD3\x5E\x5B\x4F\x09\x02\x0D\xB0\x3E\xAB\x1E\x03\x1D\xDA\x2F\xBE\x03\xD1\x79\x21\x70\xA0\xF3\x00",
			.ct_len = 62
		}
	};

	kripto_desc_stream *ctr_aes = kripto_stream_ctr(kripto_block_aes);
	TEST(ctr_aes, aes_vectors, 2);
	free(ctr_aes);

	return test_result;
}
