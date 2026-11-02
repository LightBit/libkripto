/*
 * Copyright (C) 2026 by Gregor Pintar <grpintar@gmail.com>
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
#include <kripto/stream/ecb.h>

#include "test.h"

int main(void)
{
	/*
	 * NIST SP 800-38A, F.1.1/F.1.2 ECB-AES128.
	 * https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
	 * ECB takes no IV; a multi-block message exercises the block loop.
	 */
	const struct vector aes_vectors[1] =
	{
		{
			.rounds = 0,
			.key = "\x2B\x7E\x15\x16\x28\xAE\xD2\xA6\xAB\xF7\x15\x88\x09\xCF\x4F\x3C",
			.key_len = 16,
			.iv = 0,
			.iv_len = 0,
			.pt = "\x6B\xC1\xBE\xE2\x2E\x40\x9F\x96\xE9\x3D\x7E\x11\x73\x93\x17\x2A"
				"\xAE\x2D\x8A\x57\x1E\x03\xAC\x9C\x9E\xB7\x6F\xAC\x45\xAF\x8E\x51"
				"\x30\xC8\x1C\x46\xA3\x5C\xE4\x11\xE5\xFB\xC1\x19\x1A\x0A\x52\xEF"
				"\xF6\x9F\x24\x45\xDF\x4F\x9B\x17\xAD\x2B\x41\x7B\xE6\x6C\x37\x10",
			.pt_len = 64,
			.ct = "\x3A\xD7\x7B\xB4\x0D\x7A\x36\x60\xA8\x9E\xCA\xF3\x24\x66\xEF\x97"
				"\xF5\xD3\xD5\x85\x03\xB9\x69\x9D\xE7\x85\x89\x5A\x96\xFD\xBA\xAF"
				"\x43\xB1\xCD\x7F\x59\x8E\xCE\x23\x88\x1B\x00\xE3\xED\x03\x06\x88"
				"\x7B\x0C\x78\x5E\x27\xE8\xAD\x3F\x82\x23\x20\x71\x04\x72\x5D\xD4",
			.ct_len = 64
		}
	};

	kripto_desc_stream *ecb_aes = kripto_stream_ecb(kripto_block_aes);
	TEST(ecb_aes, aes_vectors, 1);
	free(ecb_aes);

	return test_result;
}
