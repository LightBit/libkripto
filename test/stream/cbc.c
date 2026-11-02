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
#include <kripto/stream/cbc.h>

#include "test.h"

int main(void)
{
	/*
	 * NIST SP 800-38A, F.2.1/F.2.2 CBC-AES128.
	 * https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
	 * Full 4-block message in one call exercises the chaining across blocks.
	 */
	const struct vector aes_vectors[1] =
	{
		{
			.rounds = 0,
			.key = "\x2B\x7E\x15\x16\x28\xAE\xD2\xA6\xAB\xF7\x15\x88\x09\xCF\x4F\x3C",
			.key_len = 16,
			.iv = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F",
			.iv_len = 16,
			.pt = "\x6B\xC1\xBE\xE2\x2E\x40\x9F\x96\xE9\x3D\x7E\x11\x73\x93\x17\x2A"
				"\xAE\x2D\x8A\x57\x1E\x03\xAC\x9C\x9E\xB7\x6F\xAC\x45\xAF\x8E\x51"
				"\x30\xC8\x1C\x46\xA3\x5C\xE4\x11\xE5\xFB\xC1\x19\x1A\x0A\x52\xEF"
				"\xF6\x9F\x24\x45\xDF\x4F\x9B\x17\xAD\x2B\x41\x7B\xE6\x6C\x37\x10",
			.pt_len = 64,
			.ct = "\x76\x49\xAB\xAC\x81\x19\xB2\x46\xCE\xE9\x8E\x9B\x12\xE9\x19\x7D"
				"\x50\x86\xCB\x9B\x50\x72\x19\xEE\x95\xDB\x11\x3A\x91\x76\x78\xB2"
				"\x73\xBE\xD6\xB8\xE3\xC1\x74\x3B\x71\x16\xE6\x9E\x22\x22\x95\x16"
				"\x3F\xF1\xCA\xA1\x68\x1F\xAC\x09\x12\x0E\xCA\x30\x75\x86\xE1\xA7",
			.ct_len = 64
		}
	};

	kripto_desc_stream *cbc_aes = kripto_stream_cbc(kripto_block_aes);
	TEST(cbc_aes, aes_vectors, 1);
	free(cbc_aes);

	return test_result;
}
