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
#include <kripto/stream/cfb.h>

#include "test.h"

int main(void)
{
	/*
	 * NIST SP 800-38A, F.3.13/F.3.14 CFB128-AES128.
	 * https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
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
			.ct = "\x3B\x3F\xD9\x2E\xB7\x2D\xAD\x20\x33\x34\x49\xF8\xE8\x3C\xFB\x4A"
				"\xC8\xA6\x45\x37\xA0\xB3\xA9\x3F\xCD\xE3\xCD\xAD\x9F\x1C\xE5\x8B"
				"\x26\x75\x1F\x67\xA3\xCB\xB1\x40\xB1\x80\x8C\xF1\x87\xA4\xF4\xDF"
				"\xC0\x4B\x05\x35\x7C\x5D\x1C\x0E\xEA\xC4\xC6\x6F\x9F\xF7\xF2\xE6",
			.ct_len = 64
		}
	};

	kripto_desc_stream *cfb_aes = kripto_stream_cfb(kripto_block_aes);
	TEST(cfb_aes, aes_vectors, 1);
	free(cfb_aes);

	return test_result;
}
