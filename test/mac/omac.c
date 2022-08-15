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

#include <kripto/mac.h>
#include <kripto/block.h>
#include <kripto/mac/omac.h>
#include <kripto/block/aes.h>
#include <kripto/block/des.h>

#include "test.h"

int main(void)
{
	const struct vector aes_vectors[4] =
	{
		{
			.message = "",
			.message_len = 0,
			.message_repeat = 1,
			.rounds = 0,
			.key = "\x2B\x7E\x15\x16\x28\xAE\xD2\xA6\xAB\xF7\x15\x88\x09\xCF\x4F\x3C",
			.key_len = 16,
			.tag = "\xBB\x1D\x69\x29\xE9\x59\x37\x28\x7F\xA3\x7D\x12\x9B\x75\x67\x46",
			.tag_len = 16
		},
		{
			.message = "\x6B\xC1\xBE\xE2\x2E\x40\x9F\x96\xE9\x3D\x7E\x11\x73\x93\x17\x2A",
			.message_len = 16,
			.message_repeat = 1,
			.rounds = 0,
			.key = "\x2B\x7E\x15\x16\x28\xAE\xD2\xA6\xAB\xF7\x15\x88\x09\xCF\x4F\x3C",
			.key_len = 16,
			.tag = "\x07\x0A\x16\xB4\x6B\x4D\x41\x44\xF7\x9B\xDD\x9D\xD0\x4A\x28\x7C",
			.tag_len = 16
		},
		{
			.message = "\x6B\xC1\xBE\xE2\x2E\x40\x9F\x96\xE9\x3D\x7E\x11\x73\x93\x17\x2A\xAE\x2D\x8A\x57\x1E\x03\xAC\x9C\x9E\xB7\x6F\xAC\x45\xAF\x8E\x51\x30\xC8\x1C\x46\xA3\x5C\xE4\x11",
			.message_len = 40,
			.message_repeat = 1,
			.rounds = 0,
			.key = "\x2B\x7E\x15\x16\x28\xAE\xD2\xA6\xAB\xF7\x15\x88\x09\xCF\x4F\x3C",
			.key_len = 16,
			.tag = "\xDF\xA6\x67\x47\xDE\x9A\xE6\x30\x30\xCA\x32\x61\x14\x97\xC8\x27",
			.tag_len = 16
		},
		{
			.message = "\x6B\xC1\xBE\xE2\x2E\x40\x9F\x96\xE9\x3D\x7E\x11\x73\x93\x17\x2A\xAE\x2D\x8A\x57\x1E\x03\xAC\x9C\x9E\xB7\x6F\xAC\x45\xAF\x8E\x51\x30\xC8\x1C\x46\xA3\x5C\xE4\x11\xE5\xFB\xC1\x19\x1A\x0A\x52\xEF\xF6\x9F\x24\x45\xDF\x4F\x9B\x17\xAD\x2B\x41\x7B\xE6\x6C\x37\x10",
			.message_len = 64,
			.message_repeat = 1,
			.rounds = 0,
			.key = "\x2B\x7E\x15\x16\x28\xAE\xD2\xA6\xAB\xF7\x15\x88\x09\xCF\x4F\x3C",
			.key_len = 16,
			.tag = "\x51\xF0\xBE\xBF\x7E\x3B\x9D\x92\xFC\x49\x74\x17\x79\x36\x3C\xFE",
			.tag_len = 16
		}
	};

	const struct vector des_vectors[2] =
	{
		{
			.message = "\xAD\xAF\x4B\xFF\xFA\xB7\x9F\xFB\x60\xB9\x46\x47\xFA\xAC\x63\x49\x29\xC5\x6E\x69\x40\x52\x88\x18\x81\xE6\x0B\x11\x49\xB6",
			.message_len = 30,
			.message_repeat = 1,
			.rounds = 0,
			.key = "\x62\x23\x25\x01\xB9\xE9\xC1\xB5\x54\x20\x9D\x7C\x07\x5D\x2C\x31\x73\xA2\xF2\x89\xA8\x4C\x49\xCE",
			.key_len = 24,
			.tag = "\xA0\x56\x74\xF2\xC9\x05\xD1\x53",
			.tag_len = 8
		},
		{
			.message = "",
			.message_len = 0,
			.message_repeat = 1,
			.rounds = 0,
			.key = "\xF8\xFB\xA7\xB9\xB3\xE9\xD6\x8A\x2F\x70\xBF\xD3\x04\xD3\x2A\x15\x9E\x13\x45\x3E\x0D\x16\x92\x8A",
			.key_len = 24,
			.tag = "\xEB\x61\x51\x5B",
			.tag_len = 4
		}
	};

	kripto_desc_mac *omac_aes = kripto_mac_omac(kripto_block_aes);
	TEST(omac_aes, aes_vectors, 4);
	free(omac_aes);

	kripto_desc_mac *omac_des = kripto_mac_omac(kripto_block_des);
	TEST(omac_des, des_vectors, 2);
	free(omac_des);

	return test_result;
}
