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
#include <kripto/mac/xcbc.h>
#include <kripto/block/aes.h>

#include "test.h"

int main(void)
{
	const struct vector aes_vectors[7] =
	{
		{
			.message = "",
			.message_len = 0,
			.message_repeat = 1,
			.rounds = 0,
			.key = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F",
			.key_len = 16,
			.tag = "\x75\xF0\x25\x1D\x52\x8A\xC0\x1C\x45\x73\xDF\xD5\x84\xD7\x9F\x29",
			.tag_len = 16
		},
		{
			.message = "\x00\x01\x02",
			.message_len = 3,
			.message_repeat = 1,
			.rounds = 0,
			.key = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F",
			.key_len = 16,
			.tag = "\x5B\x37\x65\x80\xAE\x2F\x19\xAF\xE7\x21\x9C\xEE",
			.tag_len = 12
		},
		{
			.message = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F",
			.message_len = 16,
			.message_repeat = 1,
			.rounds = 0,
			.key = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F",
			.key_len = 16,
			.tag = "\xD2\xA2\x46\xFA\x34\x9B\x68\xA7\x99\x98\xA4\x39\x4F\xF7\xA2\x63",
			.tag_len = 16
		},
		{
			.message = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13",
			.message_len = 20,
			.message_repeat = 1,
			.rounds = 0,
			.key = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F",
			.key_len = 16,
			.tag = "\x47\xF5\x1B\x45\x64\x96\x62\x15\xB8\x98\x5C\x63\x05\x5E\xD3\x08",
			.tag_len = 16
		},
		{
			.message = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F",
			.message_len = 32,
			.message_repeat = 1,
			.rounds = 0,
			.key = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F",
			.key_len = 16,
			.tag = "\xF5\x4F\x0E\xC8\xD2\xB9\xF3\xD3\x68\x07\x73\x4B\xD5\x28\x3F\xD4",
			.tag_len = 16
		},
		{
			.message = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F\x20\x21",
			.message_len = 34,
			.message_repeat = 1,
			.rounds = 0,
			.key = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F",
			.key_len = 16,
			.tag = "\xBE\xCB\xB3\xBC\xCD\xB5\x18\xA3\x06\x77\xD5\x48\x1F\xB6\xB4\xD8",
			.tag_len = 16
		},
		{
			.message = "\x00",
			.message_len = 1,
			.message_repeat = 1000,
			.rounds = 0,
			.key = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F",
			.key_len = 16,
			.tag = "\xF0\xDA\xFE\xE8\x95\xDB\x30\x25\x37\x61\x10\x3B\x5D\x84\x52\x8F",
			.tag_len = 16
		}
	};

	kripto_desc_mac *xcbc_aes = kripto_mac_xcbc(kripto_block_aes);
	TEST(xcbc_aes, aes_vectors, 7);
	free(xcbc_aes);

	return test_result;
}
