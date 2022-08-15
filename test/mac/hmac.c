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
#include <kripto/hash.h>
#include <kripto/mac/hmac.h>
#include <kripto/hash/md5.h>
#include <kripto/hash/sha1.h>
#include <kripto/hash/sha2_256.h>
#include <kripto/hash/sha2_512.h>

#include "test.h"

int main(void)
{
	const struct vector md5_vectors[3] =
	{
		{
			.message = "what do ya want for nothing?",
			.message_len = 28,
			.message_repeat = 1,
			.rounds = 0,
			.key = "Jefe",
			.key_len = 4,
			.tag = "\x75\x0C\x78\x3E\x6A\xB0\xB5\x03\xEA\xA8\x6E\x31\x0A\x5D\xB7\x38",
			.tag_len = 16
		},
		{
			.message = "\xCD",
			.message_len = 1,
			.message_repeat = 50,
			.rounds = 0,
			.key = "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19",
			.key_len = 25,
			.tag = "\x69\x7E\xAF\x0A\xCA\x3A\x3A\xEA\x3A\x75\x16\x47\x46\xFF\xAA\x79",
			.tag_len = 16
		},
		{
			.message = "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data",
			.message_len = 73,
			.message_repeat = 1,
			.rounds = 0,
			.key = "\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA",
			.key_len = 80,
			.tag = "\x6F\x63\x0F\xAD\x67\xCD\xA0\xEE\x1F\xB1\xF5\x62\xDB\x3A\xA5\x3E",
			.tag_len = 16
		}
	};

	const struct vector sha1_vectors[3] =
	{
		{
			.message = "what do ya want for nothing?",
			.message_len = 28,
			.message_repeat = 1,
			.rounds = 0,
			.key = "Jefe",
			.key_len = 4,
			.tag = "\xEF\xFC\xDF\x6A\xE5\xEB\x2F\xA2\xD2\x74\x16\xD5\xF1\x84\xDF\x9C\x25\x9A\x7C\x79",
			.tag_len = 20
		},
		{
			.message = "\xCD",
			.message_len = 1,
			.message_repeat = 50,
			.rounds = 0,
			.key = "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19",
			.key_len = 25,
			.tag = "\x4C\x90\x07\xF4\x02\x62\x50\xC6\xBC\x84\x14\xF9\xBF\x50\xC8\x6C\x2D\x72\x35\xDA",
			.tag_len = 20
		},
		{
			.message = "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data",
			.message_len = 73,
			.message_repeat = 1,
			.rounds = 0,
			.key = "\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA",
			.key_len = 80,
			.tag = "\xE8\xE9\x9D\x0F\x45\x23\x7D\x78\x6D\x6B\xBA\xA7\x96\x5C\x78\x08\xBB\xFF\x1A\x91",
			.tag_len = 20
		}
	};

	const struct vector sha2_256_vectors[4] =
	{
		{
			.message = "what do ya want for nothing?",
			.message_len = 28,
			.message_repeat = 1,
			.rounds = 0,
			.key = "Jefe",
			.key_len = 4,
			.tag = "\xA3\x0E\x01\x09\x8B\xC6\xDB\xBF\x45\x69\x0F\x3A\x7E\x9E\x6D\x0F\x8B\xBE\xA2\xA3\x9E\x61\x48\x00\x8F\xD0\x5E\x44",
			.tag_len = 28
		},
		{
			.message = "\xCD",
			.message_len = 1,
			.message_repeat = 50,
			.rounds = 0,
			.key = "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19",
			.key_len = 25,
			.tag = "\x6C\x11\x50\x68\x74\x01\x3C\xAC\x6A\x2A\xBC\x1B\xB3\x82\x62\x7C\xEC\x6A\x90\xD8\x6E\xFC\x01\x2D\xE7\xAF\xEC\x5A",
			.tag_len = 28
		},
		{
			.message = "what do ya want for nothing?",
			.message_len = 28,
			.message_repeat = 1,
			.rounds = 0,
			.key = "Jefe",
			.key_len = 4,
			.tag = "\x5B\xDC\xC1\x46\xBF\x60\x75\x4E\x6A\x04\x24\x26\x08\x95\x75\xC7\x5A\x00\x3F\x08\x9D\x27\x39\x83\x9D\xEC\x58\xB9\x64\xEC\x38\x43",
			.tag_len = 32
		},
		{
			.message = "\xCD",
			.message_len = 1,
			.message_repeat = 50,
			.rounds = 0,
			.key = "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19",
			.key_len = 25,
			.tag = "\x82\x55\x8A\x38\x9A\x44\x3C\x0E\xA4\xCC\x81\x98\x99\xF2\x08\x3A\x85\xF0\xFA\xA3\xE5\x78\xF8\x07\x7A\x2E\x3F\xF4\x67\x29\x66\x5B",
			.tag_len = 32
		}
	};

	const struct vector sha2_512_vectors[4] =
	{
		{
			.message = "what do ya want for nothing?",
			.message_len = 28,
			.message_repeat = 1,
			.rounds = 0,
			.key = "Jefe",
			.key_len = 4,
			.tag = "\xAF\x45\xD2\xE3\x76\x48\x40\x31\x61\x7F\x78\xD2\xB5\x8A\x6B\x1B\x9C\x7E\xF4\x64\xF5\xA0\x1B\x47\xE4\x2E\xC3\x73\x63\x22\x44\x5E\x8E\x22\x40\xCA\x5E\x69\xE2\xC7\x8B\x32\x39\xEC\xFA\xB2\x16\x49",
			.tag_len = 48
		},
		{
			.message = "\xCD",
			.message_len = 1,
			.message_repeat = 50,
			.rounds = 0,
			.key = "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19",
			.key_len = 25,
			.tag = "\x3E\x8A\x69\xB7\x78\x3C\x25\x85\x19\x33\xAB\x62\x90\xAF\x6C\xA7\x7A\x99\x81\x48\x08\x50\x00\x9C\xC5\x57\x7C\x6E\x1F\x57\x3B\x4E\x68\x01\xDD\x23\xC4\xA7\xD6\x79\xCC\xF8\xA3\x86\xC6\x74\xCF\xFB",
			.tag_len = 48
		},
		{
			.message = "what do ya want for nothing?",
			.message_len = 28,
			.message_repeat = 1,
			.rounds = 0,
			.key = "Jefe",
			.key_len = 4,
			.tag = "\x16\x4B\x7A\x7B\xFC\xF8\x19\xE2\xE3\x95\xFB\xE7\x3B\x56\xE0\xA3\x87\xBD\x64\x22\x2E\x83\x1F\xD6\x10\x27\x0C\xD7\xEA\x25\x05\x54\x97\x58\xBF\x75\xC0\x5A\x99\x4A\x6D\x03\x4F\x65\xF8\xF0\xE6\xFD\xCA\xEA\xB1\xA3\x4D\x4A\x6B\x4B\x63\x6E\x07\x0A\x38\xBC\xE7\x37",
			.tag_len = 64
		},
		{
			.message = "\xCD",
			.message_len = 1,
			.message_repeat = 50,
			.rounds = 0,
			.key = "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19",
			.key_len = 25,
			.tag = "\xB0\xBA\x46\x56\x37\x45\x8C\x69\x90\xE5\xA8\xC5\xF6\x1D\x4A\xF7\xE5\x76\xD9\x7F\xF9\x4B\x87\x2D\xE7\x6F\x80\x50\x36\x1E\xE3\xDB\xA9\x1C\xA5\xC1\x1A\xA2\x5E\xB4\xD6\x79\x27\x5C\xC5\x78\x80\x63\xA5\xF1\x97\x41\x12\x0C\x4F\x2D\xE2\xAD\xEB\xEB\x10\xA2\x98\xDD",
			.tag_len = 64
		}
	};

	kripto_desc_mac *hmac_md5 = kripto_mac_hmac(kripto_hash_md5);
	TEST(hmac_md5, md5_vectors, 3);
	free(hmac_md5);

	kripto_desc_mac *hmac_sha1 = kripto_mac_hmac(kripto_hash_sha1);
	TEST(hmac_sha1, sha1_vectors, 3);
	free(hmac_sha1);

	kripto_desc_mac *hmac_sha2_256 = kripto_mac_hmac(kripto_hash_sha2_256);
	TEST(hmac_sha2_256, sha2_256_vectors, 4);
	free(hmac_sha2_256);

	kripto_desc_mac *hmac_sha2_512 = kripto_mac_hmac(kripto_hash_sha2_512);
	TEST(hmac_sha2_512, sha2_512_vectors, 4);
	free(hmac_sha2_512);

	return test_result;
}
