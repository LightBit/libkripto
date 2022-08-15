/*
 * Copyright (C) 2013 by Gregor Pintar <grpintar@gmail.com>
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

#include <stdlib.h>
#include <stdint.h>

#include <kripto/mac.h>
#include <kripto/hash.h>
#include <kripto/mac/hmac.h>
#include <kripto/hash/sha2_256.h>
#include <kripto/scrypt.h>

#include "test.h"

int main(void)
{
	/* https://www.rfc-editor.org/rfc/rfc7914 */
	const uint8_t out[64] =
	{
		0x21, 0x01, 0xCB, 0x9B, 0x6A, 0x51, 0x1A, 0xAE,
		0xAD, 0xDB, 0xBE, 0x09, 0xCF, 0x70, 0xF8, 0x81,
		0xEC, 0x56, 0x8D, 0x57, 0x4A, 0x2F, 0xFD, 0x4D,
		0xAB, 0xE5, 0xEE, 0x98, 0x20, 0xAD, 0xAA, 0x47,
		0x8E, 0x56, 0xFD, 0x8F, 0x4B, 0xA5, 0xD0, 0x9F,
		0xFA, 0x1C, 0x6D, 0x92, 0x7C, 0x40, 0xF4, 0xC3,
		0x37, 0x30, 0x40, 0x49, 0xE8, 0xA9, 0x52, 0xFB,
		0xCB, 0xF4, 0x5C, 0x6F, 0xA7, 0x7A, 0x41, 0xA4
	};
	uint8_t buf[64];

	kripto_desc_mac *mac = kripto_mac_hmac(kripto_hash_sha2_256);

	if(kripto_scrypt
	(
		mac,
		0,
		1048576,
		8,
		1,
		"pleaseletmein",
		13,
		"SodiumChloride",
		14,
		buf,
		64
	)) TEST_ERROR("kripto_scrypt() returned error");

	free(mac);

	TEST_CMP(buf, out, 64, "scrypt");

	return test_result;
}
