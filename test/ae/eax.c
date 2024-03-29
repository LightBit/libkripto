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

#include <stdint.h>

#include <kripto/block.h>
#include <kripto/block/rijndael128.h>
#include <kripto/ae.h>
#include <kripto/ae/eax.h>

#include "../test.h"

int main(void)
{
	const uint8_t k[16] =
	{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
	};
	const uint8_t pt[32] =
	{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
	};
	const uint8_t ct[32] =
	{
		0x29, 0xD8, 0x78, 0xD1, 0xA3, 0xBE, 0x85, 0x7B,
		0x6F, 0xB8, 0xC8, 0xEA, 0x59, 0x50, 0xA7, 0x78,
		0x33, 0x1F, 0xBF, 0x2C, 0xCF, 0x33, 0x98, 0x6F,
		0x35, 0xE8, 0xCF, 0x12, 0x1D, 0xCB, 0x30, 0xBC
	};
	const uint8_t tag[16] =
	{
		0x4F, 0xBE, 0x03, 0x38, 0xBE, 0x1C, 0x8C, 0x7E,
		0x1D, 0x7A, 0xE7, 0xE4, 0x5B, 0x92, 0xC5, 0x87
	};
	uint8_t t[32];

	kripto_desc_ae *desc = kripto_ae_eax(kripto_block_rijndael128);

	/* create */
	kripto_ae *s = kripto_ae_create(desc, 0, k, 16, k, 16, 16);
	if(!s) TEST_ERROR("kripto_ae_create");

	/* encrypt */
	kripto_ae_encrypt(s, pt, t, 32);
	TEST_CMP(t, ct, 32, "kripto_ae_encrypt");

	/* tag */
	kripto_ae_header(s, pt, 16);
	kripto_ae_tag(s, t, 16);
	TEST_CMP(t, tag, 16, "kripto_ae_tag after encrypt");

	/* recreate */
	s = kripto_ae_recreate(s, 0, pt, 16, pt, 16, 16);
	if(!s) TEST_ERROR("kripto_ae_recreate");

	/* decrypt */
	kripto_ae_decrypt(s, ct, t, 32);
	TEST_CMP(t, pt, 32, "kripto_ae_decrypt");

	/* tag */
	kripto_ae_header(s, pt, 16);
	kripto_ae_tag(s, t, 16);
	TEST_CMP(t, tag, 16, "kripto_ae_tag after decrypt");

	kripto_ae_destroy(s);
	free(desc);

	return test_result;
}
