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

#include <kripto/mac.h>
#include <kripto/block.h>
#include <kripto/mac/omac.h>
#include <kripto/block/aes.h>

#include "../test.h"

/* RFC 4493 CMAC-AES128 */
static const char *key = "\x2B\x7E\x15\x16\x28\xAE\xD2\xA6\xAB\xF7\x15\x88\x09\xCF\x4F\x3C";
static const char *message = "\x6B\xC1\xBE\xE2\x2E\x40\x9F\x96\xE9\x3D\x7E\x11\x73\x93\x17\x2A";
static const char *tag = "\x07\x0A\x16\xB4\x6B\x4D\x41\x44\xF7\x9B\xDD\x9D\xD0\x4A\x28\x7C";

static void verify_case(kripto_desc_mac *desc, const void *t, int expect_ok, const char *name)
{
	kripto_mac *s = kripto_mac_create(desc, 0, key, 16, 16);
	if(!s) TEST_ERROR("kripto_mac_create");

	kripto_mac_input(s, message, 16);

	int ok = kripto_mac_verify(s, t, 16) != 0;

	if(ok == expect_ok) TEST_PASS("%s", name);
	else TEST_FAIL("%s", name);

	kripto_mac_destroy(s);
}

int main(void)
{
	kripto_desc_mac *omac_aes = kripto_mac_omac(kripto_block_aes);

	/* accept: the correct tag must verify */
	verify_case(omac_aes, tag, 1, "verify accepts valid tag");

	/* reject: flip one bit in the tag -> must NOT verify */
	char forged[16];
	memcpy(forged, tag, 16);
	forged[0] ^= 0x01;
	verify_case(omac_aes, forged, 0, "verify rejects 1-bit forgery");

	/* reject: flip a bit in the last byte -> must NOT verify */
	memcpy(forged, tag, 16);
	forged[15] ^= 0x80;
	verify_case(omac_aes, forged, 0, "verify rejects last-byte forgery");

	free(omac_aes);

	return test_result;
}
