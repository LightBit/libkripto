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

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <kripto/mac.h>
#include <kripto/mac/xcbc.h>
#include <kripto/block/rijndael128.h>

static const uint8_t key[16] =
{
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
};

static const uint8_t msg[34] =
{
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
	0x20, 0x21
};

static const uint8_t tag[16] =
{
	0xBE, 0xCB, 0xB3, 0xBC, 0xCD, 0xB5, 0x18, 0xA3,
	0x06, 0x77, 0xD5, 0x48, 0x1F, 0xB6, 0xB4, 0xD8
};

int main(void)
{
	kripto_desc_mac *desc;
	uint8_t t[16];

	desc = kripto_mac_xcbc(kripto_block_rijndael128);
	if(!desc) return -1;

	kripto_mac_all(
		desc, 0,
		key, 16,
		msg, 34,
		t, 16
	);

	if(memcmp(tag, t, 16)) puts("xcbc rijndael128: FAIL");
	else puts("xcbc rijndael128: OK");

	free(desc);

	return 0;
}
