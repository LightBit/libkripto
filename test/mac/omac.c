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
#include <kripto/mac/omac.h>
#include <kripto/block/rijndael128.h>

static const uint8_t key[16] =
{
	0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
	0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C
};

static const uint8_t msg[64] =
{
	0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96,
	0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A,
	0xAE, 0x2D, 0x8A, 0x57, 0x1E, 0x03, 0xAC, 0x9C,
	0x9E, 0xB7, 0x6F, 0xAC, 0x45, 0xAF, 0x8E, 0x51,
	0x30, 0xC8, 0x1C, 0x46, 0xA3, 0x5C, 0xE4, 0x11,
	0xE5, 0xFB, 0xC1, 0x19, 0x1A, 0x0A, 0x52, 0xEF,
	0xF6, 0x9F, 0x24, 0x45, 0xDF, 0x4F, 0x9B, 0x17,
	0xAD, 0x2B, 0x41, 0x7B, 0xE6, 0x6C, 0x37, 0x10
};

static const uint8_t tag40[16] =
{
	0xDF, 0xA6, 0x67, 0x47, 0xDE, 0x9A, 0xE6, 0x30,
	0x30, 0xCA, 0x32, 0x61, 0x14, 0x97, 0xC8, 0x27
};

static const uint8_t tag64[16] =
{
	0x51, 0xF0, 0xBE, 0xBF, 0x7E, 0x3B, 0x9D, 0x92,
	0xFC, 0x49, 0x74, 0x17, 0x79, 0x36, 0x3C, 0xFE
};

int main(void)
{
	kripto_desc_mac *desc;
	uint8_t t[16];
	unsigned int i;

	desc = kripto_mac_omac(kripto_block_rijndael128);
	if(!desc) return -1;

	/* 64 */
	kripto_mac_all(
		desc, 0,
		key, 16,
		msg, 64,
		t, 16
	);

	for(i = 0; i < 16; i++) if(t[i] != tag64[i])
	{
		puts("omac rijndael128 64: FAIL");
		break;
	}
	if(i == 16) puts("omac rijndael128 64: OK");

	/* 40 */
	kripto_mac_all(
		desc, 0,
		key, 16,
		msg, 40,
		t, 16
	);

	for(i = 0; i < 16; i++) if(t[i] != tag40[i])
	{
		puts("omac rijndael128 40: FAIL");
		break;
	}
	if(i == 16) puts("omac rijndael128 40: OK");

	free(desc);

	return 0;
}
