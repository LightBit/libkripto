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
#include <stdio.h>

#include <kripto/block.h>
#include <kripto/block/blowfish.h>

int main(void)
{
	kripto_block *s;
	unsigned int i;
	unsigned int n;
	uint8_t t[8] =
	{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};
	const uint8_t k[24] =
	{
		0xF0, 0xE1, 0xD2, 0xC3, 0xB4, 0xA5, 0x96, 0x87,
		0x78, 0x69, 0x5A, 0x4B, 0x3C, 0x2D, 0x1E, 0x0F,
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77
	};
	const uint8_t pt[8] =
	{
		0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
	};
	const uint8_t ct[24][8] =
	{
		{0xF9, 0xAD, 0x59, 0x7C, 0x49, 0xDB, 0x00, 0x5E},
		{0xE9, 0x1D, 0x21, 0xC1, 0xD9, 0x61, 0xA6, 0xD6},
		{0xE9, 0xC2, 0xB7, 0x0A, 0x1B, 0xC6, 0x5C, 0xF3},
		{0xBE, 0x1E, 0x63, 0x94, 0x08, 0x64, 0x0F, 0x05},
		{0xB3, 0x9E, 0x44, 0x48, 0x1B, 0xDB, 0x1E, 0x6E},
		{0x94, 0x57, 0xAA, 0x83, 0xB1, 0x92, 0x8C, 0x0D},
		{0x8B, 0xB7, 0x70, 0x32, 0xF9, 0x60, 0x62, 0x9D},
		{0xE8, 0x7A, 0x24, 0x4E, 0x2C, 0xC8, 0x5E, 0x82},
		{0x15, 0x75, 0x0E, 0x7A, 0x4F, 0x4E, 0xC5, 0x77},
		{0x12, 0x2B, 0xA7, 0x0B, 0x3A, 0xB6, 0x4A, 0xE0},
		{0x3A, 0x83, 0x3C, 0x9A, 0xFF, 0xC5, 0x37, 0xF6},
		{0x94, 0x09, 0xDA, 0x87, 0xA9, 0x0F, 0x6B, 0xF2},
		{0x88, 0x4F, 0x80, 0x62, 0x50, 0x60, 0xB8, 0xB4},
		{0x1F, 0x85, 0x03, 0x1C, 0x19, 0xE1, 0x19, 0x68},
		{0x79, 0xD9, 0x37, 0x3A, 0x71, 0x4C, 0xA3, 0x4F},
		{0x93, 0x14, 0x28, 0x87, 0xEE, 0x3B, 0xE1, 0x5C},
		{0x03, 0x42, 0x9E, 0x83, 0x8C, 0xE2, 0xD1, 0x4B},
		{0xA4, 0x29, 0x9E, 0x27, 0x46, 0x9F, 0xF6, 0x7B},
		{0xAF, 0xD5, 0xAE, 0xD1, 0xC1, 0xBC, 0x96, 0xA8},
		{0x10, 0x85, 0x1C, 0x0E, 0x38, 0x58, 0xDA, 0x9F},
		{0xE6, 0xF5, 0x1E, 0xD7, 0x9B, 0x9D, 0xB2, 0x1F},
		{0x64, 0xA6, 0xE1, 0x4A, 0xFD, 0x36, 0xB4, 0x6F},
		{0x80, 0xC7, 0xD7, 0xD4, 0x5A, 0x54, 0x79, 0xAD},
		{0x05, 0x04, 0x4B, 0x62, 0xFA, 0x52, 0xD0, 0x80}
	};

	puts("kripto_block_blowfish");

	for(n = 1; n <= 24; n++)
	{
		s = kripto_block_create(kripto_block_blowfish, 0, k, n);
		if(!s) puts("error");

		kripto_block_encrypt(s, pt, t);
		for(i = 0; i < 8; i++) if(t[i] != ct[n - 1][i])
		{
			printf("%u-bit key encrypt: FAIL\n", n * 8);
			break;
		}
		if(i == 8) printf("%u-bit key encrypt: OK\n", n * 8);
		kripto_block_decrypt(s, ct[n - 1], t);
		for(i = 0; i < 8; i++) if(t[i] != pt[i])
		{
			printf("%u-bit key decrypt: FAIL\n", n * 8);
			break;
		}
		if(i == 8) printf("%u-bit key decrypt: OK\n", n * 8);
		kripto_block_destroy(s);
	}

	return 0;
}
