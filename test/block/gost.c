/*
 * Copyright (C) 2013 Gregor Pintar <grpintar@gmail.com>
 *
 * Permission is granted to deal in this work without any restriction,
 * including unlimited rights to use, publicly perform, publish,
 * reproduce, relicence, modify, merge, and/or distribute in any form,
 * for any purpose, with or without fee, and by any means.
 *
 * This work is provided "AS IS" and WITHOUT WARRANTY of any kind,
 * to the utmost extent permitted by applicable law. In no event
 * shall a licensor, author or contributor be held liable for any
 * issues arising in any way out of dealing in the work.
 */

#include <stdint.h>
#include <stdio.h>

#include <kripto/block/gost.h>

int main(void)
{
	kripto_block *s;
	unsigned int i;
	unsigned int n;
	uint8_t t[8];
	const uint8_t k[32] =
	{
		0xBE, 0x5E, 0xC2, 0x00, 0x6C, 0xFF, 0x9D, 0xCF,
		0x52, 0x35, 0x49, 0x59, 0xF1, 0xFF,	0x0C, 0xBF,
		0xE9, 0x50, 0x61, 0xB5, 0xA6, 0x48, 0xC1, 0x03,
		0x87, 0x06, 0x9C, 0x25, 0x99, 0x7C, 0x06, 0x72
	};
	const uint8_t pt[8] =
	{
		0x0D, 0xF8, 0x28, 0x02, 0xB7, 0x41, 0xA2, 0x92
	};
	const uint8_t ct[32][8] =
	{
		{0x32, 0x53, 0xF9, 0x3F, 0xF0, 0x93, 0xA0, 0xF9},
		{0xA7, 0xC0, 0xCD, 0x42, 0x89, 0xE0, 0xEB, 0x60},
		{0xDC, 0x02, 0xA5, 0x00, 0x4E, 0xA0, 0x23, 0xC1},
		{0xDC, 0x02, 0xA5, 0x00, 0x4E, 0xA0, 0x23, 0xC1},
		{0x15, 0xFA, 0xF7, 0x1E, 0xBE, 0xD2, 0x56, 0x55},
		{0x97, 0x2D, 0xF0, 0xF0, 0x18, 0xD3, 0x3A, 0xDC},
		{0x0C, 0x3A, 0x26, 0x12, 0x55, 0x4E, 0xC6, 0xF3},
		{0x31, 0xBF, 0xCA, 0xA8, 0x08, 0x6A, 0x5F, 0xFD},
		{0x78, 0x5F, 0x62, 0x69, 0xE7, 0x65, 0xFE, 0x93},
		{0xBC, 0x5F, 0x76, 0xAC, 0xD0, 0xFC, 0xA8, 0xA2},
		{0x61, 0xC1, 0xA8, 0xD3, 0xF8, 0x3F, 0x5C, 0xBC},
		{0x21, 0x89, 0x0A, 0x9A, 0xC2, 0x1F, 0xF1, 0x03},
		{0x3B, 0x93, 0x65, 0xF0, 0x5A, 0xE3, 0x7B, 0xD8},
		{0x9A, 0x28, 0x2F, 0xAF, 0xC2, 0x92, 0x54, 0x28},
		{0x64, 0xF3, 0x08, 0x8B, 0x27, 0x83, 0xFD, 0xB5},
		{0xBB, 0x2D, 0xA7, 0x86, 0x1D, 0xDF, 0x4F, 0x8A},
		{0x50, 0xFC, 0x52, 0xD0, 0x73, 0x4E, 0xA4, 0x61},
		{0x1D, 0x70, 0xC4, 0xAA, 0x7F, 0xAF, 0x20, 0xF4},
		{0xBF, 0x32, 0x6A, 0x0A, 0xE8, 0xC8, 0x87, 0x5A},
		{0xB2, 0x11, 0x0B, 0x05, 0x91, 0x30, 0xEB, 0x8C},
		{0xC6, 0x31, 0xD2, 0x9C, 0x3A, 0xCB, 0x7C, 0x0F},
		{0xAE, 0x09, 0x59, 0x14, 0xEA, 0x25, 0xF6, 0x21},
		{0x9D, 0x91, 0x8C, 0xB4, 0xE9, 0xD9, 0x99, 0xFF},
		{0x23, 0xCF, 0x72, 0xE0, 0xB7, 0x46, 0xC7, 0x0F},
		{0x02, 0xBF, 0xEB, 0x79, 0x1B, 0x66, 0xD5, 0x32},
		{0x47, 0x7D, 0x6E, 0xCC, 0xDA, 0x4D, 0xEB, 0x18},
		{0x0D, 0x6E, 0xB7, 0xA3, 0x05, 0x6E, 0x42, 0x68},
		{0xEF, 0x6D, 0x9D, 0x74, 0xD1, 0x24, 0x9F, 0x5C},
		{0x75, 0xF7, 0x40, 0x7A, 0x70, 0xB9, 0xAB, 0xFF},
		{0x55, 0x81, 0x86, 0xB1, 0x83, 0xC4, 0xDE, 0x54},
		{0x82, 0xAE, 0x01, 0x79, 0x7D, 0x28, 0xDA, 0xD8},
		{0x07, 0xF9, 0x02, 0x7D, 0xF7, 0xF7, 0xDF, 0x89}
	};

	puts("kripto_block_gost");

	for(n = 1; n <= 32; n++)
	{
		s = kripto_block_create(kripto_block_gost, 0, k, n);
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
