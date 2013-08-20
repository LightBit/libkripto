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

#include <kripto/block_threefish256.h>

int main(void)
{
	kripto_block *s;
	unsigned int i;
	unsigned int n;
	uint8_t t[32];
	const uint8_t k[32] =
	{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
	};
	const uint8_t tweak[16] =
	{
		0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8,
		0xF7, 0xF6, 0xF5, 0xF4, 0xF3, 0xF2, 0xF1, 0xF0
	};
	const uint8_t pt[32] =
	{
		0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8,
		0xF7, 0xF6, 0xF5, 0xF4, 0xF3, 0xF2, 0xF1, 0xF0,
		0xEF, 0xEE, 0xED, 0xEC, 0xEB, 0xEA, 0xE9, 0xE8,
		0xE7, 0xE6, 0xE5, 0xE4, 0xE3, 0xE2, 0xE1, 0xE0
	};
	const uint8_t ct[32][32] =
	{
		{
			0x44, 0x9B, 0xA4, 0x87, 0x25, 0x77, 0xA8, 0x24,
			0x85, 0x90, 0x75, 0x3A, 0x8A, 0x28, 0x89, 0x8F,
			0x61, 0x8A, 0x2B, 0xE5, 0x08, 0xF3, 0xCC, 0x84,
			0xFA, 0x85, 0x17, 0xEC, 0x17, 0x42, 0x94, 0x7C
		},
		{
			0xCB, 0x05, 0x2A, 0x40, 0xF0, 0x10, 0x56, 0x4E,
			0x90, 0x77, 0x38, 0x9B, 0x5B, 0xE6, 0xA6, 0xEF,
			0x61, 0x5B, 0xB2, 0x82, 0xEC, 0x83, 0x48, 0xB6,
			0x3D, 0x91, 0x21, 0x41, 0xEE, 0xC2, 0xFD, 0x4E
		},
		{
			0xB8, 0xCF, 0xAC, 0x4D, 0x46, 0x96, 0x7F, 0x25,
			0x91, 0x35, 0x32, 0x7F, 0xF0, 0xB9, 0x85, 0x14,
			0x4D, 0xC3, 0x0A, 0x99, 0x27, 0x56, 0x31, 0x5A,
			0x83, 0x70, 0x72, 0xA6, 0xE1, 0x1D, 0x24, 0xAB
		},
		{
			0x5B, 0xCA, 0x84, 0xFF, 0x6C, 0x6E, 0xAD, 0x87,
			0xF1, 0x18, 0x19, 0xD8, 0x64, 0x61, 0xCC, 0xF5,
			0x8C, 0x27, 0x5F, 0xF8, 0xF7, 0x5B, 0x93, 0xBB,
			0x69, 0x77, 0xFC, 0xE6, 0x4A, 0x75, 0x26, 0xBA
		},
		{
			0x4B, 0x78, 0x90, 0xDA, 0x71, 0x71, 0x9B, 0x6A,
			0x4C, 0x7A, 0x80, 0xF2, 0x24, 0xE6, 0xC6, 0xFC,
			0x31, 0x91, 0x40, 0x44, 0x0C, 0x06, 0x00, 0x78,
			0x30, 0xF9, 0x9B, 0x3C, 0x8A, 0xCA, 0xD5, 0xA3
		},
		{
			0x94, 0xA0, 0x49, 0x69, 0x68, 0x73, 0x20, 0x94,
			0x06, 0x5C, 0xA1, 0x1C, 0x39, 0x6E, 0xE1, 0x13,
			0xBE, 0xA6, 0xAA, 0x2E, 0xCD, 0x18, 0xED, 0xAF,
			0x0E, 0x2D, 0x8E, 0xC2, 0xEB, 0xC9, 0xCB, 0x9E
		},
		{
			0x48, 0xD9, 0x89, 0x88, 0x5F, 0x7D, 0xC4, 0xCA,
			0x19, 0xB5, 0x21, 0x13, 0xAC, 0x24, 0x23, 0x12,
			0xA6, 0x91, 0x54, 0xF1, 0x2E, 0xF6, 0xA7, 0x23,
			0xF8, 0x13, 0x99, 0xCC, 0x94, 0x77, 0xF0, 0x15
		},
		{
			0x77, 0x9B, 0x08, 0x44, 0x1E, 0xAD, 0x32, 0x19,
			0xF6, 0x5D, 0xFC, 0xD7, 0x9F, 0xCB, 0x1F, 0xFA,
			0x66, 0x01, 0xD0, 0x0E, 0xE3, 0xA2, 0xFF, 0x92,
			0xFB, 0x48, 0xD6, 0xAD, 0xD8, 0x91, 0xD9, 0x54
		},
		{
			0x5A, 0xD2, 0x39, 0xB5, 0x69, 0xCC, 0xE2, 0x1F,
			0xFE, 0xF4, 0xF3, 0x63, 0x7F, 0x55, 0x97, 0xF5,
			0x91, 0x82, 0x09, 0x4E, 0x6B, 0x62, 0xD6, 0x32,
			0x18, 0x7D, 0xB5, 0xA2, 0x35, 0xB6, 0x41, 0x8A
		},
		{
			0xDD, 0xB0, 0xEC, 0xFA, 0xB6, 0xAB, 0x77, 0xBD,
			0xDA, 0xE8, 0xA5, 0x8F, 0x7D, 0xED, 0xF0, 0xB7,
			0xB7, 0x57, 0x80, 0x7A, 0xD5, 0xA4, 0xB0, 0x33,
			0x3C, 0x67, 0x1B, 0x4C, 0x67, 0x92, 0x3D, 0x98
		},
		{
			0xEB, 0x45, 0xBE, 0x2C, 0xB2, 0x06, 0xC3, 0x9E,
			0x83, 0xD4, 0xAA, 0xC7, 0x08, 0x79, 0xD6, 0xAB,
			0x24, 0x18, 0x61, 0x96, 0x68, 0xDD, 0x77, 0xA9,
			0x34, 0x58, 0xFA, 0x72, 0xC8, 0xBC, 0x24, 0x18
		},
		{
			0x6A, 0xDA, 0xBB, 0x35, 0x75, 0xD8, 0x5C, 0x1E,
			0xCB, 0x39, 0x58, 0xF8, 0xF5, 0x14, 0x18, 0x5E,
			0x61, 0x74, 0x8D, 0x95, 0xBA, 0xFF, 0x9E, 0x92,
			0x57, 0xA3, 0x1C, 0xD4, 0xFC, 0x2C, 0x52, 0x45
		},
		{
			0xE7, 0xF6, 0x71, 0x99, 0xBD, 0xA1, 0xEC, 0x76,
			0xC5, 0xFA, 0xD4, 0x0B, 0x3E, 0xBF, 0x04, 0x32,
			0xF6, 0xE3, 0xB0, 0x3C, 0x5D, 0x7E, 0x9A, 0x25,
			0xC2, 0x53, 0xAF, 0xB4, 0x44, 0xA8, 0xA0, 0xA0
		},
		{
			0x80, 0x1A, 0x51, 0x97, 0xE6, 0x78, 0x04, 0x73,
			0x55, 0x12, 0x57, 0xC2, 0x3E, 0xB6, 0xE5, 0x02,
			0x5F, 0xB2, 0xC4, 0xA9, 0x77, 0x53, 0xEA, 0x29,
			0x78, 0x80, 0x13, 0x16, 0x4C, 0xEF, 0x38, 0xBD
		},
		{
			0xB1, 0xCF, 0xD3, 0xC2, 0x97, 0x43, 0xB6, 0x4A,
			0x8D, 0xA8, 0x57, 0x1D, 0xF6, 0x7B, 0x02, 0x85,
			0xEE, 0x7E, 0x60, 0x8C, 0x26, 0xEC, 0x4E, 0x93,
			0x74, 0x1C, 0x04, 0x57, 0xB7, 0x7D, 0xC7, 0x56
		},
		{
			0xC0, 0xFD, 0xDA, 0xED, 0xF9, 0xA3, 0xBC, 0x7F,
			0x13, 0xC4, 0xA5, 0x08, 0x55, 0xD0, 0x3B, 0x52,
			0x55, 0xB5, 0x15, 0xBA, 0x63, 0xC3, 0x22, 0xA4,
			0x89, 0x58, 0xB8, 0x61, 0x82, 0xB3, 0xDB, 0x0F
		},
		{
			0x7C, 0x4D, 0x0E, 0xAD, 0xF7, 0xD5, 0x78, 0xDE,
			0x3D, 0xD1, 0x3C, 0xBA, 0xFE, 0x16, 0xAD, 0x5C,
			0x43, 0xD1, 0x0E, 0xAD, 0xAB, 0x0E, 0x59, 0x0D,
			0xD0, 0x9A, 0xCC, 0x0B, 0x4E, 0xEA, 0x61, 0xBE
		},
		{
			0xCB, 0x55, 0x4B, 0xA9, 0xAC, 0xD1, 0x35, 0x9D,
			0x48, 0x44, 0xDF, 0xF0, 0x7C, 0x14, 0x79, 0x08,
			0x6F, 0x87, 0xF0, 0x75, 0xC7, 0xC1, 0x9B, 0x6F,
			0xC7, 0x8F, 0x20, 0x9F, 0xCC, 0xE6, 0xAB, 0xBA
		},
		{
			0x60, 0xB7, 0x25, 0x60, 0x11, 0xF7, 0x2C, 0xBF,
			0x10, 0x4F, 0xC9, 0x82, 0x83, 0xA6, 0x82, 0xCE,
			0xD9, 0x65, 0x05, 0xAC, 0x8E, 0xFE, 0x3A, 0x26,
			0x08, 0xFD, 0x8B, 0xB7, 0x9A, 0x68, 0x14, 0x3F
		},
		{
			0x8E, 0x59, 0x9E, 0xEF, 0x7C, 0xDF, 0x70, 0x3B,
			0xCE, 0x30, 0x0C, 0xA8, 0xF0, 0x02, 0xDD, 0xC8,
			0x1B, 0x2C, 0x9C, 0xF6, 0x66, 0xC1, 0xD4, 0x6F,
			0x7A, 0x4A, 0x22, 0xB4, 0x2B, 0x05, 0xDC, 0x2A
		},
		{
			0x72, 0x37, 0x86, 0x0C, 0x9A, 0xAD, 0x8B, 0x73,
			0x2A, 0xD4, 0x34, 0x79, 0xF3, 0x25, 0x10, 0x1E,
			0xBA, 0x0B, 0x44, 0x8C, 0x3C, 0xC9, 0xEF, 0x2E,
			0x03, 0x2A, 0x7A, 0x09, 0x28, 0xCE, 0x39, 0x99
		},
		{
			0xF3, 0x35, 0x42, 0x46, 0x55, 0xF5, 0xC7, 0xEC,
			0x5A, 0x8F, 0xDA, 0xFC, 0x1E, 0xC2, 0x71, 0xB7,
			0xC2, 0x2C, 0xC0, 0x67, 0x0C, 0xC9, 0x7C, 0x6A,
			0xFF, 0x70, 0x56, 0x9A, 0x1A, 0x4B, 0xE4, 0x38
		},
		{
			0x2E, 0x2D, 0xEF, 0xFC, 0x8C, 0xEF, 0x6C, 0xBA,
			0x37, 0xD7, 0x1D, 0xD8, 0x50, 0x13, 0xD4, 0x8A,
			0xD7, 0x3A, 0x8D, 0x47, 0x43, 0xFF, 0xB3, 0xEC,
			0x27, 0xC8, 0x63, 0xD0, 0x5D, 0xEA, 0x84, 0x1A
		},
		{
			0xA0, 0x65, 0x2B, 0xFB, 0x31, 0x54, 0xB4, 0xBA,
			0xF7, 0xA7, 0xE6, 0x86, 0xD4, 0xB7, 0x55, 0xD2,
			0x18, 0xBB, 0xF5, 0x31, 0xED, 0x06, 0x44, 0x54,
			0xBF, 0x62, 0xD0, 0x92, 0x9F, 0xD3, 0x6F, 0x56
		},
		{
			0x5C, 0x8C, 0xFB, 0x98, 0x3D, 0x3C, 0xA0, 0x74,
			0x32, 0xF3, 0xB6, 0x1F, 0xAE, 0x53, 0xB7, 0x31,
			0x25, 0x03, 0x28, 0x09, 0x29, 0x34, 0xD4, 0x4A,
			0x7B, 0xE3, 0x41, 0x4D, 0x60, 0xB5, 0xC4, 0x52
		},
		{
			0xA9, 0x7D, 0x18, 0x0B, 0xF6, 0x4D, 0x01, 0xBF,
			0xDD, 0x76, 0x79, 0xF8, 0x6F, 0xB6, 0x6F, 0x9C,
			0x5F, 0x31, 0x97, 0x5F, 0xE7, 0x0A, 0x3B, 0x88,
			0x49, 0x11, 0xA4, 0x10, 0x0C, 0x78, 0xB3, 0xD3
		},
		{
			0x60, 0xD8, 0x45, 0xD4, 0x62, 0xF8, 0x74, 0x3E,
			0x5A, 0x76, 0x03, 0xB5, 0xED, 0x10, 0x2C, 0x06,
			0x28, 0x00, 0x40, 0x7A, 0x17, 0x14, 0x4C, 0xDD,
			0x4F, 0x99, 0xA4, 0x6F, 0x71, 0x9B, 0x46, 0xD6
		},
		{
			0x98, 0x37, 0xE5, 0x86, 0xE5, 0x3D, 0x49, 0x7E,
			0x9D, 0x8A, 0x9A, 0x1A, 0xE0, 0x72, 0xF2, 0x9D,
			0x48, 0x76, 0x78, 0xBF, 0x19, 0x78, 0x51, 0xBC,
			0x62, 0xE3, 0x39, 0xA2, 0xD4, 0x2C, 0x57, 0xF4
		},
		{
			0x4E, 0x27, 0xB4, 0xFE, 0x25, 0x80, 0x5B, 0x46,
			0x1D, 0x89, 0xBD, 0xD9, 0x68, 0xE3, 0x88, 0x41,
			0x88, 0x1A, 0x9C, 0xDD, 0xDD, 0xB9, 0xEF, 0xAA,
			0xC3, 0xC9, 0x91, 0xA0, 0xA5, 0x19, 0xC9, 0x91
		},
		{
			0xE4, 0x15, 0x2D, 0x0F, 0x65, 0x40, 0x02, 0x47,
			0xB4, 0x6F, 0x5C, 0xAF, 0xB4, 0xBF, 0x1F, 0x0B,
			0x60, 0x1F, 0xDC, 0xE1, 0xF1, 0x67, 0x22, 0xEF,
			0x12, 0x2A, 0xFA, 0x50, 0x37, 0x4E, 0x8E, 0x3D
		},
		{
			0x0D, 0x97, 0x2F, 0x17, 0x93, 0xC2, 0x5D, 0x4E,
			0x58, 0x95, 0x29, 0xF9, 0xBF, 0xDD, 0x6A, 0x11,
			0x8A, 0xA5, 0x21, 0xCC, 0x6B, 0x8B, 0xB3, 0x2E,
			0xE2, 0x81, 0x66, 0xD4, 0x90, 0xED, 0x4E, 0x8B
		},
		{
			0x48, 0x07, 0x07, 0xB5, 0xE4, 0x5E, 0x71, 0x29,
			0xD9, 0x59, 0x06, 0x43, 0xB6, 0xD0, 0x24, 0xE0,
			0xB0, 0xF4, 0xFD, 0xBB, 0x7B, 0x11, 0xC2, 0xE7,
			0x9D, 0xC6, 0xFD, 0xB4, 0xCD, 0xC8, 0xAF, 0x36
		}
	};

	puts("kripto_block_threefish256");

	for(n = 1; n <= 32; n++)
	{
		s = kripto_block_create(kripto_block_threefish256, 0, k, n);
		if(!s) puts("error");

		kripto_block_threefish256_tweak(s, tweak);

		kripto_block_encrypt(s, pt, t);
		for(i = 0; i < 32; i++) if(t[i] != ct[n - 1][i])
		{
			printf("%u-bit key encrypt: FAIL\n", n * 8);
			break;
		}
		if(i == 32) printf("%u-bit key encrypt: OK\n", n * 8);

		kripto_block_decrypt(s, ct[n - 1], t);
		for(i = 0; i < 32; i++) if(t[i] != pt[i])
		{
			printf("%u-bit key decrypt: FAIL\n", n * 8);
			break;
		}
		if(i == 32) printf("%u-bit key decrypt: OK\n", n * 8);

		kripto_block_destroy(s);
	}

	return 0;
}
