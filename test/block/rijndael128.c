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
#include <kripto/block/rijndael128.h>

int main(void)
{
	kripto_block *s;
	unsigned int i;
	unsigned int n;
	uint8_t t[16];
	const uint8_t k[32] =
	{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
	};
	const uint8_t pt[16] =
	{
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF
	};
	const uint8_t ct[32][16] =
	{
		{
			0xF7, 0xD5, 0x05, 0x0A, 0x12, 0x27, 0x61, 0x7A,
			0xCD, 0xF7, 0x52, 0x0A, 0xCD, 0x4C, 0x4F, 0x1D
		},
		{
			0x4E, 0xD5, 0x3E, 0xA4, 0xFB, 0x6D, 0xAD, 0x35,
			0xC4, 0x74, 0x8F, 0x02, 0xB2, 0x36, 0xE3, 0x21
		},
		{
			0xA9, 0xBF, 0x93, 0x67, 0x69, 0x28, 0x7E, 0x39,
			0xB4, 0xE8, 0x49, 0x43, 0x73, 0xAB, 0x68, 0x3F
		},
		{
			0xA9, 0xC8, 0x19, 0x4A, 0x9B, 0xFF, 0x04, 0x68,
			0x6F, 0xBD, 0xEA, 0x29, 0xDF, 0x84, 0x7D, 0x8A
		},
		{
			0x8B, 0xF7, 0xB0, 0x75, 0xB7, 0x5B, 0xD8, 0xE2,
			0x2A, 0xD4, 0xDB, 0xAF, 0x46, 0x5C, 0xA0, 0x20
		},
		{
			0xED, 0x92, 0x04, 0x3A, 0xBF, 0xA0, 0xD0, 0x4B,
			0x3A, 0x87, 0x4F, 0x18, 0x1D, 0xD3, 0x63, 0x88
		},
		{
			0x5E, 0x72, 0x6D, 0xEB, 0x7F, 0x3B, 0x1C, 0x02,
			0xEB, 0x8C, 0x5D, 0x2C, 0xFF, 0x5E, 0x55, 0xE1
		},
		{
			0xD1, 0x91, 0x74, 0x23, 0x97, 0x58, 0xFF, 0xA5,
			0x46, 0x80, 0xED, 0x64, 0xB2, 0xC2, 0xB8, 0x94
		},
		{
			0x9B, 0xFD, 0x05, 0x38, 0x25, 0x4F, 0xA6, 0x77,
			0x21, 0xCF, 0x35, 0x5F, 0x70, 0x77, 0x00, 0xD5
		},
		{
			0xB9, 0xBC, 0x51, 0x14, 0xB4, 0x70, 0x63, 0x5D,
			0x94, 0x8D, 0x1B, 0xC1, 0xC4, 0x64, 0xE3, 0xE3
		},
		{
			0x72, 0xFB, 0xB7, 0x5C, 0xFF, 0x89, 0xB2, 0x8C,
			0xD2, 0xBC, 0x0F, 0x24, 0x0E, 0xF1, 0xCC, 0xD1
		},
		{
			0xDE, 0x1D, 0x4D, 0xC7, 0x05, 0x89, 0xF0, 0xD9,
			0x11, 0xCE, 0x9A, 0x82, 0xDD, 0x1E, 0x9B, 0xA7
		},
		{
			0x8E, 0xA4, 0xAD, 0x7B, 0x89, 0x9E, 0x65, 0x7E,
			0x37, 0x64, 0x01, 0x3F, 0xA5, 0xFB, 0xDA, 0xD1
		},
		{
			0x69, 0xC0, 0xF0, 0x9A, 0x4C, 0x17, 0x3B, 0xA2,
			0x4A, 0x48, 0x97, 0x73, 0x82, 0x97, 0x2E, 0xBF
		},
		{
			0x79, 0xEC, 0xC3, 0x0B, 0x84, 0xCA, 0x97, 0x14,
			0x78, 0x54, 0x6A, 0xC3, 0xF4, 0x5B, 0x58, 0x99
		},
		{
			0x69, 0xC4, 0xE0, 0xD8, 0x6A, 0x7B, 0x04, 0x30,
			0xD8, 0xCD, 0xB7, 0x80, 0x70, 0xB4, 0xC5, 0x5A
		},
		{
			0x57, 0x61, 0xB0, 0x5F, 0x70, 0x81, 0xA5, 0xD8,
			0xA9, 0xC5, 0x2F, 0xEE, 0x1B, 0x60, 0x5F, 0x34
		},
		{
			0xB6, 0x7C, 0x30, 0x52, 0x3A, 0x84, 0xB7, 0x37,
			0x62, 0xD3, 0x23, 0x07, 0xAE, 0xD1, 0x6E, 0x00
		},
		{
			0xC0, 0xC7, 0xDA, 0x73, 0x18, 0x61, 0x51, 0x9D,
			0x69, 0x80, 0x34, 0xCA, 0xF4, 0xF0, 0x67, 0x0C
		},
		{
			0x8C, 0x92, 0xFB, 0xEE, 0x29, 0x77, 0x45, 0xEC,
			0xDE, 0xF3, 0xCE, 0x7B, 0xD6, 0x77, 0x1A, 0x97
		},
		{
			0x32, 0xB7, 0x1C, 0x54, 0xD1, 0xD2, 0xB9, 0xB9,
			0x04, 0xA9, 0x5F, 0x57, 0x8D, 0xCD, 0x2F, 0xAD
		},
		{
			0x49, 0x73, 0x7B, 0xE9, 0xA0, 0x4A, 0xA0, 0xD7,
			0x15, 0x40, 0x3A, 0x1D, 0xD0, 0x3C, 0x3B, 0xB2
		},
		{
			0x7D, 0x91, 0x3B, 0x87, 0x00, 0x58, 0x17, 0x40,
			0x56, 0x72, 0xE3, 0x7C, 0x8D, 0xF4, 0x85, 0x7C
		},
		{
			0xDD, 0xA9, 0x7C, 0xA4, 0x86, 0x4C, 0xDF, 0xE0,
			0x6E, 0xAF, 0x70, 0xA0, 0xEC, 0x0D, 0x71, 0x91
		},
		{
			0xA5, 0x80, 0xC1, 0xAD, 0xC3, 0xBC, 0x7D, 0x76,
			0x3C, 0xA6, 0xBF, 0xEF, 0x59, 0x7A, 0x18, 0xA4
		},
		{
			0x5D, 0xE4, 0xDC, 0x38, 0xB7, 0x91, 0x3D, 0x22,
			0xF6, 0xB6, 0x27, 0x22, 0xFC, 0x77, 0x5A, 0x14
		},
		{
			0x33, 0x3D, 0x0C, 0xFA, 0x9E, 0xAB, 0xC0, 0xEC,
			0x02, 0xC8, 0xE3, 0x29, 0x2C, 0x55, 0x8B, 0xF6
		},
		{
			0x73, 0xBA, 0x76, 0xE0, 0x12, 0x0C, 0xF3, 0xF2,
			0x9B, 0x6A, 0x56, 0x4A, 0x34, 0x48, 0xE9, 0x00
		},
		{
			0x07, 0xF6, 0x79, 0x46, 0x1F, 0x81, 0x15, 0xEA,
			0x72, 0xB8, 0x41, 0x4E, 0x10, 0x91, 0x4D, 0xFC
		},
		{
			0x4D, 0x87, 0x3E, 0x64, 0x5A, 0xE5, 0x50, 0xF6,
			0x4F, 0xD6, 0x6C, 0x7F, 0x49, 0xDF, 0x6C, 0x9A
		},
		{
			0x0C, 0x1C, 0xFC, 0x4A, 0xC7, 0x98, 0x44, 0x4E,
			0xC8, 0xAC, 0x60, 0x7F, 0x5D, 0x7A, 0xFE, 0x62
		},
		{
			0x8E, 0xA2, 0xB7, 0xCA, 0x51, 0x67, 0x45, 0xBF,
			0xEA, 0xFC, 0x49, 0x90, 0x4B, 0x49, 0x60, 0x89
		}
	};

	puts("kripto_block_rijndael128");

	for(n = 1; n <= 32; n++)
	{
		s = kripto_block_create(kripto_block_rijndael128, 0, k, n);
		if(!s) puts("error");

		kripto_block_encrypt(s, pt, t);
		for(i = 0; i < 16; i++) if(t[i] != ct[n - 1][i])
		{
			printf("%u-bit key encrypt: FAIL\n", n * 8);
			break;
		}
		if(i == 16) printf("%u-bit key encrypt: OK\n", n * 8);

		kripto_block_decrypt(s, ct[n - 1], t);
		for(i = 0; i < 16; i++) if(t[i] != pt[i])
		{
			printf("%u-bit key decrypt: FAIL\n", n * 8);
			break;
		}
		if(i == 16) printf("%u-bit key decrypt: OK\n", n * 8);

		kripto_block_destroy(s);
	}

	return 0;
}
