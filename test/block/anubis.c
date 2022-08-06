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

#include <kripto/block/anubis.h>

int main(void)
{
	kripto_block *s;
	unsigned int i;
	unsigned int n;
	uint8_t t[16];
	const uint8_t k[40] =
	{
		0xDA, 0xDA, 0xDA, 0xDA, 0xDA, 0xDA, 0xDA, 0xDA,
		0xDA, 0xDA, 0xDA, 0xDA, 0xDA, 0xDA, 0xDA, 0xDA,
		0xDA, 0xDA, 0xDA, 0xDA, 0xDA, 0xDA, 0xDA, 0xDA,
		0xDA, 0xDA, 0xDA, 0xDA, 0xDA, 0xDA, 0xDA, 0xDA,
		0xDA, 0xDA, 0xDA, 0xDA, 0xDA, 0xDA, 0xDA, 0xDA
	};
	const uint8_t ct[40][16] =
	{
		{
			0xA5, 0x4E, 0xA2, 0x95, 0x55, 0x96, 0xB6, 0xFD,
			0x81, 0x25, 0x0D, 0xB2, 0x7E, 0x13, 0xEF, 0x72
		},
		{
			0xB6, 0x95, 0x83, 0x41, 0xF4, 0xBA, 0x1A, 0x8B,
			0x33, 0xFD, 0xFD, 0x6D, 0xAC, 0x27, 0xC0, 0xD7
		},
		{
			0x1C, 0x01, 0x0D, 0xC6, 0xF6, 0x6F, 0x5B, 0x43,
			0x22, 0xFE, 0xCD, 0x6E, 0xDF, 0xBD, 0x00, 0x5D
		},
		{
			0x67, 0x10, 0x3C, 0x63, 0xCE, 0xDF, 0x8C, 0x1F,
			0xFC, 0xBC, 0x77, 0xF8, 0x38, 0xCE, 0x74, 0xAB
		},
		{
			0x61, 0x5A, 0xDB, 0xB7, 0x0B, 0x1B, 0x86, 0x7F,
			0xF4, 0x66, 0xC6, 0x1A, 0xEA, 0x8A, 0xF1, 0xC2
		},
		{
			0x01, 0xD9, 0xB2, 0x1F, 0x2E, 0x76, 0x52, 0x9E,
			0xAC, 0x20, 0x80, 0x3B, 0xA3, 0xA9, 0xCB, 0xD7
		},
		{
			0xA6, 0x39, 0xE6, 0x36, 0x58, 0x22, 0xB5, 0x9D,
			0x6B, 0x31, 0x78, 0x6B, 0xC0, 0x24, 0x53, 0x6D
		},
		{
			0xBE, 0xF6, 0x3A, 0x98, 0xD6, 0xC8, 0xCD, 0x4D,
			0x78, 0x2B, 0x28, 0x12, 0xCB, 0x3C, 0x3A, 0xAB
		},
		{
			0x66, 0x92, 0xFB, 0x4C, 0x87, 0xC9, 0x18, 0xBD,
			0x2A, 0xBA, 0x8E, 0xB7, 0x8E, 0xC1, 0x56, 0xC7
		},
		{
			0xEC, 0x31, 0x5D, 0x9B, 0xC6, 0x93, 0x42, 0x6B,
			0x91, 0xCC, 0x7D, 0x6B, 0x09, 0xBF, 0x2B, 0x6B
		},
		{
			0x59, 0xFA, 0x46, 0x26, 0x9F, 0x60, 0x0B, 0x89,
			0x93, 0x97, 0x1B, 0x95, 0x07, 0x37, 0x88, 0x92
		},
		{
			0x80, 0xC5, 0xCB, 0x86, 0x8D, 0x46, 0xC7, 0xE5,
			0xF3, 0x8F, 0xD7, 0x87, 0x84, 0x7B, 0xEC, 0xEE
		},
		{
			0xA3, 0x94, 0x87, 0x7C, 0x2A, 0x18, 0xAC, 0xB0,
			0x83, 0x97, 0x9E, 0x8D, 0xC8, 0x57, 0x2C, 0x76
		},
		{
			0x80, 0xED, 0x4D, 0x6B, 0x17, 0xF0, 0x55, 0xCE,
			0x75, 0xD8, 0xB1, 0x01, 0xD2, 0x8B, 0x00, 0x30
		},
		{
			0x81, 0x0C, 0xE8, 0xA3, 0xFB, 0xE7, 0x16, 0xEA,
			0x6F, 0xCD, 0x41, 0x89, 0x5A, 0x3E, 0x9B, 0xD1
		},
		{
			0xB6, 0x16, 0x22, 0xC1, 0x44, 0x15, 0x42, 0xD7,
			0x72, 0x5A, 0xA6, 0xF6, 0xBB, 0xC1, 0xD7, 0xA1
		},
		{
			0x2E, 0xFD, 0x70, 0x95, 0x87, 0x59, 0xE9, 0x9D,
			0xB6, 0xB8, 0xC1, 0xC2, 0xDE, 0xB4, 0x08, 0x9E
		},
		{
			0xFF, 0xE7, 0x8A, 0x71, 0x5D, 0x40, 0x7D, 0x5B,
			0x41, 0xD4, 0x38, 0x32, 0xAF, 0x1C, 0x09, 0x58
		},
		{
			0x47, 0x7B, 0x50, 0x53, 0xA6, 0x65, 0x68, 0x79,
			0x53, 0x16, 0x16, 0xE7, 0xD1, 0x31, 0xB3, 0xF5
		},
		{
			0xA8, 0xB0, 0x8B, 0xD1, 0x89, 0xA7, 0x75, 0x91,
			0xDF, 0xF2, 0xBB, 0x49, 0x92, 0x4D, 0xBC, 0x6F
		},
		{
			0xE7, 0xDC, 0x18, 0x33, 0x16, 0x78, 0xD8, 0x23,
			0xD9, 0x44, 0x4C, 0xDB, 0x6F, 0xCF, 0x9B, 0xC9
		},
		{
			0xDE, 0xE8, 0xBF, 0x29, 0xD4, 0x7C, 0x39, 0x5A,
			0x20, 0x41, 0xE0, 0x55, 0xDD, 0x29, 0x2D, 0x4F
		},
		{
			0x5B, 0x15, 0x3C, 0xDA, 0x6F, 0x9C, 0x60, 0x03,
			0x82, 0x33, 0xF2, 0x72, 0x5F, 0xAA, 0xA3, 0x98
		},
		{
			0x97, 0x35, 0x61, 0x0E, 0x02, 0x18, 0x4B, 0xDF,
			0x4F, 0x1F, 0x3E, 0x6F, 0x9B, 0xB8, 0xD3, 0x4C
		},
		{
			0x2E, 0xD7, 0xC7, 0xC3, 0x75, 0x42, 0x91, 0x47,
			0x0C, 0xF9, 0x98, 0xCD, 0x62, 0x53, 0xE0, 0x99
		},
		{
			0x84, 0x05, 0xFA, 0x37, 0xAA, 0x3B, 0x8B, 0xBC,
			0x3A, 0x73, 0x25, 0x9A, 0xA0, 0x49, 0x8E, 0x76
		},
		{
			0x1D, 0xFE, 0xFC, 0x61, 0x67, 0x27, 0x85, 0x8B,
			0x51, 0x32, 0xA4, 0x5B, 0xDB, 0x98, 0xF8, 0xF9
		},
		{
			0x05, 0x53, 0xF1, 0x3F, 0xDC, 0xE2, 0x3B, 0x2E,
			0xCC, 0x42, 0x1C, 0x23, 0xAC, 0x0B, 0x29, 0x8F
		},
		{
			0x1C, 0x98, 0x3E, 0xDE, 0xDD, 0xDA, 0x6E, 0xA2,
			0xE4, 0x99, 0x36, 0x0A, 0x79, 0x2D, 0x6B, 0xD6
		},
		{
			0x2E, 0xAD, 0x0D, 0xDD, 0x19, 0x82, 0x98, 0x6F,
			0xE3, 0x83, 0xB0, 0xDA, 0x49, 0x34, 0xA8, 0x7D
		},
		{
			0xF2, 0xAC, 0x34, 0x40, 0x50, 0x4E, 0xCA, 0x24,
			0x3A, 0x81, 0xCD, 0x44, 0x77, 0x86, 0x68, 0xD1
		},
		{
			0x9E, 0xAB, 0xA2, 0xE6, 0xBF, 0xA8, 0xB0, 0x72,
			0x03, 0x36, 0xE9, 0x9F, 0x25, 0x35, 0x0D, 0x4F
		},
		{
			0x6D, 0x57, 0x81, 0xBA, 0xEF, 0xC1, 0xD0, 0xA1,
			0xC7, 0x76, 0x01, 0x57, 0x0A, 0x8E, 0x02, 0xAA
		},
		{
			0x35, 0xC0, 0xA9, 0x48, 0xD8, 0xF0, 0x3F, 0xA2,
			0x0D, 0x22, 0x2B, 0x47, 0xCB, 0x1C, 0x99, 0x38
		},
		{
			0x43, 0xF0, 0xE9, 0xEB, 0x09, 0xAF, 0x60, 0x6B,
			0xFC, 0x2E, 0xDE, 0x5C, 0x79, 0xC5, 0xF7, 0x9F
		},
		{
			0x53, 0xD8, 0x8E, 0xD0, 0xF0, 0x2C, 0xB9, 0x75,
			0xBC, 0x2C, 0xE4, 0xCF, 0xB9, 0xEE, 0x9F, 0xAF
		},
		{
			0x35, 0xD6, 0xCB, 0x3A, 0xCE, 0x48, 0x41, 0x7D,
			0x1F, 0x71, 0x7D, 0x78, 0x2E, 0x8D, 0x52, 0x56
		},
		{
			0xBD, 0x9C, 0x97, 0x71, 0x2F, 0x2E, 0xF8, 0x89,
			0x03, 0x94, 0xBF, 0x32, 0x14, 0x6F, 0xFF, 0x16
		},
		{
			0x65, 0x13, 0x6A, 0x5C, 0xF1, 0x64, 0xA7, 0xD7,
			0xC5, 0xFD, 0x15, 0xB5, 0x25, 0xEF, 0x1F, 0x39
		},
		{
			0x78, 0xE0, 0x2E, 0x15, 0x31, 0x7F, 0x42, 0xAA,
			0x1B, 0x53, 0x7A, 0xF8, 0x19, 0x0E, 0x0F, 0x14
		}
	};

	puts("kripto_block_anubis");

	for(n = 1; n <= 40; n++)
	{
		s = kripto_block_create(kripto_block_anubis, 0, k, n);
		if(!s) puts("error");

		kripto_block_encrypt(s, k, t);
		for(i = 0; i < 16; i++) if(t[i] != ct[n - 1][i])
		{
			printf("%u-bit key encrypt: FAIL\n", n * 8);
			break;
		}
		if(i == 16) printf("%u-bit key encrypt: OK\n", n * 8);

		kripto_block_decrypt(s, ct[n - 1], t);
		for(i = 0; i < 16; i++) if(t[i] != k[i])
		{
			printf("%u-bit key decrypt: FAIL\n", n * 8);
			break;
		}
		if(i == 16) printf("%u-bit key decrypt: OK\n", n * 8);

		kripto_block_destroy(s);
	}

	return 0;
}
