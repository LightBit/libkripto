/*
 * Copyright (C) 2022 by Gregor Pintar <grpintar@gmail.com>
 *
 * Permission to use, copy, modify, and/or distribute this software
 * for any purpose with or without fee is hereby granted.
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
#include <kripto/block/lea.h>

int main(void)
{
	const uint8_t k[32] =
	{
		0x0F, 0x1E, 0x2D, 0x3C, 0x4B, 0x5A, 0x69, 0x78,
		0x87, 0x96, 0xA5, 0xB4, 0xC3, 0xD2, 0xE1, 0xF0,
		0xF0, 0xE1, 0xD2, 0xC3, 0xB4, 0xA5, 0x96, 0x87,
		0x78, 0x69, 0x5A, 0x4B, 0x3C, 0x2D, 0x1E, 0x0F
	};
	const uint8_t pt128[16] =
	{
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
	};
	const uint8_t ct128[16] =
	{
		0x9F, 0xC8, 0x4E, 0x35, 0x28, 0xC6, 0xC6, 0x18,
		0x55, 0x32, 0xC7, 0xA7, 0x04, 0x64, 0x8B, 0xFD
	};
	const uint8_t pt192[16] =
	{
		0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
		0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F
	};
	const uint8_t ct192[16] =
	{
		0x6F, 0xB9, 0x5E, 0x32, 0x5A, 0xAD, 0x1B, 0x87,
		0x8C, 0xDC, 0xF5, 0x35, 0x76, 0x74, 0xC6, 0xF2
	};
	const uint8_t pt256[16] =
	{
		0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
		0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F
	};
	const uint8_t ct256[16] =
	{
		0xD6, 0x51, 0xAF, 0xF6, 0x47, 0xB1, 0x89, 0xC1,
		0x3A, 0x89, 0x00, 0xCA, 0x27, 0xF9, 0xE1, 0x97
	};
	kripto_block *s;
	unsigned int i;
	uint8_t t[16];

	puts("kripto_block_lea");

	/* 128-bit */
	s = kripto_block_create(kripto_block_lea, 0, k, 16);
	if(!s) puts("error");

	kripto_block_encrypt(s, pt128, t);
	for(i = 0; i < 16; i++) if(t[i] != ct128[i])
	{
		printf("128-bit encrypt: FAIL\n");
		break;
	}
	if(i == 16) printf("128-bit encrypt: OK\n");

	kripto_block_decrypt(s, ct128, t);
	for(i = 0; i < 16; i++) if(t[i] != pt128[i])
	{
		printf("128-bit decrypt: FAIL\n");
		break;
	}
	if(i == 16) printf("128-bit decrypt: OK\n");

	kripto_block_destroy(s);

	/* 192-bit */
	s = kripto_block_create(kripto_block_lea, 0, k, 24);
	if(!s) puts("error");

	kripto_block_encrypt(s, pt192, t);
	for(i = 0; i < 16; i++) if(t[i] != ct192[i])
	{
		printf("192-bit encrypt: FAIL\n");
		break;
	}
	if(i == 16) printf("192-bit encrypt: OK\n");

	kripto_block_decrypt(s, ct192, t);
	for(i = 0; i < 16; i++) if(t[i] != pt192[i])
	{
		printf("192-bit decrypt: FAIL\n");
		break;
	}
	if(i == 16) printf("192-bit decrypt: OK\n");

	kripto_block_destroy(s);

	/* 256-bit */
	s = kripto_block_create(kripto_block_lea, 0, k, 32);
	if(!s) puts("error");

	kripto_block_encrypt(s, pt256, t);
	for(i = 0; i < 16; i++) if(t[i] != ct256[i])
	{
		printf("256-bit encrypt: FAIL\n");
		break;
	}
	if(i == 16) printf("256-bit encrypt: OK\n");

	kripto_block_decrypt(s, ct256, t);
	for(i = 0; i < 16; i++) if(t[i] != pt256[i])
	{
		printf("256-bit decrypt: FAIL\n");
		break;
	}
	if(i == 16) printf("256-bit decrypt: OK\n");

	kripto_block_destroy(s);

	return 0;
}
