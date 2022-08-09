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
#include <kripto/block/xtea.h>

int main(void)
{
	kripto_block *s;
	unsigned int i;
	unsigned int n;
	uint8_t t[8] =
	{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};
	const uint8_t k[16] =
	{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
	};
	const uint8_t pt[8] =
	{
		0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48
	};
	const uint8_t ct[16][8] =
	{
		{0xA0, 0x39, 0x05, 0x89, 0xF8, 0xB8, 0xEF, 0xA5},
		{0xB5, 0x6D, 0x5A, 0xA4, 0x70, 0xB6, 0xE0, 0x8C},
		{0x73, 0x90, 0x10, 0xB4, 0xF3, 0x6A, 0xA9, 0xF1},
		{0x73, 0x1B, 0xB8, 0x46, 0x45, 0x29, 0x9E, 0x65},
		{0xB8, 0x4F, 0x4A, 0x9D, 0x30, 0xCB, 0x31, 0x57},
		{0xD0, 0x4D, 0x97, 0x18, 0xE4, 0x2F, 0x12, 0xD3},
		{0xC7, 0x32, 0x38, 0x99, 0xEA, 0x99, 0x74, 0xC2},
		{0xC0, 0x36, 0x07, 0x02, 0x4A, 0xD8, 0xE4, 0x24},
		{0x29, 0x1F, 0xD6, 0xF3, 0x49, 0x83, 0x79, 0x6E},
		{0x84, 0x0A, 0x43, 0xD0, 0x73, 0xE0, 0xB1, 0x5B},
		{0x1E, 0x6C, 0xC1, 0xA9, 0x17, 0x1B, 0x60, 0xF1},
		{0x51, 0xEA, 0x6A, 0x4D, 0x09, 0x68, 0x79, 0x0F},
		{0xF8, 0x12, 0xD3, 0xF4, 0xCB, 0xE2, 0x30, 0xB5},
		{0x2E, 0x02, 0x84, 0xAC, 0x58, 0xB9, 0x34, 0xB5},
		{0x0D, 0x9E, 0x10, 0x95, 0x83, 0x62, 0x06, 0x60},
		{0x49, 0x7D, 0xF3, 0xD0, 0x72, 0x61, 0x2C, 0xB5}
	};

	puts("kripto_block_xtea");

	for(n = 1; n <= 16; n++)
	{
		s = kripto_block_create(kripto_block_xtea, 0, k, n);
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
