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
#include <kripto/block/tea.h>

int main(void)
{
	kripto_block *s;
	unsigned int i;
	uint8_t t[8];
	const uint8_t k[16] =
	{
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF
	};
	const uint8_t pt[8] =
	{
		0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF
	};
	const uint8_t ct[8] =
	{
		0x12, 0x6C, 0x6B, 0x92, 0xC0, 0x65, 0x3A, 0x3E
	};

	puts("kripto_block_tea");

	/* 128-bit key */
	s = kripto_block_create(kripto_block_tea, 0, k, 16);
	if(!s) puts("error");

	kripto_block_encrypt(s, pt, t);
	for(i = 0; i < 8; i++) if(t[i] != ct[i])
	{
		puts("128-bit key encrypt: FAIL");
		break;
	}
	if(i == 8) puts("128-bit key encrypt: OK");

	kripto_block_decrypt(s, ct, t);
	for(i = 0; i < 8; i++) if(t[i] != pt[i])
	{
		puts("128-bit key decrypt: FAIL");
		break;
	}
	if(i == 8) puts("128-bit key decrypt: OK");

	kripto_block_destroy(s);

	return 0;
}
