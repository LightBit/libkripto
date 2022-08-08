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
#include <kripto/block/sm4.h>

int main(void)
{
	const uint8_t k[16] =
	{
		0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
		0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF
	};
	const uint8_t pt[16] =
	{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
	};
	const uint8_t ct[16] =
	{
		0xF7, 0x66, 0x67, 0x8F, 0x13, 0xF0, 0x1A, 0xDE,
		0xAC, 0x1B, 0x3E, 0xA9, 0x55, 0xAD, 0xB5, 0x94
	};
	kripto_block *s;
	unsigned int i;
	uint8_t t[16];

	puts("kripto_block_sm4");

	s = kripto_block_create(kripto_block_sm4, 0, k, 16);
	if(!s) puts("error");

	kripto_block_encrypt(s, pt, t);
	for(i = 0; i < 16; i++) if(t[i] != ct[i])
	{
		printf("Encrypt: FAIL\n");
		break;
	}
	if(i == 16) printf("Encrypt: OK\n");

	kripto_block_decrypt(s, ct, t);
	for(i = 0; i < 16; i++) if(t[i] != pt[i])
	{
		printf("Decrypt: FAIL\n");
		break;
	}
	if(i == 16) printf("Decrypt: OK\n");

	kripto_block_destroy(s);

	return 0;
}
