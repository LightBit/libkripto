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
#include <kripto/block/saferpp.h>

int main(void)
{
	kripto_block *s;
	unsigned int i;
	uint8_t t[16];
	const uint8_t k128[16] =
	{
		 14, 124, 101,  64,  89, 188, 122, 187,
		246, 253, 175, 117, 255, 129, 140, 227
	};
	const uint8_t pt128[16] =
	{
		228, 132, 172,  71, 177, 114,  30, 129,
		148,  87,  10,  40, 154, 151, 152, 217
	};
	const uint8_t ct128[16] =
	{
		172, 213, 197,  38, 238, 168, 124,  19,
		 89,  29,   8, 168, 169, 239, 120, 215
	};
	const uint8_t k256[32] =
	{
		 37,  62,   2, 187, 247, 187, 241, 247,
		 95, 108, 103,  64, 202, 151, 222,  47,
		231, 196, 221, 136, 201,  51, 141, 171,
		 73,  86,  77,  44,  81,  57, 102,  94
	};
	const uint8_t pt256[16] =
	{
		 91, 130, 138,  43, 142,  69, 112,  44,
		176, 173,   7,  56,  91, 131,  69, 122
	};
	const uint8_t ct256[16] =
	{
		153,  67, 204, 235,  31,  58, 117,  85,
		127,  71,  55,  73, 210, 217, 159, 186
	};

	puts("kripto_block_saferpp");

	/* 128-bit */
	s = kripto_block_create(kripto_block_saferpp, 0, k128, 16);
	if(!s) puts("error");

	kripto_block_encrypt(s, pt128, t);
	for(i = 0; i < 16; i++) if(t[i] != ct128[i])
	{
		printf("128-bit key encrypt: FAIL\n");
		break;
	}
	if(i == 16) printf("128-bit key encrypt: OK\n");

	kripto_block_decrypt(s, ct128, t);
	for(i = 0; i < 16; i++) if(t[i] != pt128[i])
	{
		printf("128-bit key decrypt: FAIL\n");
		break;
	}
	if(i == 16) printf("128-bit key decrypt: OK\n");

	kripto_block_destroy(s);
	
	/* 256-bit */
	s = kripto_block_create(kripto_block_saferpp, 0, k256, 32);
	if(!s) puts("error");

	kripto_block_encrypt(s, pt256, t);
	for(i = 0; i < 16; i++) if(t[i] != ct256[i])
	{
		printf("256-bit key encrypt: FAIL\n");
		break;
	}
	if(i == 16) printf("256-bit key encrypt: OK\n");

	kripto_block_decrypt(s, ct256, t);
	for(i = 0; i < 16; i++) if(t[i] != pt256[i])
	{
		printf("256-bit key decrypt: FAIL\n");
		break;
	}
	if(i == 16) printf("256-bit key decrypt: OK\n");

	kripto_block_destroy(s);

	return 0;
}
