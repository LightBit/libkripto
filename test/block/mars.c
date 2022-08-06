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
#include <string.h>

#include <kripto/block.h>
#include <kripto/block/mars.h>

int main(void)
{
	kripto_block *s;
	uint8_t t[16];
	const uint8_t k128[16] =
	{
		0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};
	const uint8_t pt128[16] =
	{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};
	const uint8_t ct128[16] =
	{
		0x4B, 0xBB, 0x91, 0x9E, 0x52, 0xC2, 0x58, 0x96,
		0x05, 0x49, 0xFA, 0xE9, 0xDD, 0x5F, 0xF5, 0x24
	};
	const uint8_t k192[24] =
	{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 
	};
	const uint8_t pt192[16] =
	{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 
	};
	const uint8_t ct192[16] =
	{
		0x1A, 0x4D, 0x5C, 0x52, 0xFD, 0xDE, 0xE8, 0x13,
		0x74, 0x29, 0x53, 0x41, 0xF9, 0x50, 0x05, 0x5D
	};
	const uint8_t k256[32] =
	{
		0xFB, 0xA1, 0x67, 0x98, 0x3E, 0x7A, 0xEF, 0x22,
		0x31, 0x7C, 0xE2, 0x8C, 0x02, 0xAA, 0xE1, 0xA3,
		0xE8, 0xE5, 0xCC, 0x3C, 0xED, 0xBE, 0xA8, 0x2A,
		0x99, 0xDB, 0xC3, 0x9A, 0xD6, 0x5E, 0x72, 0x27  
	};
	const uint8_t pt256[16] =
	{
		0x13, 0x44, 0xAB, 0xA4, 0xD3, 0xC4, 0x47, 0x08,
		0xA8, 0xA7, 0x21, 0x16, 0xD4, 0xF4, 0x93, 0x84 
	};
	const uint8_t ct256[16] =
	{
		0x45, 0x83, 0x35, 0xD9, 0x5E, 0xA4, 0x2A, 0x9F,
		0x4D, 0xCC, 0xD4, 0x1A, 0xEC, 0xC2, 0x39, 0x0D
	};

	puts("kripto_block_mars");

	/* 128-bit key */
	s = kripto_block_create(kripto_block_mars, 0, k128, 16);
	if(!s) puts("error");

	kripto_block_encrypt(s, pt128, t);
	if(memcmp(t, ct128, 16)) puts("128-bit key encrypt: FAIL");
	else puts("128-bit key encrypt: OK");

	kripto_block_decrypt(s, ct128, t);
	if(memcmp(t, pt128, 16)) puts("128-bit key decrypt: FAIL");
	else puts("128-bit key decrypt: OK");

	/* 192-bit key */
	s = kripto_block_recreate(s, 0, k192, 24);
	if(!s) puts("error");

	kripto_block_encrypt(s, pt192, t);
	if(memcmp(t, ct192, 16)) puts("192-bit key encrypt: FAIL");
	else puts("192-bit key encrypt: OK");

	kripto_block_decrypt(s, ct192, t);
	if(memcmp(t, pt192, 16)) puts("192-bit key decrypt: FAIL");
	else puts("192-bit key decrypt: OK");

	/* 256-bit key */
	s = kripto_block_recreate(s, 0, k256, 32);
	if(!s) puts("error");

	kripto_block_encrypt(s, pt256, t);
	if(memcmp(t, ct256, 16)) puts("256-bit key encrypt: FAIL");
	else puts("256-bit key encrypt: OK");

	kripto_block_decrypt(s, ct256, t);
	if(memcmp(t, pt256, 16)) puts("256-bit key decrypt: FAIL");
	else puts("256-bit key decrypt: OK");

	kripto_block_destroy(s);

	return 0;
}
