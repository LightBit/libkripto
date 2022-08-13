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
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <kripto/cast.h>
#include <kripto/loadstore.h>
#include <kripto/memory.h>
#include <kripto/block.h>
#include <kripto/desc/block.h>

#include <kripto/block/skipjack.h>

struct kripto_block
{
	const kripto_desc_block *desc;
	uint8_t k[10];
};

static const uint8_t S[256] =
{
	0xA3, 0xD7, 0x09, 0x83, 0xF8, 0x48, 0xF6, 0xF4, 
	0xB3, 0x21, 0x15, 0x78, 0x99, 0xB1, 0xAF, 0xF9, 
	0xE7, 0x2D, 0x4D, 0x8A, 0xCE, 0x4C, 0xCA, 0x2E, 
	0x52, 0x95, 0xD9, 0x1E, 0x4E, 0x38, 0x44, 0x28, 
	0x0A, 0xDF, 0x02, 0xA0, 0x17, 0xF1, 0x60, 0x68, 
	0x12, 0xB7, 0x7A, 0xC3, 0xE9, 0xFA, 0x3D, 0x53, 
	0x96, 0x84, 0x6B, 0xBA, 0xF2, 0x63, 0x9A, 0x19, 
	0x7C, 0xAE, 0xE5, 0xF5, 0xF7, 0x16, 0x6A, 0xA2, 
	0x39, 0xB6, 0x7B, 0x0F, 0xC1, 0x93, 0x81, 0x1B, 
	0xEE, 0xB4, 0x1A, 0xEA, 0xD0, 0x91, 0x2F, 0xB8, 
	0x55, 0xB9, 0xDA, 0x85, 0x3F, 0x41, 0xBF, 0xE0, 
	0x5A, 0x58, 0x80, 0x5F, 0x66, 0x0B, 0xD8, 0x90, 
	0x35, 0xD5, 0xC0, 0xA7, 0x33, 0x06, 0x65, 0x69, 
	0x45, 0x00, 0x94, 0x56, 0x6D, 0x98, 0x9B, 0x76, 
	0x97, 0xFC, 0xB2, 0xC2, 0xB0, 0xFE, 0xDB, 0x20, 
	0xE1, 0xEB, 0xD6, 0xE4, 0xDD, 0x47, 0x4A, 0x1D, 
	0x42, 0xED, 0x9E, 0x6E, 0x49, 0x3C, 0xCD, 0x43, 
	0x27, 0xD2, 0x07, 0xD4, 0xDE, 0xC7, 0x67, 0x18, 
	0x89, 0xCB, 0x30, 0x1F, 0x8D, 0xC6, 0x8F, 0xAA, 
	0xC8, 0x74, 0xDC, 0xC9, 0x5D, 0x5C, 0x31, 0xA4, 
	0x70, 0x88, 0x61, 0x2C, 0x9F, 0x0D, 0x2B, 0x87, 
	0x50, 0x82, 0x54, 0x64, 0x26, 0x7D, 0x03, 0x40, 
	0x34, 0x4B, 0x1C, 0x73, 0xD1, 0xC4, 0xFD, 0x3B, 
	0xCC, 0xFB, 0x7F, 0xAB, 0xE6, 0x3E, 0x5B, 0xA5, 
	0xAD, 0x04, 0x23, 0x9C, 0x14, 0x51, 0x22, 0xF0, 
	0x29, 0x79, 0x71, 0x7E, 0xFF, 0x8C, 0x0E, 0xE2, 
	0x0C, 0xEF, 0xBC, 0x72, 0x75, 0x6F, 0x37, 0xA1, 
	0xEC, 0xD3, 0x8E, 0x62, 0x8B, 0x86, 0x10, 0xE8, 
	0x08, 0x77, 0x11, 0xBE, 0x92, 0x4F, 0x24, 0xC5, 
	0x32, 0x36, 0x9D, 0xCF, 0xF3, 0xA6, 0xBB, 0xAC, 
	0x5E, 0x6C, 0xA9, 0x13, 0x57, 0x25, 0xB5, 0xE3, 
	0xBD, 0xA8, 0x3A, 0x01, 0x05, 0x59, 0x2A, 0x46
};

#define G(X, K0, K1, K2, K3)				\
{							\
	X ^= (uint16_t)S[((uint8_t)X) ^ s->k[K0]] << 8;	\
	X ^= (uint16_t)S[(X >>     8) ^ s->k[K1]];	\
	X ^= (uint16_t)S[((uint8_t)X) ^ s->k[K2]] << 8;	\
	X ^= (uint16_t)S[(X >>     8) ^ s->k[K3]];	\
}

#define IG(X, K0, K1, K2, K3)				\
{							\
	X ^= (uint16_t)S[(X >>     8) ^ s->k[K3]];	\
	X ^= (uint16_t)S[((uint8_t)X) ^ s->k[K2]] << 8;	\
	X ^= (uint16_t)S[(X >>     8) ^ s->k[K1]];	\
	X ^= (uint16_t)S[((uint8_t)X) ^ s->k[K0]] << 8;	\
}

static void skipjack_encrypt(const kripto_block *s, const void *pt, void *ct)
{
	uint16_t x0 = LOAD16L(CU8(pt) + 6);
	uint16_t x1 = LOAD16L(CU8(pt) + 4);
	uint16_t x2 = LOAD16L(CU8(pt) + 2);
	uint16_t x3 = LOAD16L(CU8(pt)    );

	/* Rule A */
	G(x0, 0, 1, 2, 3); x3 ^= x0 ^ 1;
	G(x3, 4, 5, 6, 7); x2 ^= x3 ^ 2;
	G(x2, 8, 9, 0, 1); x1 ^= x2 ^ 3;
	G(x1, 2, 3, 4, 5); x0 ^= x1 ^ 4;
	G(x0, 6, 7, 8, 9); x3 ^= x0 ^ 5;
	G(x3, 0, 1, 2, 3); x2 ^= x3 ^ 6;
	G(x2, 4, 5, 6, 7); x1 ^= x2 ^ 7;
	G(x1, 8, 9, 0, 1); x0 ^= x1 ^ 8;

	/* Rule B */
	x1 ^= x0 ^  9; G(x0, 2, 3, 4, 5);
	x0 ^= x3 ^ 10; G(x3, 6, 7, 8, 9);
	x3 ^= x2 ^ 11; G(x2, 0, 1, 2, 3);
	x2 ^= x1 ^ 12; G(x1, 4, 5, 6, 7);
	x1 ^= x0 ^ 13; G(x0, 8, 9, 0, 1);
	x0 ^= x3 ^ 14; G(x3, 2, 3, 4, 5);
	x3 ^= x2 ^ 15; G(x2, 6, 7, 8, 9);
	x2 ^= x1 ^ 16; G(x1, 0, 1, 2, 3);

	/* Rule A */
	G(x0, 4, 5, 6, 7); x3 ^= x0 ^ 17;
	G(x3, 8, 9, 0, 1); x2 ^= x3 ^ 18;
	G(x2, 2, 3, 4, 5); x1 ^= x2 ^ 19;
	G(x1, 6, 7, 8, 9); x0 ^= x1 ^ 20;
	G(x0, 0, 1, 2, 3); x3 ^= x0 ^ 21;
	G(x3, 4, 5, 6, 7); x2 ^= x3 ^ 22;
	G(x2, 8, 9, 0, 1); x1 ^= x2 ^ 23;
	G(x1, 2, 3, 4, 5); x0 ^= x1 ^ 24;

	/* Rule B */
	x1 ^= x0 ^ 25; G(x0, 6, 7, 8, 9);
	x0 ^= x3 ^ 26; G(x3, 0, 1, 2, 3);
	x3 ^= x2 ^ 27; G(x2, 4, 5, 6, 7);
	x2 ^= x1 ^ 28; G(x1, 8, 9, 0, 1);
	x1 ^= x0 ^ 29; G(x0, 2, 3, 4, 5);
	x0 ^= x3 ^ 30; G(x3, 6, 7, 8, 9);
	x3 ^= x2 ^ 31; G(x2, 0, 1, 2, 3);
	x2 ^= x1 ^ 32; G(x1, 4, 5, 6, 7);

	STORE16L(x0, U8(ct) + 6);
	STORE16L(x1, U8(ct) + 4);
	STORE16L(x2, U8(ct) + 2);
	STORE16L(x3, U8(ct)    );
}

static void skipjack_decrypt(const kripto_block *s, const void *ct, void *pt)
{
	uint16_t x0 = LOAD16L(CU8(ct) + 6);
	uint16_t x1 = LOAD16L(CU8(ct) + 4);
	uint16_t x2 = LOAD16L(CU8(ct) + 2);
	uint16_t x3 = LOAD16L(CU8(ct)    );

	/* Rule A */
	IG(x1, 4, 5, 6, 7); x2 ^= x1 ^ 32;
	IG(x2, 0, 1, 2, 3); x3 ^= x2 ^ 31;
	IG(x3, 6, 7, 8, 9); x0 ^= x3 ^ 30;
	IG(x0, 2, 3, 4, 5); x1 ^= x0 ^ 29;
	IG(x1, 8, 9, 0, 1); x2 ^= x1 ^ 28;
	IG(x2, 4, 5, 6, 7); x3 ^= x2 ^ 27;
	IG(x3, 0, 1, 2, 3); x0 ^= x3 ^ 26;
	IG(x0, 6, 7, 8, 9); x1 ^= x0 ^ 25;

	/* Rule B */
	x0 ^= x1 ^ 24; IG(x1, 2, 3, 4, 5);
	x1 ^= x2 ^ 23; IG(x2, 8, 9, 0, 1);
	x2 ^= x3 ^ 22; IG(x3, 4, 5, 6, 7);
	x3 ^= x0 ^ 21; IG(x0, 0, 1, 2, 3);
	x0 ^= x1 ^ 20; IG(x1, 6, 7, 8, 9);
	x1 ^= x2 ^ 19; IG(x2, 2, 3, 4, 5);
	x2 ^= x3 ^ 18; IG(x3, 8, 9, 0, 1);
	x3 ^= x0 ^ 17; IG(x0, 4, 5, 6, 7);

	/* Rule A */
	IG(x1, 0, 1, 2, 3); x2 ^= x1 ^ 16;
	IG(x2, 6, 7, 8, 9); x3 ^= x2 ^ 15;
	IG(x3, 2, 3, 4, 5); x0 ^= x3 ^ 14;
	IG(x0, 8, 9, 0, 1); x1 ^= x0 ^ 13;
	IG(x1, 4, 5, 6, 7); x2 ^= x1 ^ 12;
	IG(x2, 0, 1, 2, 3); x3 ^= x2 ^ 11;
	IG(x3, 6, 7, 8, 9); x0 ^= x3 ^ 10;
	IG(x0, 2, 3, 4, 5); x1 ^= x0 ^  9;

	/* Rule B */
	x0 ^= x1 ^ 8; IG(x1, 8, 9, 0, 1);
	x1 ^= x2 ^ 7; IG(x2, 4, 5, 6, 7);
	x2 ^= x3 ^ 6; IG(x3, 0, 1, 2, 3);
	x3 ^= x0 ^ 5; IG(x0, 6, 7, 8, 9);
	x0 ^= x1 ^ 4; IG(x1, 2, 3, 4, 5);
	x1 ^= x2 ^ 3; IG(x2, 8, 9, 0, 1);
	x2 ^= x3 ^ 2; IG(x3, 4, 5, 6, 7);
	x3 ^= x0 ^ 1; IG(x0, 0, 1, 2, 3);

	STORE16L(x0, U8(pt) + 6);
	STORE16L(x1, U8(pt) + 4);
	STORE16L(x2, U8(pt) + 2);
	STORE16L(x3, U8(pt)    );
}

static kripto_block *skipjack_recreate
(
	kripto_block *s,
	unsigned int r,
	const void *key,
	unsigned int key_len
)
{
	assert(!r || r == 32);
	(void)r;

	for(unsigned int i = 0; i < key_len; i++)
	{
		s->k[9 - i] = CU8(key)[i];
	}

	for(unsigned int i = key_len; i < 10; i++)
	{
		s->k[9 - i] = 0;
	}

	return s;
}

static kripto_block *skipjack_create
(
	const kripto_desc_block *desc,
	unsigned int r,
	const void *key,
	unsigned int key_len
)
{
	kripto_block *s = (kripto_block *)malloc(sizeof(kripto_block));
	if(!s) return 0;

	s->desc = desc;

	return skipjack_recreate(s, r, key, key_len);
}

static void skipjack_destroy(kripto_block *s)
{
	kripto_memory_wipe(s, sizeof(kripto_block));
	free(s);
}

static const kripto_desc_block skipjack =
{
	&skipjack_create,
	&skipjack_recreate,
	0, /* tweak */
	&skipjack_encrypt,
	&skipjack_decrypt,
	&skipjack_destroy,
	8, /* block size */
	10, /* max key */
	0 /* max tweak */
};

const kripto_desc_block *const kripto_block_skipjack = &skipjack;
