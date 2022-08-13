/*
 * Copyright (C) 2022 by Gregor Pintar <grpintar@gmail.com>
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
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <kripto/cast.h>
#include <kripto/loadstore.h>
#include <kripto/rotate.h>
#include <kripto/memory.h>
#include <kripto/block.h>
#include <kripto/desc/block.h>

#include <kripto/block/shacal2.h>

struct kripto_block
{
	const kripto_desc_block *desc;
	unsigned int r;
	uint32_t *k;
};

static const uint32_t RC[128] =
{
	0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
	0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
	0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
	0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
	0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
	0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
	0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
	0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
	0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
	0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
	0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
	0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
	0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
	0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
	0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
	0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
	0xCA273ECE, 0xD186B8C7, 0xEADA7DD6, 0xF57D4F7F,
	0x06F067AA, 0x0A637DC5, 0x113F9804, 0x1B710B35,
	0x28DB77F5, 0x32CAAB7B, 0x3C9EBE0A, 0x431D67C4,
	0x4CC5D4BE, 0x597F299C, 0x5FCB6FAB, 0x6C44198C,
	0x7BA0EA2D, 0x7EABF2D0, 0x8DBE8D03, 0x90BB1721,
	0x99A2AD45, 0x9F86E289, 0xA84C4472, 0xB3DF34FC,
	0xB99BB8D7, 0xBC76CBAB, 0xC226A69A, 0xD304F19A,
	0xDE1BE20A, 0xE39BB437, 0xEE84927C, 0xF3EDD277,
	0xFBFDFE53, 0x0BEE2C7A, 0x0E90181C, 0x25F57204,
	0x2DA45582, 0x3A52C34C, 0x41DC0172, 0x495796FC,
	0x4BD31FC6, 0x533CDE21, 0x5F7ABFE3, 0x66C206B3,
	0x6DFCC6BC, 0x7062F20F, 0x778D5127, 0x7EABA3CC,
	0x8363ECCC, 0x85BE1C25, 0x93C04028, 0x9F4A205F,
	0xA1953565, 0xA627BB0F, 0xACFA8089, 0xB3C29B23,
	0xB602F6FA, 0xC36CEE0A, 0xC7DC81EE, 0xCE7B8471,
	0xD740288C, 0xE21DBA7A, 0xEABBFF66, 0xF56A9E60
};

#define CH(X0, X1, X2) (X2 ^ (X0 & (X1 ^ X2)))
#define MAJ(X0, X1, X2) ((X0 & X1) | (X2 & (X0 | X1)))

#define S0(X) (ROR32_07(X) ^ ROR32_18(X) ^ ((X) >> 3))
#define S1(X) (ROR32_17(X) ^ ROR32_19(X) ^ ((X) >> 10))

#define E0(X) (ROR32_02(X) ^ ROR32_13(X) ^ ROR32_22(X))
#define E1(X) (ROR32_06(X) ^ ROR32_11(X) ^ ROR32_25(X))

#define ROUND(A, B, C, D, E, F, G, H, RK)	\
{ 						\
	H += E1(E) + CH(E, F, G) + RK;		\
	D += H;					\
	H += E0(A) + MAJ(A, B, C);		\
}

#define IROUND(A, B, C, D, E, F, G, H, RK)	\
{ 						\
	H -= E0(A) + MAJ(A, B, C);		\
	D -= H;					\
	H -= E1(E) + CH(E, F, G) + RK;		\
}

static void shacal2_encrypt
(
	const kripto_block *s,
	const void *pt,
	void *ct
)
{
	uint32_t a = LOAD32B(CU8(pt)     );
	uint32_t b = LOAD32B(CU8(pt) +  4);
	uint32_t c = LOAD32B(CU8(pt) +  8);
	uint32_t d = LOAD32B(CU8(pt) + 12);
	uint32_t e = LOAD32B(CU8(pt) + 16);
	uint32_t f = LOAD32B(CU8(pt) + 20);
	uint32_t g = LOAD32B(CU8(pt) + 24);
	uint32_t h = LOAD32B(CU8(pt) + 28);

	for(unsigned int i = 0; i < s->r; i += 8)
	{
		ROUND(a, b, c, d, e, f, g, h, s->k[i    ]);
		ROUND(h, a, b, c, d, e, f, g, s->k[i + 1]);
		ROUND(g, h, a, b, c, d, e, f, s->k[i + 2]);
		ROUND(f, g, h, a, b, c, d, e, s->k[i + 3]);
		ROUND(e, f, g, h, a, b, c, d, s->k[i + 4]);
		ROUND(d, e, f, g, h, a, b, c, s->k[i + 5]);
		ROUND(c, d, e, f, g, h, a, b, s->k[i + 6]);
		ROUND(b, c, d, e, f, g, h, a, s->k[i + 7]);
	}

	STORE32B(a, U8(ct)     );
	STORE32B(b, U8(ct) +  4);
	STORE32B(c, U8(ct) +  8);
	STORE32B(d, U8(ct) + 12);
	STORE32B(e, U8(ct) + 16);
	STORE32B(f, U8(ct) + 20);
	STORE32B(g, U8(ct) + 24);
	STORE32B(h, U8(ct) + 28);
}

static void shacal2_decrypt
(
	const kripto_block *s,
	const void *ct,
	void *pt
)
{
	uint32_t a = LOAD32B(CU8(ct)     );
	uint32_t b = LOAD32B(CU8(ct) +  4);
	uint32_t c = LOAD32B(CU8(ct) +  8);
	uint32_t d = LOAD32B(CU8(ct) + 12);
	uint32_t e = LOAD32B(CU8(ct) + 16);
	uint32_t f = LOAD32B(CU8(ct) + 20);
	uint32_t g = LOAD32B(CU8(ct) + 24);
	uint32_t h = LOAD32B(CU8(ct) + 28);

	for(unsigned int i = s->r; i > 0; i -= 8)
	{
		IROUND(b, c, d, e, f, g, h, a, s->k[i - 1]);
		IROUND(c, d, e, f, g, h, a, b, s->k[i - 2]);
		IROUND(d, e, f, g, h, a, b, c, s->k[i - 3]);
		IROUND(e, f, g, h, a, b, c, d, s->k[i - 4]);
		IROUND(f, g, h, a, b, c, d, e, s->k[i - 5]);
		IROUND(g, h, a, b, c, d, e, f, s->k[i - 6]);
		IROUND(h, a, b, c, d, e, f, g, s->k[i - 7]);
		IROUND(a, b, c, d, e, f, g, h, s->k[i - 8]);
	}

	STORE32B(a, U8(pt)     );
	STORE32B(b, U8(pt) +  4);
	STORE32B(c, U8(pt) +  8);
	STORE32B(d, U8(pt) + 12);
	STORE32B(e, U8(pt) + 16);
	STORE32B(f, U8(pt) + 20);
	STORE32B(g, U8(pt) + 24);
	STORE32B(h, U8(pt) + 28);
}

static void shacal2_setup
(
	kripto_block *s,
	const void *key,
	unsigned int key_len
)
{
	memset(s->k, 0, 64);
	LOAD32B_ARRAY(key, s->k, key_len);

	for(unsigned int i = 16; i < s->r; i++)
	{
		s->k[i] = s->k[i - 16] + S0(s->k[i - 15]) + s->k[i - 7] + S1(s->k[i - 2]);
	}

	for(unsigned int i = 0; i < s->r; i++)
	{
		s->k[i] += RC[i];
	}
}

static kripto_block *shacal2_create
(
	const kripto_desc_block *desc,
	unsigned int r,
	const void *key,
	unsigned int key_len
)
{
	assert(r < 128);

	if(!r) r = 64;

	kripto_block *s = (kripto_block *)malloc(sizeof(kripto_block) + (r << 2));
	if(!s) return 0;

	s->desc = desc;
	s->k = (uint32_t *)(s + 1);
	s->r = r;
	shacal2_setup(s, key, key_len);

	return s;
}

static void shacal2_destroy(kripto_block *s)
{
	kripto_memory_wipe(s, sizeof(kripto_block) + (s->r << 2));
	free(s);
}

static kripto_block *shacal2_recreate
(
	kripto_block *s,
	unsigned int r,
	const void *key,
	unsigned int key_len
)
{
	assert(r < 128);

	if(!r) r = 64;

	if(r != s->r)
	{
		shacal2_destroy(s);
		s = shacal2_create(s->desc, r, key, key_len);
	}
	else
	{
		shacal2_setup(s, key, key_len);
	}

	return s;
}

static const kripto_desc_block shacal2 =
{
	&shacal2_create,
	&shacal2_recreate,
	0, /* tweak */
	&shacal2_encrypt,
	&shacal2_decrypt,
	&shacal2_destroy,
	32, /* block size */
	64, /* max key */
	0 /* max tweak */
};

const kripto_desc_block *const kripto_block_shacal2 = &shacal2;
