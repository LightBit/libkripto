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

/* written and placed in the public domain by Wei Dai */

#include <stdint.h>
#include <stdlib.h>

#include <kripto/cast.h>
#include <kripto/loadstore.h>
#include <kripto/memory.h>
#include <kripto/block.h>
#include <kripto/desc/block.h>
#include <kripto/object/block.h>

#include <kripto/block/idea.h>

struct kripto_block
{
	struct kripto_block_object obj;
	unsigned int r;
	uint16_t *ek;
	uint16_t *dk;
};

#define LO16(X) ((uint16_t)(X))
#define HI16(X) ((X) >> 16)

static inline uint16_t MUL(uint16_t a, uint16_t b)
{
	uint32_t p = a * b;

	if(p)
	{
		p = LO16(p) - HI16(p);
		return LO16(p) - HI16(p);
	}
	else return 1 - a - b;
}

static inline uint16_t INV_MUL(uint16_t x)
{
	unsigned int i;
	uint16_t y = x;

	for(i = 0; i < 15; i++)
	{
		y = MUL(y, y);
		y = MUL(y, x);
	}

	return y;
}

#define INV_ADD(X) ((uint16_t)(-(X)))

static void idea_setup
(
	kripto_block *s,
	const uint8_t *key,
	unsigned int key_len
)
{
	unsigned int i;
	unsigned int j;

	/* encryption key */
	for(i = 0; i < 8; i++) s->ek[i] = 0;
	LOAD16B_ARRAY(key, s->ek, key_len);

	for(i = 8; i < (6 * s->r + 4); i++)
	{
		j = (i & ~7) - 8;

		s->ek[i] = LO16((s->ek[j + ((i + 1) & 7)] << 9)
			| (s->ek[j + ((i + 2) & 7)] >> 7));
	}

	/* decryption key */
	for(i = 0; i < s->r; i++)
	{
		s->dk[i * 6] = INV_MUL(s->ek[(s->r - i) * 6]);
		s->dk[i * 6 + 1] = INV_ADD(s->ek[(s->r - i) * 6 + 1 + (i > 0)]);
		s->dk[i * 6 + 2] = INV_ADD(s->ek[(s->r - i) * 6 + 2 - (i > 0)]);
		s->dk[i * 6 + 3] = INV_MUL(s->ek[(s->r - i) * 6 + 3]);
		s->dk[i * 6 + 4] = s->ek[(s->r - 1 - i) * 6 + 4];
		s->dk[i * 6 + 5] = s->ek[(s->r - 1 - i) * 6 + 5];
	}

	s->dk[i * 6] = INV_MUL(s->ek[(s->r - i) * 6]);
	s->dk[i * 6 + 1] = INV_ADD(s->ek[(s->r - i) * 6 + 1]);
	s->dk[i * 6 + 2] = INV_ADD(s->ek[(s->r - i) * 6 + 2]);
	s->dk[i * 6 + 3] = INV_MUL(s->ek[(s->r - i) * 6 + 3]);
}

static void idea_crypt
(
	const uint16_t *k,
	unsigned int r,
	const void *in,
	void *out
)
{
	uint16_t x0 = LOAD16B(CU8(in));
	uint16_t x1 = LOAD16B(CU8(in) + 2);
	uint16_t x2 = LOAD16B(CU8(in) + 4);
	uint16_t x3 = LOAD16B(CU8(in) + 6);
	uint16_t t0;
	uint16_t t1;
	unsigned int i = 0;

	while(i < r * 6)
	{
		x0 = MUL(x0, k[i++]);
		x1 += k[i++];
		x2 += k[i++];
		x3 = MUL(x3, k[i++]);
		t0 = x0 ^ x2; 
		t0 = MUL(t0, k[i++]);
		t1 = t0 + (x1 ^ x3);
		t1 = MUL(t1, k[i++]);
		t0 += t1;
		x0 ^= t1;
		x3 ^= t0;
		t0 ^= x1;
		x1 = x2 ^ t1;
		x2 = t0;
	}

	x0 = MUL(x0, k[i++]);
	x2 += k[i++];
	x1 += k[i++];
	x3 = MUL(x3, k[i++]);

	STORE16B(x0, U8(out));
	STORE16B(x2, U8(out) + 2);
	STORE16B(x1, U8(out) + 4);
	STORE16B(x3, U8(out) + 6);
}

static void idea_encrypt
(
	const kripto_block *s,
	const void *pt,
	void *ct
)
{
	idea_crypt(s->ek, s->r, pt, ct);
}

static void idea_decrypt
(
	const kripto_block *s,
	const void *ct,
	void *pt
)
{
	idea_crypt(s->dk, s->r, ct, pt);
}

static kripto_block *idea_create
(
	const kripto_block_desc *desc,
	unsigned int r,
	const void *key,
	unsigned int key_len
)
{
	kripto_block *s;

	if(!r) r = 8;

	s = (kripto_block *)malloc(sizeof(kripto_block) + r * 24 + 16);
	if(!s) return 0;

	s->obj.desc = desc;
	s->ek = (uint16_t *)(s + 1);
	s->dk = s->ek + r * 6 + 4;
	s->r = r;

	idea_setup(s, (const uint8_t *)key, key_len);

	return s;
}

static void idea_destroy(kripto_block *s)
{
	kripto_memory_wipe(s, sizeof(kripto_block) + s->r * 24 + 16);
	free(s);
}

static kripto_block *idea_recreate
(
	kripto_block *s,
	unsigned int r,
	const void *key,
	unsigned int key_len
)
{
	if(!r) r = 8;

	if(r != s->r)
	{
		idea_destroy(s);
		s = idea_create(s->obj.desc, r, key, key_len);
	}
	else
	{
		idea_setup(s, (const uint8_t *)key, key_len);
	}

	return s;
}

static const kripto_block_desc idea =
{
	&idea_create,
	&idea_recreate,
	0, /* tweak */
	&idea_encrypt,
	&idea_decrypt,
	&idea_destroy,
	8, /* block size */
	16, /* max key */
	0 /* max tweak */
};

const kripto_block_desc *const kripto_block_idea = &idea;
