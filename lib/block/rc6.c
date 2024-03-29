/*
 * Copyright (C) 2011 by Gregor Pintar <grpintar@gmail.com>
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
#include <limits.h>

#include <kripto/cast.h>
#include <kripto/loadstore.h>
#include <kripto/rotate.h>
#include <kripto/memory.h>
#include <kripto/block.h>
#include <kripto/desc/block.h>

#include <kripto/block/rc6.h>

struct kripto_block
{
	const kripto_desc_block *desc;
	unsigned int rounds;
	uint32_t *k;
};

#define RC6_K_LEN(r) (((r) + 2) << 1)

static void rc6_setup
(
	kripto_block *s,
	const uint8_t *key,
	unsigned int key_len
)
{
	unsigned int i;
	unsigned int j;
	unsigned int k;
	const unsigned int ls = (key_len + 3) >> 2;
	uint32_t a;
	uint32_t b;
	uint32_t x[64];

	for(i = 0; i < ls; i++) x[i] = 0;
	LOAD32L_ARRAY(key, x, key_len);

	*s->k = 0xB7E15163;
	for(i = 1; i < RC6_K_LEN(s->rounds); i++)
		s->k[i] = s->k[i-1] + 0x9E3779B9;

	a = b = i = j = k = 0;
	while(k < RC6_K_LEN(s->rounds) * 3)
	{
		a = s->k[i] = ROL32_03(s->k[i] + a + b);
		b = x[j] = ROL32(x[j] + a + b, a + b);
		if(++i == RC6_K_LEN(s->rounds)) i = 0;
		if(++j == ls) j = 0;
		k++;
	}

	/* wipe */
	kripto_memory_wipe(x, ls << 2);
	kripto_memory_wipe(&a, sizeof(uint32_t));
	kripto_memory_wipe(&b, sizeof(uint32_t));
}

static void rc6_encrypt(const kripto_block *s, const void *pt, void *ct)
{
	uint32_t a;
	uint32_t b;
	uint32_t c;
	uint32_t d;
	uint32_t m0;
	uint32_t m1;
	uint32_t t;
	unsigned int i = 2;

	a = LOAD32L(CU8(pt));
	b = LOAD32L(CU8(pt) + 4);
	c = LOAD32L(CU8(pt) + 8);
	d = LOAD32L(CU8(pt) + 12);

	b += s->k[0];
	d += s->k[1];

	while(i <= (s->rounds << 1))
	{
		m0 = ROL32_05(b * ((b << 1) | 1));
		m1 = ROL32_05(d * ((d << 1) | 1));

		t = ROL32(a ^ m0, m1) + s->k[i++];
		a = b;
		b = ROL32(c ^ m1, m0) + s->k[i++];
		c = d;
		d = t;
	}

	a += s->k[i];
	c += s->k[i + 1];

	STORE32L(a, U8(ct));
	STORE32L(b, U8(ct) + 4);
	STORE32L(c, U8(ct) + 8);
	STORE32L(d, U8(ct) + 12);
}

static void rc6_decrypt(const kripto_block *s, const void *ct, void *pt)
{
	uint32_t a;
	uint32_t b;
	uint32_t c;
	uint32_t d;
	uint32_t m0;
	uint32_t m1;
	uint32_t t;
	unsigned int i = s->rounds << 1;

	a = LOAD32L(CU8(ct));
	b = LOAD32L(CU8(ct) + 4);
	c = LOAD32L(CU8(ct) + 8);
	d = LOAD32L(CU8(ct) + 12);

	a -= s->k[i + 2];
	c -= s->k[i + 3];

	while(i)
	{
		m0 = ROL32_05(a * ((a << 1) | 1));
		m1 = ROL32_05(c * ((c << 1) | 1));

		t = d;
		d = c;
		c = ROR32(b - s->k[i + 1], m0) ^ m1;
		b = a;
		a = ROR32(t - s->k[i], m1) ^ m0;

		i -= 2;
	}

	b -= s->k[0];
	d -= s->k[1];

	STORE32L(a, U8(pt));
	STORE32L(b, U8(pt) + 4);
	STORE32L(c, U8(pt) + 8);
	STORE32L(d, U8(pt) + 12);
}

static kripto_block *rc6_create
(
	const kripto_desc_block *desc,
	unsigned int r,
	const void *key,
	unsigned int key_len
)
{
	kripto_block *s;

	if(!r) r = 20;

	s = (kripto_block *)malloc(sizeof(kripto_block) + (RC6_K_LEN(r) << 2));
	if(!s) return 0;

	s->desc = desc;
	s->rounds = r;
	s->k = (uint32_t *)(s + 1);

	rc6_setup(s, (const uint8_t *)key, key_len);

	return s;
}

static void rc6_destroy(kripto_block *s)
{
	kripto_memory_wipe(s, sizeof(kripto_block) + (RC6_K_LEN(s->rounds) << 2));
	free(s);
}

static kripto_block *rc6_recreate
(
	kripto_block *s,
	unsigned int r,
	const void *key,
	unsigned int key_len
)
{
	if(!r) r = 20;

	if(r != s->rounds)
	{
		rc6_destroy(s);
		s = rc6_create(s->desc, r, key, key_len);
	}
	else
	{
		rc6_setup(s, (const uint8_t *)key, key_len);
	}

	return s;
}

static const kripto_desc_block rc6 =
{
	&rc6_create,
	&rc6_recreate,
	0, /* tweak */
	&rc6_encrypt,
	&rc6_decrypt,
	&rc6_destroy,
	16, /* block size */
	255, /* max key */
	0 /* max tweak */
};

const kripto_desc_block *const kripto_block_rc6 = &rc6;
