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

/* this XTEA implementation is big endian */

#include <stdint.h>
#include <stdlib.h>
#include <limits.h>

#include <kripto/cast.h>
#include <kripto/loadstore.h>
#include <kripto/memory.h>
#include <kripto/block.h>
#include <kripto/desc/block.h>

#include <kripto/block/xtea.h>

struct kripto_block
{
	const kripto_desc_block *desc;
	unsigned int rounds;
	uint32_t *k;
};

static void xtea_setup
(
	kripto_block *s,
	const void *key,
	unsigned int key_len
)
{
	uint32_t c = 0;
	uint32_t k[4] = {0, 0, 0, 0};
	unsigned int i;

	LOAD32B_ARRAY(key, k, key_len);

	key_len = (key_len + 3) >> 2;
	i = 0;
	while(i < s->rounds)
	{
		s->k[i++] = c + k[c % key_len];
		if(i == s->rounds) break;
		c += 0x9E3779B9;
		s->k[i++] = c + k[(c >> 11) % key_len];
	}

	kripto_memory_wipe(k, 16);
}

#define F(X) ((((X) << 4) ^ ((X) >> 5)) + (X))

static void xtea_encrypt(const kripto_block *s, const void *pt, void *ct)
{
	uint32_t x0 = LOAD32B(CU8(pt));
	uint32_t x1 = LOAD32B(CU8(pt) + 4);
	unsigned int i = 0;

	while(i < s->rounds)
	{
		x0 += F(x1) ^ s->k[i++];

		if(i == s->rounds) break;

		x1 += F(x0) ^ s->k[i++];
	}

	STORE32B(x0, U8(ct));
	STORE32B(x1, U8(ct) + 4);
}
 
static void xtea_decrypt(const kripto_block *s, const void *ct, void *pt)
{
	uint32_t x0 = LOAD32B(CU8(ct));
	uint32_t x1 = LOAD32B(CU8(ct) + 4);
	unsigned int i = s->rounds;

	while(i)
	{
		x1 -= F(x0) ^ s->k[--i];

		if(i == UINT_MAX) break;

		x0 -= F(x1) ^ s->k[--i];
	}

	STORE32B(x0, U8(pt));
	STORE32B(x1, U8(pt) + 4);
}

static kripto_block *xtea_create
(
	const kripto_desc_block *desc,
	unsigned int r,
	const void *key,
	unsigned int key_len
)
{
	kripto_block *s;

	if(!r) r = 64;

	s = (kripto_block *)malloc(sizeof(kripto_block) + (r << 2));
	if(!s) return 0;

	s->desc = desc;
	s->rounds = r;
	s->k = (uint32_t *)(s + 1);

	xtea_setup(s, key, key_len);

	return s;
}

static void xtea_destroy(kripto_block *s)
{
	kripto_memory_wipe(s, sizeof(kripto_block) + (s->rounds << 2));
	free(s);
}

static kripto_block *xtea_recreate
(
	kripto_block *s,
	unsigned int r,
	const void *key,
	unsigned int key_len
)
{
	if(!r) r = 64;

	if(r != s->rounds)
	{
		xtea_destroy(s);
		s = xtea_create(s->desc, r, key, key_len);
	}
	else
	{
		xtea_setup(s, key, key_len);
	}

	return s;
}

static const kripto_desc_block xtea =
{
	&xtea_create,
	&xtea_recreate,
	0, /* tweak */
	&xtea_encrypt,
	&xtea_decrypt,
	&xtea_destroy,
	8, /* block size */
	16, /* max key */
	0 /* max tweak */
};

const kripto_desc_block *const kripto_block_xtea = &xtea;
