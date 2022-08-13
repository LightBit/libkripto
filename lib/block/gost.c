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

#include <kripto/cast.h>
#include <kripto/loadstore.h>
#include <kripto/rotate.h>
#include <kripto/memory.h>
#include <kripto/block.h>
#include <kripto/desc/block.h>
#include <kripto/object/block.h>

#include <kripto/block/gost.h>

struct kripto_block
{
	struct kripto_block_object obj;
	unsigned int r;
	const unsigned char *s0;
	const unsigned char *s1;
	const unsigned char *s2;
	const unsigned char *s3;
	const unsigned char *s4;
	const unsigned char *s5;
	const unsigned char *s6;
	const unsigned char *s7;
	uint32_t *k;
};

#define S(X)						\
(							\
	((uint32_t)s->s7[((X) >> 28) & 0xF] << 28) |	\
	((uint32_t)s->s6[((X) >> 24) & 0xF] << 24) |	\
	((uint32_t)s->s5[((X) >> 20) & 0xF] << 20) |	\
	((uint32_t)s->s4[((X) >> 16) & 0xF] << 16) |	\
	((uint32_t)s->s3[((X) >> 12) & 0xF] << 12) |	\
	((uint32_t)s->s2[((X) >>  8) & 0xF] <<  8) |	\
	((uint32_t)s->s1[((X) >>  4) & 0xF] <<  4) |	\
	((uint32_t)s->s0[((X)      ) & 0xF]      )	\
)

static inline uint32_t f(const kripto_block *s, uint32_t x)
{
	x = S(x);
	return ROL32_11(x);
}

static void gost_encrypt
(
	const kripto_block *s,
	const void *pt,
	void *ct
)
{
	uint32_t l = LOAD32L(CU8(pt)    );
	uint32_t r = LOAD32L(CU8(pt) + 4);

	for(unsigned int i = 0; i < s->r;)
	{
		r ^= f(s, l + s->k[i++]);
		l ^= f(s, r + s->k[i++]);
	}

	STORE32L(r, U8(ct)    );
	STORE32L(l, U8(ct) + 4);
}

static void gost_decrypt
(
	const kripto_block *s,
	const void *ct,
	void *pt
)
{
	uint32_t l = LOAD32L(CU8(ct)    );
	uint32_t r = LOAD32L(CU8(ct) + 4);

	for(unsigned int i = s->r; i;)
	{
		r ^= f(s, l + s->k[--i]);
		l ^= f(s, r + s->k[--i]);
	}

	STORE32L(r, U8(pt)    );
	STORE32L(l, U8(pt) + 4);
}

static void gost_setup
(
	kripto_block *s,
	const void *key,
	unsigned int key_len
)
{
	unsigned int i;
	unsigned int j;

	for(i = 0; i < (key_len + 3) >> 2; i++)
		s->k[i] = 0;

	for(i = key_len; i;)
	{
		i--;
		s->k[i >> 2] = (s->k[i >> 2] << 8) | CU8(key)[i];
	}

	key_len = (key_len + 3) >> 2;

	for(i = key_len, j = 0; s->r - i > key_len; i++)
	{
		s->k[i] = s->k[j];

		if(++j == key_len) j = 0;
	}

	/* reversed */
	for(j = key_len; j; i++)
	{
		s->k[i] = s->k[--j];
	}
}

struct gost
{
	const unsigned char (*sboxes)[16];
};

static kripto_block *gost_create
(
	const kripto_block_desc *desc,
	unsigned int r,
	const void *key,
	unsigned int key_len
)
{
	kripto_block *s;

	if(!r) r = 32;

	s = (kripto_block *)malloc(sizeof(kripto_block) + (r << 2));
	if(!s) return 0;

	s->obj.desc = desc;
	s->r = r;
	s->k = (uint32_t *)(s + 1);

	const struct gost *gost = (const struct gost *)(desc + 1);
	s->s0 = gost->sboxes[0];
	s->s1 = gost->sboxes[1];
	s->s2 = gost->sboxes[2];
	s->s3 = gost->sboxes[3];
	s->s4 = gost->sboxes[4];
	s->s5 = gost->sboxes[5];
	s->s6 = gost->sboxes[6];
	s->s7 = gost->sboxes[7];

	gost_setup(s, key, key_len);

	return s;
}

static void gost_destroy(kripto_block *s)
{
	kripto_memory_wipe(s, sizeof(kripto_block) + (s->r << 2));
	free(s);
}

static kripto_block *gost_recreate
(
	kripto_block *s,
	unsigned int r,
	const void *key,
	unsigned int key_len
)
{
	if(!r) r = 32;

	if(r != s->r)
	{
		gost_destroy(s);
		s = gost_create(s->obj.desc, r, key, key_len);
	}
	else
	{
		gost_setup(s, key, key_len);
	}

	return s;
}

kripto_block_desc *kripto_block_gost(const unsigned char (*sboxes)[16])
{
	kripto_block_desc *desc = (kripto_block_desc *)malloc(sizeof(kripto_block_desc) + sizeof(struct gost));

	desc->create = &gost_create;
	desc->recreate = &gost_recreate;
	desc->tweak = 0;
	desc->encrypt = &gost_encrypt;
	desc->decrypt = &gost_decrypt;
	desc->destroy = &gost_destroy;
	desc->blocksize = 8;
	desc->maxkey = 32;
	desc->maxtweak = 0;

	struct gost *gost = (struct gost *)(desc + 1);
	gost->sboxes = sboxes;

	return desc;
}

static const unsigned char CBR[8][16] =
{
	{0x4, 0xA, 0x9, 0x2, 0xD, 0x8, 0x0, 0xE, 0x6, 0xB, 0x1, 0xC, 0x7, 0xF, 0x5, 0x3},
	{0xE, 0xB, 0x4, 0xC, 0x6, 0xD, 0xF, 0xA, 0x2, 0x3, 0x8, 0x1, 0x0, 0x7, 0x5, 0x9},
	{0x5, 0x8, 0x1, 0xD, 0xA, 0x3, 0x4, 0x2, 0xE, 0xF, 0xC, 0x7, 0x6, 0x0, 0x9, 0xB},
	{0x7, 0xD, 0xA, 0x1, 0x0, 0x8, 0x9, 0xF, 0xE, 0x4, 0x6, 0xC, 0xB, 0x2, 0x5, 0x3},
	{0x6, 0xC, 0x7, 0x1, 0x5, 0xF, 0xD, 0x8, 0x4, 0xA, 0x9, 0xE, 0x0, 0x3, 0xB, 0x2},
	{0x4, 0xB, 0xA, 0x0, 0x7, 0x2, 0x1, 0xD, 0x3, 0x6, 0x8, 0x5, 0x9, 0xC, 0xF, 0xE},
	{0xD, 0xB, 0x4, 0x1, 0x3, 0xF, 0x5, 0x9, 0x0, 0xA, 0xE, 0x7, 0x6, 0x8, 0x2, 0xC},
	{0x1, 0xF, 0xD, 0x0, 0x5, 0x7, 0xA, 0x4, 0x9, 0x2, 0x3, 0xE, 0x6, 0xB, 0x8, 0xC}
};

kripto_block_desc *kripto_block_gost_cbr(void)
{
	return kripto_block_gost(CBR);
}

static const unsigned char R34_12_2015[8][16] =
{
	{0xC, 0x4, 0x6, 0x2, 0xA, 0x5, 0xB, 0x9, 0xE, 0x8, 0xD, 0x7, 0x0, 0x3, 0xF, 0x1},
	{0x6, 0x8, 0x2, 0x3, 0x9, 0xA, 0x5, 0xC, 0x1, 0xE, 0x4, 0x7, 0xB, 0xD, 0x0, 0xF},
	{0xB, 0x3, 0x5, 0x8, 0x2, 0xF, 0xA, 0xD, 0xE, 0x1, 0x7, 0x4, 0xC, 0x9, 0x6, 0x0},
	{0xC, 0x8, 0x2, 0x1, 0xD, 0x4, 0xF, 0x6, 0x7, 0x0, 0xA, 0x5, 0x3, 0xE, 0x9, 0xB},
	{0x7, 0xF, 0x5, 0xA, 0x8, 0x1, 0x6, 0xD, 0x0, 0x9, 0x3, 0xE, 0xB, 0x4, 0x2, 0xC},
	{0x5, 0xD, 0xF, 0x6, 0x9, 0x2, 0xC, 0xA, 0xB, 0x7, 0x8, 0x1, 0x4, 0x3, 0xE, 0x0},
	{0x8, 0xE, 0x2, 0x5, 0x6, 0x9, 0x1, 0xC, 0xF, 0x4, 0xB, 0x0, 0xD, 0xA, 0x3, 0x7},
	{0x1, 0x7, 0xE, 0xD, 0x0, 0x5, 0x8, 0x3, 0x4, 0xF, 0xA, 0x6, 0x9, 0xC, 0xB, 0x2}
};

kripto_block_desc *kripto_block_gost_r34_12_2015(void)
{
	return kripto_block_gost(R34_12_2015);
}
