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
#include <stdlib.h>

#include <kripto/cast.h>
#include <kripto/rotate.h>
#include <kripto/loadstore.h>
#include <kripto/memory.h>
#include <kripto/block.h>
#include <kripto/desc/block.h>

#include <kripto/block/trax_m.h>

struct kripto_block
{
	const kripto_desc_block *desc;
	unsigned int steps;
	uint32_t *k;
	uint32_t tweak[2];
};

#define ALZETTE(X, Y, C)	\
{				\
	X += ROR32_31(Y);	\
	Y ^= ROR32_24(X);	\
	X ^= C;			\
	X += ROR32_17(Y);	\
	Y ^= ROR32_17(X);	\
	X ^= C;			\
	X += Y;			\
	Y ^= ROR32_31(X);	\
	X ^= C;			\
	X += ROR32_24(Y);	\
	Y ^= ROR32_16(X);	\
	X ^= C;			\
}

#define ALZETTE_INV(X, Y, C)	\
{				\
	X ^= C;			\
	Y ^= ROR32_16(X);	\
	X -= ROR32_24(Y);	\
	X ^= C;			\
	Y ^= ROR32_31(X);	\
	X -= Y;			\
	X ^= C;			\
	Y ^= ROR32_17(X);	\
	X -= ROR32_17(Y);	\
	X ^= C;			\
	Y ^= ROR32_24(X);	\
	X -= ROR32_31(Y);	\
}

static const uint32_t rcon[8] =
{
	0xB7E15162, 0xBF715880, 0x38B4DA56, 0x324E7738,
	0xBB1185EB, 0x4F7C7B57, 0xCFBFA1C8, 0xC2B3293D
};

static void trax_m_setup
(
	kripto_block *s,
	const void *key,
	unsigned int key_len
)
{
	uint32_t *k = s->k;

	s->tweak[1] = s->tweak[0] = 0;
	k[3] = k[2] = k[1] = k[0] = 0;
	LOAD32L_ARRAY(key, k, key_len);

	for(unsigned int i = 0; i < s->steps; i++, k += 4)
	{
		k[7] = k[0] + k[1] + rcon[i & 7];
		k[4] = k[1];
		k[5] = k[2] ^ k[3] ^ i;
		k[6] = k[3];
	}
}

static void trax_m_encrypt(const kripto_block *s, const void *pt, void *ct)
{
	uint32_t x0 = LOAD32L(CU8(pt)     );
	uint32_t y0 = LOAD32L(CU8(pt) +  4);
	uint32_t x1 = LOAD32L(CU8(pt) +  8);
	uint32_t y1 = LOAD32L(CU8(pt) + 12);

	for(unsigned int i = 0; i < s->steps; i++)
	{
		if(i & 1)
		{
			x0 ^= s->tweak[0];
			y0 ^= s->tweak[1];
		}

		x0 ^= s->k[(i << 2)    ];
		y0 ^= s->k[(i << 2) + 1];
		x1 ^= s->k[(i << 2) + 2];
		y1 ^= s->k[(i << 2) + 3];

		uint32_t c;

		c = rcon[((i << 1)    ) & 7];
		ALZETTE(x0, y0, c);

		c = rcon[((i << 1) + 1) & 7];
		ALZETTE(x1, y1, c);

		uint32_t xt = x0 ^ x1; x1 = x0; x0 = xt;
		uint32_t yt = y0 ^ y1; y1 = y0; y0 = yt;
	}
	
	x0 ^= s->k[(s->steps << 2)    ];
	y0 ^= s->k[(s->steps << 2) + 1];
	x1 ^= s->k[(s->steps << 2) + 2];
	y1 ^= s->k[(s->steps << 2) + 3];

	STORE32L(x0, U8(ct)     );
	STORE32L(y0, U8(ct) +  4);
	STORE32L(x1, U8(ct) +  8);
	STORE32L(y1, U8(ct) + 12);
}
 
static void trax_m_decrypt(const kripto_block *s, const void *ct, void *pt)
{
	uint32_t x0 = LOAD32L(CU8(ct)     );
	uint32_t y0 = LOAD32L(CU8(ct) +  4);
	uint32_t x1 = LOAD32L(CU8(ct) +  8);
	uint32_t y1 = LOAD32L(CU8(ct) + 12);

	x0 ^= s->k[(s->steps << 2)    ];
	y0 ^= s->k[(s->steps << 2) + 1];
	x1 ^= s->k[(s->steps << 2) + 2];
	y1 ^= s->k[(s->steps << 2) + 3];

	for(unsigned int i = s->steps; i-- > 0;)
	{
		uint32_t xt = x0 ^ x1; x0 = x1; x1 = xt;
		uint32_t yt = y0 ^ y1; y0 = y1; y1 = yt;

		uint32_t c;

		c = rcon[((i << 1)    ) & 7];
		ALZETTE_INV(x0, y0, c);

		c = rcon[((i << 1) + 1) & 7];
		ALZETTE_INV(x1, y1, c);

		x0 ^= s->k[(i << 2)    ];
		y0 ^= s->k[(i << 2) + 1];
		x1 ^= s->k[(i << 2) + 2];
		y1 ^= s->k[(i << 2) + 3];

		if(i & 1)
		{
			x0 ^= s->tweak[0];
			y0 ^= s->tweak[1];
		}
	}

	STORE32L(x0, U8(pt)     );
	STORE32L(y0, U8(pt) +  4);
	STORE32L(x1, U8(pt) +  8);
	STORE32L(y1, U8(pt) + 12);
}

static kripto_block *trax_m_create
(
	const kripto_desc_block *desc,
	unsigned int r,
	const void *key,
	unsigned int key_len
)
{
	if(!r) r = 14;

	kripto_block *s = (kripto_block *)malloc(sizeof(kripto_block) + ((r + 1) << 4));
	if(!s) return 0;

	s->desc = desc;
	s->steps = r;
	s->k = (uint32_t *)(s + 1);

	trax_m_setup(s, key, key_len);

	return s;
}

static void trax_m_destroy(kripto_block *s)
{
	kripto_memory_wipe(s, sizeof(kripto_block) + ((s->steps + 1) << 4));
	free(s);
}

static kripto_block *trax_m_recreate
(
	kripto_block *s,
	unsigned int r,
	const void *key,
	unsigned int key_len
)
{
	if(!r) r = 14;

	if(r != s->steps)
	{
		trax_m_destroy(s);
		s = trax_m_create(s->desc, r, key, key_len);
	}
	else
	{
		trax_m_setup(s, key, key_len);
	}

	return s;
}

static void trax_m_tweak
(
	kripto_block *s,
	const void *tweak,
	unsigned int tweak_len
)
{
	s->tweak[1] = s->tweak[0] = 0;
	LOAD32L_ARRAY(tweak, s->tweak, tweak_len);
}

static const kripto_desc_block trax_m =
{
	.create = &trax_m_create,
	.recreate = &trax_m_recreate,
	.tweak = &trax_m_tweak,
	.encrypt = &trax_m_encrypt,
	.decrypt = &trax_m_decrypt,
	.destroy = &trax_m_destroy,
	.blocksize = 16,
	.maxkey = 16,
	.maxtweak = 8
};

const kripto_desc_block *const kripto_block_trax_m = &trax_m;
