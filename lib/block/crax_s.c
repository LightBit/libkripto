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

#include <kripto/block/crax_s.h>

struct kripto_block
{
	const kripto_desc_block *desc;
	unsigned int steps;
	uint32_t k[4];
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

#define KEY(X, Y, K, STEP)	\
{				\
	if(STEP & 1)		\
	{			\
		X ^= K[2];	\
		Y ^= K[3];	\
	}			\
	else			\
	{			\
		X ^= K[0];	\
		Y ^= K[1];	\
	}			\
}

static const uint32_t rcon[5] =
{
	0xB7E15162, 0xBF715880, 0x38B4DA56, 0x324E7738, 0xBB1185EB
};

static void crax_s_setup
(
	kripto_block *s,
	const void *key,
	unsigned int key_len
)
{
	s->k[3] = s->k[2] = s->k[1] = s->k[0] = 0;
	LOAD32L_ARRAY(key, s->k, key_len);
}

static void crax_s_encrypt(const kripto_block *s, const void *pt, void *ct)
{
	uint32_t x = LOAD32L(CU8(pt));
	uint32_t y = LOAD32L(CU8(pt) + 4);

	for(unsigned int i = 0; i < s->steps; i++)
	{
		x ^= i;
		KEY(x, y, s->k, i);
		ALZETTE(x, y, rcon[i % 5]);
	}

	KEY(x, y, s->k, s->steps);

	STORE32L(x, U8(ct));
	STORE32L(y, U8(ct) + 4);
}
 
static void crax_s_decrypt(const kripto_block *s, const void *ct, void *pt)
{
	uint32_t x = LOAD32L(CU8(ct));
	uint32_t y = LOAD32L(CU8(ct) + 4);

	KEY(x, y, s->k, s->steps);

	for(unsigned int i = s->steps; i-- > 0;)
	{
		ALZETTE_INV(x, y, rcon[i % 5]);
		KEY(x, y, s->k, i);
		x ^= i;
	}

	STORE32L(x, U8(pt));
	STORE32L(y, U8(pt) + 4);
}

static kripto_block *crax_s_create
(
	const kripto_desc_block *desc,
	unsigned int r,
	const void *key,
	unsigned int key_len
)
{
	if(!r) r = 10;

	kripto_block *s = (kripto_block *)malloc(sizeof(kripto_block));
	if(!s) return 0;

	s->desc = desc;
	s->steps = r;

	crax_s_setup(s, key, key_len);

	return s;
}

static void crax_s_destroy(kripto_block *s)
{
	kripto_memory_wipe(s, sizeof(kripto_block));
	free(s);
}

static kripto_block *crax_s_recreate
(
	kripto_block *s,
	unsigned int r,
	const void *key,
	unsigned int key_len
)
{
	if(!r) r = 10;

	s->steps = r;

	crax_s_setup(s, key, key_len);

	return s;
}

static const kripto_desc_block crax_s =
{
	.create = &crax_s_create,
	.recreate = &crax_s_recreate,
	.tweak = 0,
	.encrypt = &crax_s_encrypt,
	.decrypt = &crax_s_decrypt,
	.destroy = &crax_s_destroy,
	.blocksize = 8,
	.maxkey = 16,
	.maxtweak = 0
};

const kripto_desc_block *const kripto_block_crax_s = &crax_s;
