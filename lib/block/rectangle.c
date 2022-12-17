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
#include <string.h>
#include <assert.h>

#include <kripto/cast.h>
#include <kripto/rotate.h>
#include <kripto/loadstore.h>
#include <kripto/memory.h>
#include <kripto/block.h>
#include <kripto/desc/block.h>

#include <kripto/block/rectangle.h>

struct kripto_block
{
	const kripto_desc_block *desc;
	unsigned int rounds;
	uint16_t *k;
};

#define SUB_COLUMN(A, B, C, D)		\
{					\
	uint16_t T0 = C;		\
	C ^= B;				\
	B = ~B;				\
	uint16_t T1 = A;		\
	A &= B;				\
	B |= D;				\
	D ^= T0;			\
	A ^= D;				\
	B ^= T1;			\
	D &= B;				\
	D ^= C;				\
	C |= A;				\
	C ^= B;				\
	B ^= T0;			\
}

#define SHIFT_ROW(A, B, C, D)		\
{					\
	B = ROL16_01(B);		\
	C = ROL16_12(C);		\
	D = ROL16_13(D);		\
}

#define ADD_ROUND_KEY(A, B, C, D, K)	\
{					\
	A ^= K[0];			\
	B ^= K[1];			\
	C ^= K[2];			\
	D ^= K[3];			\
}

#define INV_SUB_COLUMN(A, B, C, D)	\
{					\
	uint16_t T = A;			\
	A &= C;				\
	A ^= D;				\
	D |= T;				\
	D ^= C;				\
	B ^= D;				\
	C = B;				\
	B ^= T;				\
	B ^= A;				\
	D = ~D;				\
	T = D;				\
	D |= B;				\
	D ^= A;				\
	A &= B;				\
	A ^= T;				\
}

#define INV_SHIFT_ROW(A, B, C, D)	\
{					\
	B = ROR16_01(B);		\
	C = ROR16_12(C);		\
	D = ROR16_13(D);		\
}

static const uint8_t rc[25] =
{
	0x01, 0x02, 0x04, 0x09, 0x12, 0x05, 0x0B, 0x16,
	0x0C, 0x19, 0x13, 0x07, 0x0F, 0x1F, 0x1E, 0x1C,
	0x18, 0x11, 0x03, 0x06, 0x0D, 0x1B, 0x17, 0x0E,
	0x1D
};

static void rectangle_setup
(
	kripto_block *s,
	const void *key,
	unsigned int key_len
)
{
	if(key_len > 10)
	{
		/* key longer than 80-bit */
		uint32_t k[4] = {0, 0, 0, 0};
		uint8_t t[4] = {0, 0, 0, 0};

		LOAD32B_ARRAY(key, k, key_len);

		for(unsigned int i = 0; i < s->rounds; i++)
		{
			/* output round key */
			s->k[(i << 2)    ] = k[0];
			s->k[(i << 2) + 1] = k[1];
			s->k[(i << 2) + 2] = k[2];
			s->k[(i << 2) + 3] = k[3];

			/* apply S-box on 8 right most bits */
			t[0] = k[0];
			t[1] = k[1];
			t[2] = k[2];
			t[3] = k[3];
			SUB_COLUMN(t[0], t[1], t[2], t[3]);
			k[0] = (k[0] & 0xFFFFFF00) | t[0];
			k[1] = (k[1] & 0xFFFFFF00) | t[1];
			k[2] = (k[2] & 0xFFFFFF00) | t[2];
			k[3] = (k[3] & 0xFFFFFF00) | t[3];

			/* feistel and rotation */
			uint32_t tk = k[0];
			k[0] = ROL32_08(k[0]) ^ k[1];
			k[1] = k[2];
			k[2] = ROL32_16(k[2]) ^ k[3];
			k[3] = tk;

			/* add round constant */
			k[0] ^= rc[i];
		}

		/* output last round key */
		s->k[(s->rounds << 2)    ] = k[0];
		s->k[(s->rounds << 2) + 1] = k[1];
		s->k[(s->rounds << 2) + 2] = k[2];
		s->k[(s->rounds << 2) + 3] = k[3];

		kripto_memory_wipe(k, 16);
		kripto_memory_wipe(t, 4);
	}
	else
	{
		/* 80-bit or shorter key */
		uint16_t k[5] = {0, 0, 0, 0, 0};
		uint16_t t[4];

		LOAD16B_ARRAY(key, k, key_len);

		for(unsigned int i = 0; i < s->rounds; i++)
		{
			/* output round key */
			memcpy(s->k + (i << 2), k, 8);

			/* apply S-box on 4 right most bits */
			memcpy(t, k, 8);
			SUB_COLUMN(t[0], t[1], t[2], t[3]);
			k[0] = (k[0] & 0xFFF0) | (t[0] & 0xF);
			k[1] = (k[1] & 0xFFF0) | (t[1] & 0xF);
			k[2] = (k[2] & 0xFFF0) | (t[2] & 0xF);
			k[3] = (k[3] & 0xFFF0) | (t[3] & 0xF);

			/* feistel and rotation */
			t[0] = k[0];
			k[0] = ROL16_08(k[0]) ^ k[1];
			k[1] = k[2];
			k[2] = k[3];
			k[3] = ROL16_12(k[3]) ^ k[4];
			k[4] = t[0];

			/* add round constant */
			k[0] ^= rc[i];
		}
		
		/* output last round key */
		memcpy(s->k + (s->rounds << 2), k, 8);

		kripto_memory_wipe(k, 10);
		kripto_memory_wipe(t, 8);
	}
}

static void rectangle_encrypt(const kripto_block *s, const void *pt, void *ct)
{
	uint16_t a = LOAD16B(CU8(pt));
	uint16_t b = LOAD16B(CU8(pt) + 2);
	uint16_t c = LOAD16B(CU8(pt) + 4);
	uint16_t d = LOAD16B(CU8(pt) + 6);
	uint16_t *k = s->k;

	for(; k < s->k + (s->rounds << 2); k += 4)
	{
		ADD_ROUND_KEY(a, b, c, d, k);
		SUB_COLUMN(a, b, c, d);
		SHIFT_ROW(a, b, c, d);
	}

	ADD_ROUND_KEY(a, b, c, d, k);

	STORE16B(a, U8(ct));
	STORE16B(b, U8(ct) + 2);
	STORE16B(c, U8(ct) + 4);
	STORE16B(d, U8(ct) + 6);
}
 
static void rectangle_decrypt(const kripto_block *s, const void *ct, void *pt)
{
	uint16_t a = LOAD16B(CU8(ct));
	uint16_t b = LOAD16B(CU8(ct) + 2);
	uint16_t c = LOAD16B(CU8(ct) + 4);
	uint16_t d = LOAD16B(CU8(ct) + 6);
	uint16_t *k = s->k + (s->rounds << 2);

	for(; k > s->k; k -= 4)
	{
		ADD_ROUND_KEY(a, b, c, d, k);
		INV_SHIFT_ROW(a, b, c, d);
		INV_SUB_COLUMN(a, b, c, d);
	}

	ADD_ROUND_KEY(a, b, c, d, k);

	STORE16B(a, U8(pt));
	STORE16B(b, U8(pt) + 2);
	STORE16B(c, U8(pt) + 4);
	STORE16B(d, U8(pt) + 6);
}

static kripto_block *rectangle_create
(
	const kripto_desc_block *desc,
	unsigned int r,
	const void *key,
	unsigned int key_len
)
{
	assert(r <= 25);

	if(!r) r = 25;

	kripto_block *s = (kripto_block *)malloc(sizeof(kripto_block) + ((r + 1) << 3));
	if(!s) return 0;

	s->desc = desc;
	s->rounds = r;
	s->k = (uint16_t *)(s + 1);

	rectangle_setup(s, key, key_len);

	return s;
}

static void rectangle_destroy(kripto_block *s)
{
	kripto_memory_wipe(s, sizeof(kripto_block) + ((s->rounds + 1) << 3));
	free(s);
}

static kripto_block *rectangle_recreate
(
	kripto_block *s,
	unsigned int r,
	const void *key,
	unsigned int key_len
)
{
	assert(r <= 25);

	if(!r) r = 25;

	if(r != s->rounds)
	{
		rectangle_destroy(s);
		s = rectangle_create(s->desc, r, key, key_len);
	}
	else
	{
		rectangle_setup(s, key, key_len);
	}

	return s;
}

static const kripto_desc_block rectangle =
{
	&rectangle_create,
	&rectangle_recreate,
	0, /* tweak */
	&rectangle_encrypt,
	&rectangle_decrypt,
	&rectangle_destroy,
	8, /* block size */
	16, /* max key */
	0 /* max tweak */
};

const kripto_desc_block *const kripto_block_rectangle = &rectangle;
