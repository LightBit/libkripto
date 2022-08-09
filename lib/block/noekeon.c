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
#include <kripto/object/block.h>

#include <kripto/block/noekeon.h>

struct kripto_block
{
	struct kripto_block_object obj;
	unsigned int rounds;
	uint32_t k[4];
	uint32_t dk[4];
};

static const uint8_t rc[34] =
{
	0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A,
	0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A,
	0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39,
	0x72, 0xE4, 0xD3, 0xBD, 0x61, 0xC2, 0x9F, 0x25,
	0x4A, 0x94
};

#define THETA(X0, X1, X2, X3, K0, K1, K2, K3)	\
{						\
	T = X0 ^ X2;				\
	T ^= ROL32_08(T) ^ ROR32_08(T);		\
	X1 ^= T;				\
	X3 ^= T;				\
	X0 ^= K0; X1 ^= K1; X2 ^= K2; X3 ^= K3;	\
	T = X1 ^ X3;				\
	T ^= ROL32_08(T) ^ ROR32_08(T);		\
	X0 ^= T;				\
	X2 ^= T;				\
}

#define GAMMA(X0, X1, X2, X3)		\
{					\
	X1 ^= ~(X3 | X2);		\
	X0 ^= X2 & X1;			\
	T = X3; X3 = X0; X0 = T;	\
	X2 ^= X0 ^ X1 ^ X3;		\
	X1 ^= ~(X3 | X2);		\
	X0 ^= X2 & X1;			\
}

#define PI1(X1, X2, X3)		\
{				\
	X1 = ROL32_01(X1);	\
	X2 = ROL32_05(X2);	\
	X3 = ROL32_02(X3);	\
}

#define PI2(X1, X2, X3)		\
{				\
	X1 = ROR32_01(X1);	\
	X2 = ROR32_05(X2);	\
	X3 = ROR32_02(X3);	\
}

static void noekeon_encrypt
(
	const kripto_block *s,
	const void *pt,
	void *ct
)
{
	uint32_t x0;
	uint32_t x1;
	uint32_t x2;
	uint32_t x3;
	uint32_t T;
	unsigned int r;

	x0 = LOAD32B(CU8(pt));
	x1 = LOAD32B(CU8(pt) + 4);
	x2 = LOAD32B(CU8(pt) + 8);
	x3 = LOAD32B(CU8(pt) + 12);

	for(r = 0; r < s->rounds; r++)
	{
		x0 ^= rc[r];
		THETA(x0, x1, x2, x3, s->k[0], s->k[1], s->k[2], s->k[3]);
		PI1(x1, x2, x3);
		GAMMA(x0, x1, x2, x3);
		PI2(x1, x2, x3);
	}
	x0 ^= rc[r];
	THETA(x0, x1, x2, x3, s->k[0], s->k[1], s->k[2], s->k[3]);

	STORE32B(x0, U8(ct));
	STORE32B(x1, U8(ct) + 4);
	STORE32B(x2, U8(ct) + 8);
	STORE32B(x3, U8(ct) + 12);
}

static void noekeon_decrypt
(
	const kripto_block *s,
	const void *ct,
	void *pt
)
{
	uint32_t x0;
	uint32_t x1;
	uint32_t x2;
	uint32_t x3;
	uint32_t T;
	unsigned int r;

	x0 = LOAD32B(CU8(ct));
	x1 = LOAD32B(CU8(ct) + 4);
	x2 = LOAD32B(CU8(ct) + 8);
	x3 = LOAD32B(CU8(ct) + 12);

	for(r = s->rounds; r; r--)
	{
		THETA(x0, x1, x2, x3, s->dk[0], s->dk[1], s->dk[2], s->dk[3]);
		x0 ^= rc[r];
		PI1(x1, x2, x3);
		GAMMA(x0, x1, x2, x3);
		PI2(x1, x2, x3);
	}
	THETA(x0, x1, x2, x3, s->dk[0], s->dk[1], s->dk[2], s->dk[3]);
	x0 ^= rc[r];

	STORE32B(x0, U8(pt));
	STORE32B(x1, U8(pt) + 4);
	STORE32B(x2, U8(pt) + 8);
	STORE32B(x3, U8(pt) + 12);
}

static void noekeon_setup
(
	kripto_block *s,
	const uint8_t *key,
	unsigned int key_len
)
{
	uint32_t T;

	if(!s->rounds) s->rounds = 16;

	/* direct mode */
	s->k[0] = s->k[1] = s->k[2] = s->k[3] = 0;
	LOAD32B_ARRAY(key, s->k, key_len);

	/* decryption key */
	s->dk[0] = s->k[0];
	s->dk[1] = s->k[1];
	s->dk[2] = s->k[2];
	s->dk[3] = s->k[3];
	THETA(s->dk[0], s->dk[1], s->dk[2], s->dk[3], 0, 0, 0, 0);
}

static kripto_block *noekeon_create
(
	unsigned int r,
	const void *key,
	unsigned int key_len
)
{
	kripto_block *s = (kripto_block *)malloc(sizeof(kripto_block));
	if(!s) return 0;

	s->obj.desc = kripto_block_noekeon;
	s->rounds = r;

	noekeon_setup(s, (const uint8_t *)key, key_len);

	return s;
}

static kripto_block *noekeon_recreate
(
	kripto_block *s,
	unsigned int r,
	const void *key,
	unsigned int key_len
)
{
	s->rounds = r;
	noekeon_setup(s, (const uint8_t *)key, key_len);

	return s;
}

static void noekeon_destroy(kripto_block *s)
{
	kripto_memory_wipe(s, sizeof(kripto_block));
	free(s);
}

static const kripto_block_desc noekeon =
{
	&noekeon_create,
	&noekeon_recreate,
	0, /* tweak */
	&noekeon_encrypt,
	&noekeon_decrypt,
	&noekeon_destroy,
	16, /* block size */
	16, /* max key */
	0 /* max tweak */
};

const kripto_block_desc *const kripto_block_noekeon = &noekeon;
