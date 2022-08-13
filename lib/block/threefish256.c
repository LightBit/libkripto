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
#include <limits.h>

#include <kripto/cast.h>
#include <kripto/loadstore.h>
#include <kripto/rotate.h>
#include <kripto/memory.h>
#include <kripto/block.h>
#include <kripto/desc/block.h>
#include <kripto/object/block.h>

#include <kripto/block/threefish256.h>

#define C240 0x1BD11BDAA9FC1A22

struct kripto_block
{
	struct kripto_block_object obj;
	unsigned int rounds;
	uint64_t t[3];
	uint64_t k[5];
};

static void threefish256_tweak
(
	kripto_block *s,
	const void *tweak,
	unsigned int len
)
{
	s->t[0] = s->t[1] = 0;
	LOAD64L_ARRAY(tweak, s->t, len);
	s->t[2] = s->t[0] ^ s->t[1];
}

static void threefish256_encrypt
(
	const kripto_block *s,
	const void *pt,
	void *ct
)
{
	uint64_t x0 = LOAD64L(CU8(pt)) + s->k[0];
	uint64_t x1 = LOAD64L(CU8(pt) + 8) + s->k[1] + s->t[0];
	uint64_t x2 = LOAD64L(CU8(pt) + 16) + s->k[2] + s->t[1];
	uint64_t x3 = LOAD64L(CU8(pt) + 24) + s->k[3];
	unsigned int r = 1;

	while(r <= s->rounds >> 2)
	{
		x0 += x1; x1 = ROL64_14(x1); x1 ^= x0;
		x2 += x3; x3 = ROL64_16(x3); x3 ^= x2;

		x0 += x3; x3 = ROL64_52(x3); x3 ^= x0;
		x2 += x1; x1 = ROL64_57(x1); x1 ^= x2;

		x0 += x1; x1 = ROL64_23(x1); x1 ^= x0;
		x2 += x3; x3 = ROL64_40(x3); x3 ^= x2;

		x0 += x3; x3 = ROL64_05(x3); x3 ^= x0;
		x2 += x1; x1 = ROL64_37(x1); x1 ^= x2;

		x0 += s->k[r % 5];
		x1 += s->k[(r + 1) % 5] + s->t[r % 3];
		x2 += s->k[(r + 2) % 5] + s->t[(r + 1) % 3];
		x3 += s->k[(r + 3) % 5] + r;
		r++;

		x0 += x1; x1 = ROL64_25(x1); x1 ^= x0;
		x2 += x3; x3 = ROL64_33(x3); x3 ^= x2;

		x0 += x3; x3 = ROL64_46(x3); x3 ^= x0;
		x2 += x1; x1 = ROL64_12(x1); x1 ^= x2;

		x0 += x1; x1 = ROL64_58(x1); x1 ^= x0;
		x2 += x3; x3 = ROL64_22(x3); x3 ^= x2;

		x0 += x3; x3 = ROL64_32(x3); x3 ^= x0;
		x2 += x1; x1 = ROL64_32(x1); x1 ^= x2;

		x0 += s->k[r % 5];
		x1 += s->k[(r + 1) % 5] + s->t[r % 3];
		x2 += s->k[(r + 2) % 5] + s->t[(r + 1) % 3];
		x3 += s->k[(r + 3) % 5] + r;
		r++;
	}

	STORE64L(x0, U8(ct));
	STORE64L(x1, U8(ct) + 8);
	STORE64L(x2, U8(ct) + 16);
	STORE64L(x3, U8(ct) + 24);
}

static void threefish256_decrypt
(
	const kripto_block *s,
	const void *ct,
	void *pt
)
{
	uint64_t x0 = LOAD64L(CU8(ct));
	uint64_t x1 = LOAD64L(CU8(ct) + 8);
	uint64_t x2 = LOAD64L(CU8(ct) + 16);
	uint64_t x3 = LOAD64L(CU8(ct) + 24);
	unsigned int r = s->rounds >> 2;

	while(r > 1)
	{
		x0 -= s->k[r % 5];
		x1 -= s->k[(r + 1) % 5] + s->t[r % 3];
		x2 -= s->k[(r + 2) % 5] + s->t[(r + 1) % 3];
		x3 -= s->k[(r + 3) % 5] + r;
		r--;

		x1 = ROR64_32(x1 ^ x2); x2 -= x1;
		x3 = ROR64_32(x3 ^ x0); x0 -= x3;

		x3 = ROR64_22(x3 ^ x2); x2 -= x3;
		x1 = ROR64_58(x1 ^ x0); x0 -= x1;

		x1 = ROR64_12(x1 ^ x2); x2 -= x1;
		x3 = ROR64_46(x3 ^ x0); x0 -= x3;

		x3 = ROR64_33(x3 ^ x2); x2 -= x3;
		x1 = ROR64_25(x1 ^ x0); x0 -= x1;

		x0 -= s->k[r % 5];
		x1 -= s->k[(r + 1) % 5] + s->t[r % 3];
		x2 -= s->k[(r + 2) % 5] + s->t[(r + 1) % 3];
		x3 -= s->k[(r + 3) % 5] + r;
		r--;

		x1 = ROR64_37(x1 ^ x2); x2 -= x1;
		x3 = ROR64_05(x3 ^ x0); x0 -= x3;

		x3 = ROR64_40(x3 ^ x2); x2 -= x3;
		x1 = ROR64_23(x1 ^ x0); x0 -= x1;

		x1 = ROR64_57(x1 ^ x2); x2 -= x1;
		x3 = ROR64_52(x3 ^ x0); x0 -= x3;

		x3 = ROR64_16(x3 ^ x2); x2 -= x3;
		x1 = ROR64_14(x1 ^ x0); x0 -= x1;
	}

	x0 -= s->k[0];
	x1 -= s->k[1] + s->t[0];
	x2 -= s->k[2] + s->t[1];
	x3 -= s->k[3];

	STORE64L(x0, U8(pt));
	STORE64L(x1, U8(pt) + 8);
	STORE64L(x2, U8(pt) + 16);
	STORE64L(x3, U8(pt) + 24);
}

static kripto_block *threefish256_recreate
(
	kripto_block *s,
	unsigned int r,
	const void *key,
	unsigned int key_len
)
{
	s->rounds = r;
	if(!s->rounds) s->rounds = 72;

	memset(s->k, 0, 32);
	LOAD64L_ARRAY(key, s->k, key_len);

	s->k[4] = s->k[0] ^ s->k[1] ^ s->k[2] ^ s->k[3] ^ C240;
	s->t[0] = s->t[1] = s->t[2] = 0;

	return s;
}

static kripto_block *threefish256_create
(
	const kripto_block_desc *desc,
	unsigned int r,
	const void *key,
	unsigned int key_len
)
{
	kripto_block *s = (kripto_block *)malloc(sizeof(kripto_block));
	if(!s) return 0;

	s->obj.desc = desc;

	return threefish256_recreate(s, r, key, key_len);
}

static void threefish256_destroy(kripto_block *s)
{
	kripto_memory_wipe(s, sizeof(kripto_block));
	free(s);
}

static const kripto_block_desc threefish256 =
{
	&threefish256_create,
	&threefish256_recreate,
	&threefish256_tweak,
	&threefish256_encrypt,
	&threefish256_decrypt,
	&threefish256_destroy,
	32, /* block size */
	32, /* max key */
	16 /* max tweak */
};

const kripto_block_desc *const kripto_block_threefish256 = &threefish256;
