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

#include <kripto/block/speck32.h>

struct kripto_block
{
	const kripto_desc_block *desc;
	unsigned int rounds;
	uint16_t *k;
};

#define R(A, B, K)			\
{					\
	A = (ROR16_07(A) + B) ^ (K);	\
	B = ROL16_02(B) ^ A;		\
}

#define IR(A, B, K)			\
{					\
	B = ROR16_02(B ^ A);		\
	A = ROL16_07((A ^ (K)) - B);	\
}

static void speck32_encrypt
(
	const kripto_block *s,
	const void *pt,
	void *ct
)
{
	uint16_t a = LOAD16L(CU8(pt) + 2);
	uint16_t b = LOAD16L(CU8(pt)    );

	for(unsigned int i = 0; i < s->rounds; i++)
		R(a, b, s->k[i]);

	STORE16L(a, U8(ct) + 2);
	STORE16L(b, U8(ct)    );
}

static void speck32_decrypt
(
	const kripto_block *s,
	const void *ct,
	void *pt
)
{
	uint16_t a = LOAD16L(CU8(ct) + 2);
	uint16_t b = LOAD16L(CU8(ct)    );

	for(unsigned int i = s->rounds; i--;)
		IR(a, b, s->k[i]);

	STORE16L(a, U8(pt) + 2);
	STORE16L(b, U8(pt)    );
}

static void speck32_setup
(
	kripto_block *s,
	const void *key,
	unsigned int len
)
{
	uint16_t k[4] = {0, 0, 0, 0};
	unsigned int m = ((len + 1) >> 1) - 1;

	LOAD16L_ARRAY(key, k, len);

	s->k[0] = k[0];

	for(unsigned int i = 0; i < s->rounds - 1;)
	{
		unsigned int a = (i % m) + 1;
		R(k[a], k[0], i);
		s->k[++i] = k[0];
	}

	kripto_memory_wipe(k, 8);
}

static kripto_block *speck32_create
(
	const kripto_desc_block *desc,
	unsigned int r,
	const void *key,
	unsigned int key_len
)
{
	kripto_block *s;

	if(!r) r = 22;

	s = (kripto_block *)malloc(sizeof(kripto_block) + (r << 1));
	if(!s) return 0;

	s->desc = desc;
	s->k = (uint16_t *)(s + 1);
	s->rounds = r;

	speck32_setup(s, key, key_len);

	return s;
}

static void speck32_destroy(kripto_block *s)
{
	kripto_memory_wipe(s, sizeof(kripto_block) + (s->rounds << 1));
	free(s);
}

static kripto_block *speck32_recreate
(
	kripto_block *s,
	unsigned int r,
	const void *key,
	unsigned int key_len
)
{
	if(!r) r = 22;

	if(r != s->rounds)
	{
		speck32_destroy(s);
		s = speck32_create(s->desc, r, key, key_len);
	}
	else
	{
		speck32_setup(s, key, key_len);
	}

	return s;
}

static const kripto_desc_block speck32 =
{
	&speck32_create,
	&speck32_recreate,
	0, /* tweak */
	&speck32_encrypt,
	&speck32_decrypt,
	&speck32_destroy,
	4, /* block size */
	8, /* max key */
	0 /* max tweak */
};

const kripto_desc_block *const kripto_block_speck32 = &speck32;
