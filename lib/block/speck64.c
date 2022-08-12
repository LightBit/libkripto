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

#include <kripto/block/speck64.h>

struct kripto_block
{
	struct kripto_block_object obj;
	unsigned int rounds;
	uint32_t *k;
};

#define R(A, B, K)			\
{					\
	A = (ROR32_08(A) + B) ^ (K);	\
	B = ROL32_03(B) ^ A;		\
}

#define IR(A, B, K)			\
{					\
	B = ROR32_03(B ^ A);		\
	A = ROL32_08((A ^ (K)) - B);	\
}

static void speck64_encrypt
(
	const kripto_block *s,
	const void *pt,
	void *ct
)
{
	uint32_t a = LOAD32L(CU8(pt) + 4);
	uint32_t b = LOAD32L(CU8(pt)    );

	for(unsigned int i = 0; i < s->rounds; i++)
		R(a, b, s->k[i]);

	STORE32L(a, U8(ct) + 4);
	STORE32L(b, U8(ct)    );
}

static void speck64_decrypt
(
	const kripto_block *s,
	const void *ct,
	void *pt
)
{
	uint32_t a = LOAD32L(CU8(ct) + 4);
	uint32_t b = LOAD32L(CU8(ct)    );

	for(unsigned int i = s->rounds; i--;)
		IR(a, b, s->k[i]);

	STORE32L(a, U8(pt) + 4);
	STORE32L(b, U8(pt)    );
}

static void speck64_setup
(
	kripto_block *s,
	const void *key,
	unsigned int len
)
{
	uint32_t k[4] = {0, 0, 0, 0};
	unsigned int m = ((len + 3) >> 2) - 1;

	LOAD32L_ARRAY(key, k, len);

	s->k[0] = k[0];

	for(unsigned int i = 0; i < s->rounds - 1;)
	{
		unsigned int a = (i % m) + 1;
		R(k[a], k[0], i);
		s->k[++i] = k[0];
	}

	kripto_memory_wipe(k, 16);
}

static kripto_block *speck64_create
(
	unsigned int r,
	const void *key,
	unsigned int key_len
)
{
	kripto_block *s;

	if(!r) r = 23 + ((key_len + 3) >> 2);

	s = (kripto_block *)malloc(sizeof(kripto_block) + (r << 2));
	if(!s) return 0;

	s->obj.desc = kripto_block_speck64;
	s->k = (uint32_t *)(s + 1);
	s->rounds = r;

	speck64_setup(s, key, key_len);

	return s;
}

static void speck64_destroy(kripto_block *s)
{
	kripto_memory_wipe(s, sizeof(kripto_block) + (s->rounds << 2));
	free(s);
}

static kripto_block *speck64_recreate
(
	kripto_block *s,
	unsigned int r,
	const void *key,
	unsigned int key_len
)
{
	if(!r) r = 23 + ((key_len + 3) >> 2);

	if(r != s->rounds)
	{
		speck64_destroy(s);
		s = speck64_create(r, key, key_len);
	}
	else
	{
		speck64_setup(s, key, key_len);
	}

	return s;
}

static const kripto_block_desc speck64 =
{
	&speck64_create,
	&speck64_recreate,
	0, /* tweak */
	&speck64_encrypt,
	&speck64_decrypt,
	&speck64_destroy,
	8, /* block size */
	16, /* max key */
	0 /* max tweak */
};

const kripto_block_desc *const kripto_block_speck64 = &speck64;
