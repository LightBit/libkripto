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

#include <kripto/block/speck128.h>

struct kripto_block
{
	struct kripto_block_object obj;
	unsigned int rounds;
	uint64_t *k;
};

#define R(A, B, K)			\
{					\
	A = (ROR64_08(A) + B) ^ (K);	\
	B = ROL64_03(B) ^ A;		\
}

#define IR(A, B, K)			\
{					\
	B = ROR64_03(B ^ A);		\
	A = ROL64_08((A ^ (K)) - B);	\
}

static void speck128_encrypt
(
	const kripto_block *s,
	const void *pt,
	void *ct
)
{
	uint64_t a = LOAD64L(CU8(pt) + 8);
	uint64_t b = LOAD64L(CU8(pt)    );

	for(unsigned int i = 0; i < s->rounds; i++)
		R(a, b, s->k[i]);

	STORE64L(a, U8(ct) + 8);
	STORE64L(b, U8(ct)    );
}

static void speck128_decrypt
(
	const kripto_block *s,
	const void *ct,
	void *pt
)
{
	uint64_t a = LOAD64L(CU8(ct) + 8);
	uint64_t b = LOAD64L(CU8(ct)    );

	for(unsigned int i = s->rounds; i--;)
		IR(a, b, s->k[i]);

	STORE64L(a, U8(pt) + 8);
	STORE64L(b, U8(pt)    );
}

static void speck128_setup
(
	kripto_block *s,
	const void *key,
	unsigned int len
)
{
	uint64_t k[4] = {0, 0, 0, 0};
	unsigned int m = ((len + 7) >> 3) - 1;

	LOAD64L_ARRAY(key, k, len);

	s->k[0] = k[0];

	for(unsigned int i = 0; i < s->rounds - 1;)
	{
		unsigned int a = (i % m) + 1;
		R(k[a], k[0], i);
		s->k[++i] = k[0];
	}

	kripto_memory_wipe(k, 32);
}

static kripto_block *speck128_create
(
	unsigned int r,
	const void *key,
	unsigned int key_len
)
{
	kripto_block *s;

	if(!r) r = 30 + ((key_len + 7) >> 3);

	s = (kripto_block *)malloc(sizeof(kripto_block) + (r << 3));
	if(!s) return 0;

	s->obj.desc = kripto_block_speck128;
	s->k = (uint64_t *)(s + 1);
	s->rounds = r;

	speck128_setup(s, key, key_len);

	return s;
}

static void speck128_destroy(kripto_block *s)
{
	kripto_memory_wipe(s, sizeof(kripto_block) + (s->rounds << 3));
	free(s);
}

static kripto_block *speck128_recreate
(
	kripto_block *s,
	unsigned int r,
	const void *key,
	unsigned int key_len
)
{
	if(!r) r = 30 + ((key_len + 7) >> 3);

	if(r != s->rounds)
	{
		speck128_destroy(s);
		s = speck128_create(r, key, key_len);
	}
	else
	{
		speck128_setup(s, key, key_len);
	}

	return s;
}

static const kripto_block_desc speck128 =
{
	&speck128_create,
	&speck128_recreate,
	0, /* tweak */
	&speck128_encrypt,
	&speck128_decrypt,
	&speck128_destroy,
	16, /* block size */
	32, /* max key */
	0 /* max tweak */
};

const kripto_block_desc *const kripto_block_speck128 = &speck128;
