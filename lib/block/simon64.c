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

#include <kripto/block/simon64.h>

struct kripto_block
{
	struct kripto_block_object obj;
	unsigned int rounds;
	uint32_t *k;
};

#define F(X) ((ROL32_01(X) & ROL32_08(X)) ^ ROL32_02(X))

static void simon64_encrypt
(
	const kripto_block *s,
	const void *pt,
	void *ct
)
{
	uint32_t a = LOAD32L(CU8(pt) + 4);
	uint32_t b = LOAD32L(CU8(pt)    );

	for(unsigned int i = 0; i < s->rounds;)
	{
		b ^= F(a) ^ s->k[i++];

		if(i == s->rounds)
		{
			STORE32L(a, U8(ct)    );
			STORE32L(b, U8(ct) + 4);
			return;
		}

		a ^= F(b) ^ s->k[i++];
	}

	STORE32L(a, U8(ct) + 4);
	STORE32L(b, U8(ct)    );
}

static void simon64_decrypt
(
	const kripto_block *s,
	const void *ct,
	void *pt
)
{
	uint32_t a = LOAD32L(CU8(ct) + 4);
	uint32_t b = LOAD32L(CU8(ct)    );

	for(unsigned int i = s->rounds; i;)
	{
		a ^= F(b) ^ s->k[--i];

		if(!i)
		{
			STORE32L(a, U8(pt)    );
			STORE32L(b, U8(pt) + 4);
			return;
		}

		b ^= F(a) ^ s->k[--i];
	}

	STORE32L(a, U8(pt) + 4);
	STORE32L(b, U8(pt)    );
}

static const uint64_t z[2] =
{
	0x3369F885192C0EF5,
	0x3C2CE51207A635DB
};

static void simon64_setup
(
	kripto_block *s,
	const void *key,
	unsigned int len
)
{
	uint32_t t;
	unsigned int m = (len + 3) >> 2;
	if(m < 3) m = 3;

	for(unsigned int i = 0; i < m; i++)
		s->k[i] = 0;

	LOAD32L_ARRAY(key, s->k, len);

	for(unsigned int i = m; i < s->rounds; i++)
	{
		t = ROR32_03(s->k[i - 1]);
		if(m == 4) t ^= s->k[i - 3];
		t ^= ROR32_01(t) ^ ~s->k[i - m] ^ 3;
		s->k[i] = t ^ ((z[m - 3] >> ((i - m) % 62)) & 1);
	}

	kripto_memory_wipe(&t, sizeof(uint32_t));
}

static kripto_block *simon64_create
(
	const kripto_block_desc *desc,
	unsigned int r,
	const void *key,
	unsigned int key_len
)
{
	kripto_block *s;

	if(!r) r = 36 + (((key_len + 3) >> 2) << 1);

	s = (kripto_block *)malloc(sizeof(kripto_block) + (r << 2));
	if(!s) return 0;

	s->obj.desc = desc;
	s->k = (uint32_t *)(s + 1);
	s->rounds = r;

	simon64_setup(s, key, key_len);

	return s;
}

static void simon64_destroy(kripto_block *s)
{
	kripto_memory_wipe(s, sizeof(kripto_block) + (s->rounds << 2));
	free(s);
}

static kripto_block *simon64_recreate
(
	kripto_block *s,
	unsigned int r,
	const void *key,
	unsigned int key_len
)
{
	if(!r) r = 36 + (((key_len + 3) >> 2) << 1);

	if(r != s->rounds)
	{
		simon64_destroy(s);
		s = simon64_create(s->obj.desc, r, key, key_len);
	}
	else
	{
		simon64_setup(s, key, key_len);
	}

	return s;
}

static const kripto_block_desc simon64 =
{
	&simon64_create,
	&simon64_recreate,
	0, /* tweak */
	&simon64_encrypt,
	&simon64_decrypt,
	&simon64_destroy,
	8, /* block size */
	16, /* max key */
	0 /* max tweak */
};

const kripto_block_desc *const kripto_block_simon64 = &simon64;
