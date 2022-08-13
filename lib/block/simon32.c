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

#include <kripto/block/simon32.h>

struct kripto_block
{
	struct kripto_block_object obj;
	unsigned int rounds;
	uint16_t *k;
};

#define F(X) ((ROL16_01(X) & ROL16_08(X)) ^ ROL16_02(X))

static void simon32_encrypt
(
	const kripto_block *s,
	const void *pt,
	void *ct
)
{
	uint16_t a = LOAD16L(CU8(pt) + 2);
	uint16_t b = LOAD16L(CU8(pt)    );

	for(unsigned int i = 0; i < s->rounds;)
	{
		b ^= F(a) ^ s->k[i++];

		if(i == s->rounds)
		{
			STORE16L(a, U8(ct)    );
			STORE16L(b, U8(ct) + 2);
			return;
		}

		a ^= F(b) ^ s->k[i++];
	}

	STORE16L(a, U8(ct) + 2);
	STORE16L(b, U8(ct)    );
}

static void simon32_decrypt
(
	const kripto_block *s,
	const void *ct,
	void *pt
)
{
	uint16_t a = LOAD16L(CU8(ct) + 2);
	uint16_t b = LOAD16L(CU8(ct)    );

	for(unsigned int i = s->rounds; i;)
	{
		a ^= F(b) ^ s->k[--i];

		if(!i)
		{
			STORE16L(a, U8(pt)    );
			STORE16L(b, U8(pt) + 2);
			return;
		}

		b ^= F(a) ^ s->k[--i];
	}

	STORE16L(a, U8(pt) + 2);
	STORE16L(b, U8(pt)    );
}

static void simon32_setup
(
	kripto_block *s,
	const void *key,
	unsigned int len
)
{
	uint16_t t;

	s->k[3] = s->k[2] = s->k[1] = s->k[0] = 0;
    LOAD16L_ARRAY(key, s->k, len);

	for(unsigned int i = 4; i < s->rounds; i++)
	{
		t = ROR16_03(s->k[i - 1]) ^ s->k[i - 3];
		t ^= ROR16_01(t) ^ ~s->k[i - 4] ^ 3;
		s->k[i] = t ^ ((0x19C3522FB386A45F >> ((i - 4) % 62)) & 1);
	}

	kripto_memory_wipe(&t, sizeof(uint16_t));
}

static kripto_block *simon32_create
(
	const kripto_block_desc *desc,
	unsigned int r,
	const void *key,
	unsigned int key_len
)
{
	kripto_block *s;

	if(!r) r = 32;

	s = (kripto_block *)malloc(sizeof(kripto_block) + (r << 1));
	if(!s) return 0;

	s->obj.desc = desc;
	s->k = (uint16_t *)(s + 1);
	s->rounds = r;

	simon32_setup(s, key, key_len);

	return s;
}

static void simon32_destroy(kripto_block *s)
{
	kripto_memory_wipe(s, sizeof(kripto_block) + (s->rounds << 1));
	free(s);
}

static kripto_block *simon32_recreate
(
	kripto_block *s,
	unsigned int r,
	const void *key,
	unsigned int key_len
)
{
	if(!r) r = 32;

	if(r != s->rounds)
	{
		simon32_destroy(s);
		s = simon32_create(s->obj.desc, r, key, key_len);
	}
	else
	{
		simon32_setup(s, key, key_len);
	}

	return s;
}

static const kripto_block_desc simon32 =
{
	&simon32_create,
	&simon32_recreate,
	0, /* tweak */
	&simon32_encrypt,
	&simon32_decrypt,
	&simon32_destroy,
	4, /* block size */
	8, /* max key */
	0 /* max tweak */
};

const kripto_block_desc *const kripto_block_simon32 = &simon32;
