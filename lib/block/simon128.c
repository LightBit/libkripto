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

#include <kripto/block/simon128.h>

struct kripto_block
{
	struct kripto_block_object obj;
	unsigned int rounds;
	uint64_t *k;
};

#define F(X) ((ROL64_01(X) & ROL64_08(X)) ^ ROL64_02(X))

static void simon128_encrypt
(
	const kripto_block *s,
	const void *pt,
	void *ct
)
{
	uint64_t a = LOAD64L(CU8(pt) + 8);
	uint64_t b = LOAD64L(CU8(pt)    );

	for(unsigned int i = 0; i < s->rounds;)
	{
		b ^= F(a) ^ s->k[i++];

		if(i == s->rounds)
		{
			STORE64L(a, U8(ct)    );
			STORE64L(b, U8(ct) + 8);
			return;
		}

		a ^= F(b) ^ s->k[i++];
	}

	STORE64L(a, U8(ct) + 8);
	STORE64L(b, U8(ct)    );
}

static void simon128_decrypt
(
	const kripto_block *s,
	const void *ct,
	void *pt
)
{
	uint64_t a = LOAD64L(CU8(ct) + 8);
	uint64_t b = LOAD64L(CU8(ct)    );

	for(unsigned int i = s->rounds; i;)
	{
		a ^= F(b) ^ s->k[--i];

		if(!i)
		{
			STORE64L(a, U8(pt)    );
			STORE64L(b, U8(pt) + 8);
			return;
		}

		b ^= F(a) ^ s->k[--i];
	}

	STORE64L(a, U8(pt) + 8);
	STORE64L(b, U8(pt)    );
}

static const uint64_t z[3] =
{
	0x3369F885192C0EF5,
	0x3C2CE51207A635DB,
	0x3DC94C3A046D678B
};

static void simon128_setup
(
	kripto_block *s,
	const void *key,
	unsigned int len
)
{
	uint64_t t;
	unsigned int m = (len + 7) >> 3;
	if(m < 2) m = 2;

	for(unsigned int i = 0; i < m; i++)
		s->k[i] = 0;

	LOAD64L_ARRAY(key, s->k, len);

	for(unsigned int i = m; i < s->rounds; i++)
	{
		t = ROR64_03(s->k[i - 1]);
		if(m == 4) t ^= s->k[i - 3];
		t ^= ROR64_01(t) ^ ~s->k[i - m] ^ 3;
		s->k[i] = t ^ ((z[m - 2] >> ((i - m) % 62)) & 1);
	}

	kripto_memory_wipe(&t, sizeof(uint64_t));
}

static kripto_block *simon128_create
(
	const kripto_block_desc *desc,
	unsigned int r,
	const void *key,
	unsigned int key_len
)
{
	kripto_block *s;

	if(!r)
	{
		switch((key_len + 7) >> 3)
		{
			case 3: r = 69; break;
			case 4: r = 72; break;
			default: r = 68; break;
		}
	}

	s = (kripto_block *)malloc(sizeof(kripto_block) + (r << 3));
	if(!s) return 0;

	s->obj.desc = desc;
	s->k = (uint64_t *)(s + 1);
	s->rounds = r;

	simon128_setup(s, key, key_len);

	return s;
}

static void simon128_destroy(kripto_block *s)
{
	kripto_memory_wipe(s, sizeof(kripto_block) + (s->rounds << 3));
	free(s);
}

static kripto_block *simon128_recreate
(
	kripto_block *s,
	unsigned int r,
	const void *key,
	unsigned int key_len
)
{
	if(!r)
	{
		switch((key_len + 7) >> 3)
		{
			case 3: r = 69; break;
			case 4: r = 72; break;
			default: r = 68; break;
		}
	}

	if(r != s->rounds)
	{
		simon128_destroy(s);
		s = simon128_create(s->obj.desc, r, key, key_len);
	}
	else
	{
		simon128_setup(s, key, key_len);
	}

	return s;
}

static const kripto_block_desc simon128 =
{
	&simon128_create,
	&simon128_recreate,
	0, /* tweak */
	&simon128_encrypt,
	&simon128_decrypt,
	&simon128_destroy,
	16, /* block size */
	32, /* max key */
	0 /* max tweak */
};

const kripto_block_desc *const kripto_block_simon128 = &simon128;
