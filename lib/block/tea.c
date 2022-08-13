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
#include <limits.h>

#include <kripto/cast.h>
#include <kripto/loadstore.h>
#include <kripto/memory.h>
#include <kripto/block.h>
#include <kripto/desc/block.h>
#include <kripto/object/block.h>

#include <kripto/block/tea.h>

struct kripto_block
{
	struct kripto_block_object obj;
	uint32_t c;
	uint32_t k[4];
};

static void tea_encrypt(const kripto_block *s, const void *pt, void *ct)
{
	uint32_t x0 = LOAD32B(CU8(pt));
	uint32_t x1 = LOAD32B(CU8(pt) + 4);
	uint32_t c;

	for(c = 0; c != s->c;)
	{
		c += 0x9E3779B9;
		x0 += ((x1 << 4) + s->k[0]) ^ (x1 + c) ^ ((x1 >> 5) + s->k[1]);
		x1 += ((x0 << 4) + s->k[2]) ^ (x0 + c) ^ ((x0 >> 5) + s->k[3]);
	}

	STORE32B(x0, U8(ct));
	STORE32B(x1, U8(ct) + 4);
}
 
static void tea_decrypt(const kripto_block *s, const void *ct, void *pt)
{
	uint32_t x0 = LOAD32B(CU8(ct));
	uint32_t x1 = LOAD32B(CU8(ct) + 4);
	uint32_t c;

	for(c = s->c; c; c -= 0x9E3779B9)
	{
		x1 -= ((x0 << 4) + s->k[2]) ^ (x0 + c) ^ ((x0 >> 5) + s->k[3]);
		x0 -= ((x1 << 4) + s->k[0]) ^ (x1 + c) ^ ((x1 >> 5) + s->k[1]);
	}

	STORE32B(x0, U8(pt));
	STORE32B(x1, U8(pt) + 4);
}

static kripto_block *tea_recreate
(
	kripto_block *s,
	unsigned int r,
	const void *key,
	unsigned int key_len
)
{
	unsigned int i;

	if(r) s->c = 0x9E3779B9 * r;
	else s->c = 0xC6EF3720; /* 0x9E3779B9 * 32 */

	for(i = 0; i < 4; i++) s->k[i] = 0;
	LOAD32B_ARRAY(key, s->k, key_len);

	return s;
}

static kripto_block *tea_create
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

	return tea_recreate(s, r, key, key_len);
}

static void tea_destroy(kripto_block *s)
{
	kripto_memory_wipe(s, sizeof(kripto_block));
	free(s);
}

static const kripto_block_desc tea =
{
	&tea_create,
	&tea_recreate,
	0, /* tweak */
	&tea_encrypt,
	&tea_decrypt,
	&tea_destroy,
	8, /* block size */
	16, /* max key */
	0 /* max tweak */
};

const kripto_block_desc *const kripto_block_tea = &tea;
