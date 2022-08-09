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
#include <stddef.h>
#include <stdlib.h>

#include <kripto/cast.h>
#include <kripto/loadstore.h>
#include <kripto/rotate.h>
#include <kripto/memory.h>
#include <kripto/block.h>
#include <kripto/desc/block.h>
#include <kripto/object/block.h>

#include <kripto/block/lea.h>

struct kripto_block
{
	struct kripto_block_object obj;
	unsigned int r;
	uint32_t *k;
};

static const uint32_t C[8] =
{
	0xC3EFE9DB, 0x44626B02, 0x79E27C8A, 0x78DF30EC,
	0x715EA49E, 0xC785DA0A, 0xE04EF22A, 0xE5C40957
};

static void lea_encrypt
(
	const kripto_block *s,
	const void *pt,
	void *ct
)
{
	uint32_t a = LOAD32L(CU8(pt)     );
	uint32_t b = LOAD32L(CU8(pt) +  4);
	uint32_t c = LOAD32L(CU8(pt) +  8);
	uint32_t d = LOAD32L(CU8(pt) + 12);

	for(unsigned int i = 0; i < s->r * 6; i += 24)
	{
		d = ROR32_03((c ^ s->k[i +  4]) + (d ^ s->k[i +  5]));
		c = ROR32_05((b ^ s->k[i +  2]) + (c ^ s->k[i +  3]));
		b = ROL32_09((a ^ s->k[i     ]) + (b ^ s->k[i +  1]));

		a = ROR32_03((d ^ s->k[i + 10]) + (a ^ s->k[i + 11]));
		d = ROR32_05((c ^ s->k[i +  8]) + (d ^ s->k[i +  9]));
		c = ROL32_09((b ^ s->k[i +  6]) + (c ^ s->k[i +  7]));

		b = ROR32_03((a ^ s->k[i + 16]) + (b ^ s->k[i + 17]));
		a = ROR32_05((d ^ s->k[i + 14]) + (a ^ s->k[i + 15]));
		d = ROL32_09((c ^ s->k[i + 12]) + (d ^ s->k[i + 13]));

		c = ROR32_03((b ^ s->k[i + 22]) + (c ^ s->k[i + 23]));
		b = ROR32_05((a ^ s->k[i + 20]) + (b ^ s->k[i + 21]));
		a = ROL32_09((d ^ s->k[i + 18]) + (a ^ s->k[i + 19]));
	}

	STORE32L(a, U8(ct)     );
	STORE32L(b, U8(ct) +  4);
	STORE32L(c, U8(ct) +  8);
	STORE32L(d, U8(ct) + 12);
}

static void lea_decrypt
(
	const kripto_block *s,
	const void *ct,
	void *pt
)
{
	uint32_t a = LOAD32L(CU8(ct)     );
	uint32_t b = LOAD32L(CU8(ct) +  4);
	uint32_t c = LOAD32L(CU8(ct) +  8);
	uint32_t d = LOAD32L(CU8(ct) + 12);

	for(unsigned int i = s->r * 6; i > 0; i -= 24)
	{
		a = (ROR32_09(a) - (d ^ s->k[i -  6])) ^ s->k[i -  5];
		b = (ROL32_05(b) - (a ^ s->k[i -  4])) ^ s->k[i -  3];
		c = (ROL32_03(c) - (b ^ s->k[i -  2])) ^ s->k[i -  1];

		d = (ROR32_09(d) - (c ^ s->k[i - 12])) ^ s->k[i - 11];
		a = (ROL32_05(a) - (d ^ s->k[i - 10])) ^ s->k[i -  9];
		b = (ROL32_03(b) - (a ^ s->k[i -  8])) ^ s->k[i -  7];

		c = (ROR32_09(c) - (b ^ s->k[i - 18])) ^ s->k[i - 17];
		d = (ROL32_05(d) - (c ^ s->k[i - 16])) ^ s->k[i - 15];
		a = (ROL32_03(a) - (d ^ s->k[i - 14])) ^ s->k[i - 13];

		b = (ROR32_09(b) - (a ^ s->k[i - 24])) ^ s->k[i - 23];
		c = (ROL32_05(c) - (b ^ s->k[i - 22])) ^ s->k[i - 21];
		d = (ROL32_03(d) - (c ^ s->k[i - 20])) ^ s->k[i - 19];
	}

	STORE32L(a, U8(pt)     );
	STORE32L(b, U8(pt) +  4);
	STORE32L(c, U8(pt) +  8);
	STORE32L(d, U8(pt) + 12);
}

static void lea_setup
(
	kripto_block *s,
	const void *key,
	unsigned int key_len
)
{
	uint32_t *k = s->k;

	if(key_len > 24) /* 256-bit */
	{
		uint32_t t[8] = {0, 0, 0, 0, 0, 0, 0, 0};
		LOAD32L_ARRAY(key, t, key_len);

		for(unsigned int i = 0; i < s->r; i++)
		{
			uint32_t ci = C[i & 7];

			t[(i * 6    ) & 7] = ROL32_01(t[(i * 6    ) & 7] + ROL32(ci, (i    ) & 31));
			t[(i * 6 + 1) & 7] = ROL32_03(t[(i * 6 + 1) & 7] + ROL32(ci, (i + 1) & 31));
			t[(i * 6 + 2) & 7] = ROL32_06(t[(i * 6 + 2) & 7] + ROL32(ci, (i + 2) & 31));
			t[(i * 6 + 3) & 7] = ROL32_11(t[(i * 6 + 3) & 7] + ROL32(ci, (i + 3) & 31));
			t[(i * 6 + 4) & 7] = ROL32_13(t[(i * 6 + 4) & 7] + ROL32(ci, (i + 4) & 31));
			t[(i * 6 + 5) & 7] = ROL32_17(t[(i * 6 + 5) & 7] + ROL32(ci, (i + 5) & 31));

			*k++ = t[(i * 6    ) & 7];
			*k++ = t[(i * 6 + 1) & 7];
			*k++ = t[(i * 6 + 2) & 7];
			*k++ = t[(i * 6 + 3) & 7];
			*k++ = t[(i * 6 + 4) & 7];
			*k++ = t[(i * 6 + 5) & 7];
		}

		kripto_memory_wipe(t, 32);
	}
	else if(key_len > 16) /* 192-bit */
	{
		uint32_t t[6] = {0, 0, 0, 0, 0, 0};
		LOAD32L_ARRAY(key, t, key_len);

		for(unsigned int i = 0; i < s->r; i++)
		{
			uint32_t ci = C[i % 6];

			t[0] = ROL32_01(t[0] + ROL32(ci, (i    ) & 31));
			t[1] = ROL32_03(t[1] + ROL32(ci, (i + 1) & 31));
			t[2] = ROL32_06(t[2] + ROL32(ci, (i + 2) & 31));
			t[3] = ROL32_11(t[3] + ROL32(ci, (i + 3) & 31));
			t[4] = ROL32_13(t[4] + ROL32(ci, (i + 4) & 31));
			t[5] = ROL32_17(t[5] + ROL32(ci, (i + 5) & 31));

			*k++ = t[0];
			*k++ = t[1];
			*k++ = t[2];
			*k++ = t[3];
			*k++ = t[4];
			*k++ = t[5];
		}

		kripto_memory_wipe(t, 24);
	}
	else /* 128-bit */
	{
		uint32_t t[4] = {0, 0, 0, 0};
		LOAD32L_ARRAY(key, t, key_len);

		for(unsigned int i = 0; i < s->r; i++)
		{
			uint32_t ci = C[i & 3];

			t[0] = ROL32_01(t[0] + ROL32(ci, (i    ) & 31));
			t[1] = ROL32_03(t[1] + ROL32(ci, (i + 1) & 31));
			t[2] = ROL32_06(t[2] + ROL32(ci, (i + 2) & 31));
			t[3] = ROL32_11(t[3] + ROL32(ci, (i + 3) & 31));

			*k++ = t[0];
			*k++ = t[1];
			*k++ = t[2];
			*k++ = t[1];
			*k++ = t[3];
			*k++ = t[1];
		}

		kripto_memory_wipe(t, 16);
	}
}

static kripto_block *lea_create
(
	unsigned int r,
	const void *key,
	unsigned int key_len
)
{
	if(!r)
	{
		if(key_len > 24) r = 32;
		else if(key_len > 16) r = 28;
		else r = 24;
	}

	kripto_block *s = (kripto_block *)malloc(sizeof(kripto_block) + r * 24);
	if(!s) return 0;

	s->obj.desc = kripto_block_lea;
	s->k = (uint32_t *)(s + 1);
	s->r = r;
	lea_setup(s, key, key_len);

	return s;
}

static void lea_destroy(kripto_block *s)
{
	kripto_memory_wipe(s, sizeof(kripto_block) + s->r * 24);
	free(s);
}

static kripto_block *lea_recreate
(
	kripto_block *s,
	unsigned int r,
	const void *key,
	unsigned int key_len
)
{
	if(!r)
	{
		if(key_len > 24) r = 32;
		else if(key_len > 16) r = 28;
		else r = 24;
	}

	if(r != s->r)
	{
		lea_destroy(s);
		s = lea_create(r, key, key_len);
	}
	else
	{
		lea_setup(s, key, key_len);
	}

	return s;
}

static const kripto_block_desc lea =
{
	&lea_create,
	&lea_recreate,
	0, /* tweak */
	&lea_encrypt,
	&lea_decrypt,
	&lea_destroy,
	16, /* block size */
	32, /* max key */
	0 /* max tweak */
};

const kripto_block_desc *const kripto_block_lea = &lea;
