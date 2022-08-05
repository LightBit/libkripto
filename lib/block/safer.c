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

/* based on Richard De Moliner's implementation */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <kripto/cast.h>
#include <kripto/rotate.h>
#include <kripto/memwipe.h>
#include <kripto/block.h>
#include <kripto/desc/block.h>
#include <kripto/object/block.h>

#include <kripto/block/safer.h>
#include <kripto/block/safer_sk.h>

struct kripto_block
{
	struct kripto_block_object obj;
	unsigned int rounds;
	size_t size;
	uint8_t *k;
};

static const uint8_t exp_tab[256] =
{
	0x01, 0x2D, 0xE2, 0x93, 0xBE, 0x45, 0x15, 0xAE,
	0x78, 0x03, 0x87, 0xA4, 0xB8, 0x38, 0xCF, 0x3F,
	0x08, 0x67, 0x09, 0x94, 0xEB, 0x26, 0xA8, 0x6B,
	0xBD, 0x18, 0x34, 0x1B, 0xBB, 0xBF, 0x72, 0xF7,
	0x40, 0x35, 0x48, 0x9C, 0x51, 0x2F, 0x3B, 0x55,
	0xE3, 0xC0, 0x9F, 0xD8, 0xD3, 0xF3, 0x8D, 0xB1,
	0xFF, 0xA7, 0x3E, 0xDC, 0x86, 0x77, 0xD7, 0xA6,
	0x11, 0xFB, 0xF4, 0xBA, 0x92, 0x91, 0x64, 0x83,
	0xF1, 0x33, 0xEF, 0xDA, 0x2C, 0xB5, 0xB2, 0x2B,
	0x88, 0xD1, 0x99, 0xCB, 0x8C, 0x84, 0x1D, 0x14,
	0x81, 0x97, 0x71, 0xCA, 0x5F, 0xA3, 0x8B, 0x57,
	0x3C, 0x82, 0xC4, 0x52, 0x5C, 0x1C, 0xE8, 0xA0,
	0x04, 0xB4, 0x85, 0x4A, 0xF6, 0x13, 0x54, 0xB6,
	0xDF, 0x0C, 0x1A, 0x8E, 0xDE, 0xE0, 0x39, 0xFC,
	0x20, 0x9B, 0x24, 0x4E, 0xA9, 0x98, 0x9E, 0xAB,
	0xF2, 0x60, 0xD0, 0x6C, 0xEA, 0xFA, 0xC7, 0xD9,
	0x00, 0xD4, 0x1F, 0x6E, 0x43, 0xBC, 0xEC, 0x53,
	0x89, 0xFE, 0x7A, 0x5D, 0x49, 0xC9, 0x32, 0xC2,
	0xF9, 0x9A, 0xF8, 0x6D, 0x16, 0xDB, 0x59, 0x96,
	0x44, 0xE9, 0xCD, 0xE6, 0x46, 0x42, 0x8F, 0x0A,
	0xC1, 0xCC, 0xB9, 0x65, 0xB0, 0xD2, 0xC6, 0xAC,
	0x1E, 0x41, 0x62, 0x29, 0x2E, 0x0E, 0x74, 0x50,
	0x02, 0x5A, 0xC3, 0x25, 0x7B, 0x8A, 0x2A, 0x5B,
	0xF0, 0x06, 0x0D, 0x47, 0x6F, 0x70, 0x9D, 0x7E,
	0x10, 0xCE, 0x12, 0x27, 0xD5, 0x4C, 0x4F, 0xD6,
	0x79, 0x30, 0x68, 0x36, 0x75, 0x7D, 0xE4, 0xED,
	0x80, 0x6A, 0x90, 0x37, 0xA2, 0x5E, 0x76, 0xAA,
	0xC5, 0x7F, 0x3D, 0xAF, 0xA5, 0xE5, 0x19, 0x61,
	0xFD, 0x4D, 0x7C, 0xB7, 0x0B, 0xEE, 0xAD, 0x4B,
	0x22, 0xF5, 0xE7, 0x73, 0x23, 0x21, 0xC8, 0x05,
	0xE1, 0x66, 0xDD, 0xB3, 0x58, 0x69, 0x63, 0x56,
	0x0F, 0xA1, 0x31, 0x95, 0x17, 0x07, 0x3A, 0x28
};

static const uint8_t log_tab[256] =
{
	0x80, 0x00, 0xB0, 0x09, 0x60, 0xEF, 0xB9, 0xFD,
	0x10, 0x12, 0x9F, 0xE4, 0x69, 0xBA, 0xAD, 0xF8,
	0xC0, 0x38, 0xC2, 0x65, 0x4F, 0x06, 0x94, 0xFC,
	0x19, 0xDE, 0x6A, 0x1B, 0x5D, 0x4E, 0xA8, 0x82,
	0x70, 0xED, 0xE8, 0xEC, 0x72, 0xB3, 0x15, 0xC3,
	0xFF, 0xAB, 0xB6, 0x47, 0x44, 0x01, 0xAC, 0x25,
	0xC9, 0xFA, 0x8E, 0x41, 0x1A, 0x21, 0xCB, 0xD3,
	0x0D, 0x6E, 0xFE, 0x26, 0x58, 0xDA, 0x32, 0x0F,
	0x20, 0xA9, 0x9D, 0x84, 0x98, 0x05, 0x9C, 0xBB,
	0x22, 0x8C, 0x63, 0xE7, 0xC5, 0xE1, 0x73, 0xC6,
	0xAF, 0x24, 0x5B, 0x87, 0x66, 0x27, 0xF7, 0x57,
	0xF4, 0x96, 0xB1, 0xB7, 0x5C, 0x8B, 0xD5, 0x54,
	0x79, 0xDF, 0xAA, 0xF6, 0x3E, 0xA3, 0xF1, 0x11,
	0xCA, 0xF5, 0xD1, 0x17, 0x7B, 0x93, 0x83, 0xBC,
	0xBD, 0x52, 0x1E, 0xEB, 0xAE, 0xCC, 0xD6, 0x35,
	0x08, 0xC8, 0x8A, 0xB4, 0xE2, 0xCD, 0xBF, 0xD9,
	0xD0, 0x50, 0x59, 0x3F, 0x4D, 0x62, 0x34, 0x0A,
	0x48, 0x88, 0xB5, 0x56, 0x4C, 0x2E, 0x6B, 0x9E,
	0xD2, 0x3D, 0x3C, 0x03, 0x13, 0xFB, 0x97, 0x51,
	0x75, 0x4A, 0x91, 0x71, 0x23, 0xBE, 0x76, 0x2A,
	0x5F, 0xF9, 0xD4, 0x55, 0x0B, 0xDC, 0x37, 0x31,
	0x16, 0x74, 0xD7, 0x77, 0xA7, 0xE6, 0x07, 0xDB,
	0xA4, 0x2F, 0x46, 0xF3, 0x61, 0x45, 0x67, 0xE3,
	0x0C, 0xA2, 0x3B, 0x1C, 0x85, 0x18, 0x04, 0x1D,
	0x29, 0xA0, 0x8F, 0xB2, 0x5A, 0xD8, 0xA6, 0x7E,
	0xEE, 0x8D, 0x53, 0x4B, 0xA1, 0x9A, 0xC1, 0x0E,
	0x7A, 0x49, 0xA5, 0x2C, 0x81, 0xC4, 0xC7, 0x36,
	0x2B, 0x7F, 0x43, 0x95, 0x33, 0xF2, 0x6C, 0x68,
	0x6D, 0xF0, 0x02, 0x28, 0xCE, 0xDD, 0x9B, 0xEA,
	0x5E, 0x99, 0x7C, 0x14, 0x86, 0xCF, 0xE5, 0x42,
	0xB8, 0x40, 0x78, 0x2D, 0x3A, 0xE9, 0x64, 0x1F,
	0x92, 0x90, 0x7D, 0x39, 0x6F, 0xE0, 0x89, 0x30
};

#define EXP(X) exp_tab[(uint8_t)(X)]
#define LOG(X) log_tab[(uint8_t)(X)]

static void safer_encrypt
(
	const kripto_block *s,
	const void *pt,
	void *ct
)
{
	uint8_t x0 = CU8(pt)[0];
	uint8_t x1 = CU8(pt)[1];
	uint8_t x2 = CU8(pt)[2];
	uint8_t x3 = CU8(pt)[3];
	uint8_t x4 = CU8(pt)[4];
	uint8_t x5 = CU8(pt)[5];
	uint8_t x6 = CU8(pt)[6];
	uint8_t x7 = CU8(pt)[7];
	uint8_t t;
	unsigned int i = 0;

	while(i < s->rounds << 4)
	{
		x0 = EXP(x0 ^ s->k[i++]);
		x1 = LOG(x1 + s->k[i++]);
		x2 = LOG(x2 + s->k[i++]);
		x3 = EXP(x3 ^ s->k[i++]);
		x4 = EXP(x4 ^ s->k[i++]);
		x5 = LOG(x5 + s->k[i++]);
		x6 = LOG(x6 + s->k[i++]);
		x7 = EXP(x7 ^ s->k[i++]);

		x0 += s->k[i++];
		x1 ^= s->k[i++];
		x2 ^= s->k[i++];
		x3 += s->k[i++];
		x4 += s->k[i++];
		x5 ^= s->k[i++];
		x6 ^= s->k[i++];
		x7 += s->k[i++];

		x1 += x0; x3 += x2; x5 += x4; x7 += x6;
		x0 += x1; x2 += x3; x4 += x5; x6 += x7;

		x2 += x0; x6 += x4; x3 += x1; x7 += x5;
		x0 += x2; x4 += x6; x1 += x3; x5 += x7;

		x4 += x0; x5 += x1; x6 += x2; x7 += x3;
		x0 += x4; x1 += x5; x2 += x6; x3 += x7;

		t = x1; x1 = x4; x4 = x2; x2 = t;
		t = x3; x3 = x5; x5 = x6; x6 = t;
	}

	x0 ^= s->k[i++];
	x1 += s->k[i++];
	x2 += s->k[i++];
	x3 ^= s->k[i++];
	x4 ^= s->k[i++];
	x5 += s->k[i++];
	x6 += s->k[i++];
	x7 ^= s->k[i++];

	U8(ct)[0] = x0;
	U8(ct)[1] = x1;
	U8(ct)[2] = x2;
	U8(ct)[3] = x3;
	U8(ct)[4] = x4;
	U8(ct)[5] = x5;
	U8(ct)[6] = x6;
	U8(ct)[7] = x7;
}

static void safer_decrypt
(
	const kripto_block *s,
	const void *ct,
	void *pt
)
{
	uint8_t x0 = CU8(ct)[0];
	uint8_t x1 = CU8(ct)[1];
	uint8_t x2 = CU8(ct)[2];
	uint8_t x3 = CU8(ct)[3];
	uint8_t x4 = CU8(ct)[4];
	uint8_t x5 = CU8(ct)[5];
	uint8_t x6 = CU8(ct)[6];
	uint8_t x7 = CU8(ct)[7];
	uint8_t t;
	unsigned int i = (s->rounds << 4) + 8;

	x7 ^= s->k[--i];
	x6 -= s->k[--i];
	x5 -= s->k[--i];
	x4 ^= s->k[--i];
	x3 ^= s->k[--i];
	x2 -= s->k[--i];
	x1 -= s->k[--i];
	x0 ^= s->k[--i];

	while(i)
	{
		t = x4; x4 = x1; x1 = x2; x2 = t;
		t = x5; x5 = x3; x3 = x6; x6 = t;

		x0 -= x4; x1 -= x5; x2 -= x6; x3 -= x7;
		x4 -= x0; x5 -= x1; x6 -= x2; x7 -= x3;

		x0 -= x2; x4 -= x6; x1 -= x3; x5 -= x7;
		x2 -= x0; x6 -= x4; x3 -= x1; x7 -= x5;

		x0 -= x1; x2 -= x3; x4 -= x5; x6 -= x7;
		x1 -= x0; x3 -= x2; x5 -= x4; x7 -= x6;

		x7 -= s->k[--i];
		x6 ^= s->k[--i];
		x5 ^= s->k[--i];
		x4 -= s->k[--i];
		x3 -= s->k[--i];
		x2 ^= s->k[--i];
		x1 ^= s->k[--i];
		x0 -= s->k[--i];

		x7 = LOG(x7) ^ s->k[--i];
		x6 = EXP(x6) - s->k[--i];
		x5 = EXP(x5) - s->k[--i];
		x4 = LOG(x4) ^ s->k[--i];
		x3 = LOG(x3) ^ s->k[--i];
		x2 = EXP(x2) - s->k[--i];
		x1 = EXP(x1) - s->k[--i];
		x0 = LOG(x0) ^ s->k[--i];
	}

	U8(pt)[0] = x0;
	U8(pt)[1] = x1;
	U8(pt)[2] = x2;
	U8(pt)[3] = x3;
	U8(pt)[4] = x4;
	U8(pt)[5] = x5;
	U8(pt)[6] = x6;
	U8(pt)[7] = x7;
}

static void safer_setup
(
	kripto_block *s,
	const uint8_t *key,
	unsigned int len,
	int sk
)
{
	const uint8_t *key2;
	uint8_t *k = s->k;
	uint8_t ka[9];
	uint8_t kb[9];
	unsigned int i;
	unsigned int j;

	kb[8] = ka[8] = 0;

	if(len > 8) key2 = key + 8; /* 128-bit */
	else key2 = key; /* 64-bit */

	for(i = 0; i < 8; i++)
	{
		ka[8] ^= ka[i] = ROL8_5(key[i]);
		kb[8] ^= kb[i] = *k++ = key2[i];
	}

	for(i = 1; i <= s->rounds; i++)
	{
		for(j = 0; j <= 8; j++)
		{
			ka[j] = ROL8_6(ka[j]);
			kb[j] = ROL8_6(kb[j]);
		}

		for(j = 0; j < 8; j++)
		{
			if(sk) *k++ = ka[((i << 1) + j - 1) % 9]
				+ EXP(EXP(18 * i + j + 1));
			else *k++ = ka[j] + EXP(EXP(18 * i + j + 1));
		}

		for(j = 0; j < 8; j++)
		{
			if(sk) *k++ = kb[((i << 1) + j) % 9]
				+ EXP(EXP(18 * i + j + 10));
			else *k++ = kb[j] + EXP(EXP(18 * i + j + 10));
		}
	}

	kripto_memwipe(ka, 9);
	kripto_memwipe(kb, 9);
}

static void safer_destroy(kripto_block *s)
{
	kripto_memwipe(s, s->size);
	free(s);
}

static kripto_block *safer_create
(
	unsigned int r,
	const void *key,
	unsigned int key_len
)
{
	kripto_block *s;

	if(!r)
	{
		if(key_len > 8) r = 10;
		else r = 6;
	}

	s = malloc(sizeof(kripto_block) + (r << 4) + 8);
	if(!s) return 0;

	s->obj.desc = kripto_block_safer;
	s->size = sizeof(kripto_block) + (r << 4) + 8;
	s->rounds = r;
	s->k = (uint8_t *)s + sizeof(kripto_block);

	safer_setup(s, key, key_len, 0);

	return s;
}

static kripto_block *safer_recreate
(
	kripto_block *s,
	unsigned int r,
	const void *key,
	unsigned int key_len
)
{
	if(!r)
	{
		if(key_len > 8) r = 10;
		else r = 6;
	}

	if(sizeof(kripto_block) + (r << 4) + 8 > s->size)
	{
		safer_destroy(s);
		s = safer_create(r, key, key_len);
	}
	else
	{
		s->rounds = r;
		safer_setup(s, key, key_len, 0);
	}

	return s;
}

static kripto_block *safer_sk_create
(
	unsigned int r,
	const void *key,
	unsigned int key_len
)
{
	kripto_block *s;

	if(!r)
	{
		if(key_len > 8) r = 10;
		else r = 8;
	}

	s = malloc(sizeof(kripto_block) + (r << 4) + 8);
	if(!s) return 0;

	s->obj.desc = kripto_block_safer_sk;
	s->size = sizeof(kripto_block) + (r << 4) + 8;
	s->rounds = r;
	s->k = (uint8_t *)s + sizeof(kripto_block);

	safer_setup(s, key, key_len, -1);

	return s;
}

static kripto_block *safer_sk_recreate
(
	kripto_block *s,
	unsigned int r,
	const void *key,
	unsigned int key_len
)
{
	if(!r)
	{
		if(key_len > 8) r = 10;
		else r = 8;
	}

	if(sizeof(kripto_block) + (r << 4) + 8 > s->size)
	{
		safer_destroy(s);
		s = safer_sk_create(r, key, key_len);
	}
	else
	{
		s->rounds = r;
		safer_setup(s, key, key_len, -1);
	}

	return s;
}

static const kripto_block_desc safer =
{
	&safer_create,
	&safer_recreate,
	0, /* tweak */
	&safer_encrypt,
	&safer_decrypt,
	&safer_destroy,
	8, /* block size */
	16, /* max key */
	0 /* max tweak */
};

static const kripto_block_desc safer_sk =
{
	&safer_sk_create,
	&safer_sk_recreate,
	0, /* tweak */
	&safer_encrypt,
	&safer_decrypt,
	&safer_destroy,
	8, /* block size */
	16, /* max key */
	0 /* max tweak */
};

const kripto_block_desc *const kripto_block_safer = &safer;
const kripto_block_desc *const kripto_block_safer_sk = &safer_sk;
