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
#include <stdlib.h>
#include <string.h>

#include <kripto/cast.h>
#include <kripto/rotate.h>
#include <kripto/memory.h>
#include <kripto/block.h>
#include <kripto/desc/block.h>
#include <kripto/object/block.h>

#include <kripto/block/saferpp.h>

struct kripto_block
{
	struct kripto_block_object obj;
	unsigned int rounds;
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

#define PHT4(A, B, C, D) { D += A; D += B; D += C; A += D; B += D; C += D; }
#define IPHT4(A, B, C, D) { C -= D; B -= D; A -= D; D -= C; D -= B; D -= A; }

static void saferpp_encrypt
(
	const kripto_block *s,
	const void *pt,
	void *ct
)
{
	uint8_t x00 = CU8(pt)[ 0];
	uint8_t x01 = CU8(pt)[ 1];
	uint8_t x02 = CU8(pt)[ 2];
	uint8_t x03 = CU8(pt)[ 3];
	uint8_t x04 = CU8(pt)[ 4];
	uint8_t x05 = CU8(pt)[ 5];
	uint8_t x06 = CU8(pt)[ 6];
	uint8_t x07 = CU8(pt)[ 7];
	uint8_t x08 = CU8(pt)[ 8];
	uint8_t x09 = CU8(pt)[ 9];
	uint8_t x10 = CU8(pt)[10];
	uint8_t x11 = CU8(pt)[11];
	uint8_t x12 = CU8(pt)[12];
	uint8_t x13 = CU8(pt)[13];
	uint8_t x14 = CU8(pt)[14];
	uint8_t x15 = CU8(pt)[15];
	unsigned int i = 0;

	while(i < s->rounds << 5)
	{
		x00 = EXP(x00 ^ s->k[i++]);
		x01 = LOG(x01 + s->k[i++]);
		x02 = LOG(x02 + s->k[i++]);
		x03 = EXP(x03 ^ s->k[i++]);
		x04 = EXP(x04 ^ s->k[i++]);
		x05 = LOG(x05 + s->k[i++]);
		x06 = LOG(x06 + s->k[i++]);
		x07 = EXP(x07 ^ s->k[i++]);
		x08 = EXP(x08 ^ s->k[i++]);
		x09 = LOG(x09 + s->k[i++]);
		x10 = LOG(x10 + s->k[i++]);
		x11 = EXP(x11 ^ s->k[i++]);
		x12 = EXP(x12 ^ s->k[i++]);
		x13 = LOG(x13 + s->k[i++]);
		x14 = LOG(x14 + s->k[i++]);
		x15 = EXP(x15 ^ s->k[i++]);
		
		x00 += s->k[i++];
		x01 ^= s->k[i++];
		x02 ^= s->k[i++];
		x03 += s->k[i++];
		x04 += s->k[i++];
		x05 ^= s->k[i++];
		x06 ^= s->k[i++];
		x07 += s->k[i++];
		x08 += s->k[i++];
		x09 ^= s->k[i++];
		x10 ^= s->k[i++];
		x11 += s->k[i++];
		x12 += s->k[i++];
		x13 ^= s->k[i++];
		x14 ^= s->k[i++];
		x15 += s->k[i++];

		PHT4(x08, x05, x02, x15);
		PHT4(x00, x13, x10, x07);
		PHT4(x04, x01, x14, x11);
		PHT4(x12, x09, x06, x03);
		
		PHT4(x04, x13, x02, x03);
		PHT4(x08, x09, x14, x07);
		PHT4(x00, x05, x06, x11);
		PHT4(x12, x01, x10, x15);

		{ uint8_t t; t = x08; x08 = x00; x00 = x04; x04 = t; }
		{ uint8_t t; t = x13; x13 = x01; x01 = t; }
		{ uint8_t t; t = x09; x09 = x05; x05 = t; }
		{ uint8_t t; t = x06; x06 = x14; x14 = x10; x10 = t; }
	}

	U8(ct)[ 0] = x00 ^ s->k[i++];
	U8(ct)[ 1] = x01 + s->k[i++];
	U8(ct)[ 2] = x02 + s->k[i++];
	U8(ct)[ 3] = x03 ^ s->k[i++];
	U8(ct)[ 4] = x04 ^ s->k[i++];
	U8(ct)[ 5] = x05 + s->k[i++];
	U8(ct)[ 6] = x06 + s->k[i++];
	U8(ct)[ 7] = x07 ^ s->k[i++];
	U8(ct)[ 8] = x08 ^ s->k[i++];
	U8(ct)[ 9] = x09 + s->k[i++];
	U8(ct)[10] = x10 + s->k[i++];
	U8(ct)[11] = x11 ^ s->k[i++];
	U8(ct)[12] = x12 ^ s->k[i++];
	U8(ct)[13] = x13 + s->k[i++];
	U8(ct)[14] = x14 + s->k[i++];
	U8(ct)[15] = x15 ^ s->k[i++];
}

static void saferpp_decrypt
(
	const kripto_block *s,
	const void *ct,
	void *pt
)
{
	unsigned int i = (s->rounds << 5) + 16;
	uint8_t x15 = CU8(ct)[15] ^ s->k[--i];
	uint8_t x14 = CU8(ct)[14] - s->k[--i];
	uint8_t x13 = CU8(ct)[13] - s->k[--i];
	uint8_t x12 = CU8(ct)[12] ^ s->k[--i];
	uint8_t x11 = CU8(ct)[11] ^ s->k[--i];
	uint8_t x10 = CU8(ct)[10] - s->k[--i];
	uint8_t x09 = CU8(ct)[ 9] - s->k[--i];
	uint8_t x08 = CU8(ct)[ 8] ^ s->k[--i];
	uint8_t x07 = CU8(ct)[ 7] ^ s->k[--i];
	uint8_t x06 = CU8(ct)[ 6] - s->k[--i];
	uint8_t x05 = CU8(ct)[ 5] - s->k[--i];
	uint8_t x04 = CU8(ct)[ 4] ^ s->k[--i];
	uint8_t x03 = CU8(ct)[ 3] ^ s->k[--i];
	uint8_t x02 = CU8(ct)[ 2] - s->k[--i];
	uint8_t x01 = CU8(ct)[ 1] - s->k[--i];
	uint8_t x00 = CU8(ct)[ 0] ^ s->k[--i];

	while(i)
	{
		{ uint8_t t; t = x08; x08 = x04; x04 = x00; x00 = t; }
		{ uint8_t t; t = x13; x13 = x01; x01 = t; }
		{ uint8_t t; t = x09; x09 = x05; x05 = t; }
		{ uint8_t t; t = x06; x06 = x10; x10 = x14; x14 = t; }

		IPHT4(x04, x13, x02, x03);
		IPHT4(x08, x09, x14, x07);
		IPHT4(x00, x05, x06, x11);
		IPHT4(x12, x01, x10, x15);
		
		IPHT4(x08, x05, x02, x15);
		IPHT4(x00, x13, x10, x07);
		IPHT4(x04, x01, x14, x11);
		IPHT4(x12, x09, x06, x03);

		x15 -= s->k[--i];
		x14 ^= s->k[--i];
		x13 ^= s->k[--i];
		x12 -= s->k[--i];
		x11 -= s->k[--i];
		x10 ^= s->k[--i];
		x09 ^= s->k[--i];
		x08 -= s->k[--i];
		x07 -= s->k[--i];
		x06 ^= s->k[--i];
		x05 ^= s->k[--i];
		x04 -= s->k[--i];
		x03 -= s->k[--i];
		x02 ^= s->k[--i];
		x01 ^= s->k[--i];
		x00 -= s->k[--i];

		x15 = LOG(x15) ^ s->k[--i];
		x14 = EXP(x14) - s->k[--i];
		x13 = EXP(x13) - s->k[--i];
		x12 = LOG(x12) ^ s->k[--i];
		x11 = LOG(x11) ^ s->k[--i];
		x10 = EXP(x10) - s->k[--i];
		x09 = EXP(x09) - s->k[--i];
		x08 = LOG(x08) ^ s->k[--i];
		x07 = LOG(x07) ^ s->k[--i];
		x06 = EXP(x06) - s->k[--i];
		x05 = EXP(x05) - s->k[--i];
		x04 = LOG(x04) ^ s->k[--i];
		x03 = LOG(x03) ^ s->k[--i];
		x02 = EXP(x02) - s->k[--i];
		x01 = EXP(x01) - s->k[--i];
		x00 = LOG(x00) ^ s->k[--i];
	}

	U8(pt)[15] = x15;
	U8(pt)[14] = x14;
	U8(pt)[13] = x13;
	U8(pt)[12] = x12;
	U8(pt)[11] = x11;
	U8(pt)[10] = x10;
	U8(pt)[ 9] = x09;
	U8(pt)[ 8] = x08;
	U8(pt)[ 7] = x07;
	U8(pt)[ 6] = x06;
	U8(pt)[ 5] = x05;
	U8(pt)[ 4] = x04;
	U8(pt)[ 3] = x03;
	U8(pt)[ 2] = x02;
	U8(pt)[ 1] = x01;
	U8(pt)[ 0] = x00;
}

static void saferpp_setup
(
	kripto_block *s,
	const uint8_t *key,
	unsigned int len
)
{
	const uint8_t *key2;
	uint8_t *k = s->k;
	uint8_t ka[17];
	uint8_t kb[17];

	kb[16] = ka[16] = 0;

	if(len > 16) key2 = key + 16; /* 256-bit */
	else key2 = key; /* 128-bit */

	for(unsigned int i = 0; i < 16; i++)
	{
		ka[16] ^= ka[i] = ROL8_5(key2[i]);
		kb[16] ^= kb[i] = *k++ = key[i];
	}

	for(unsigned int i = 2; i <= s->rounds << 1; i += 2)
	{
		for(unsigned int j = 0; j <= 16; j++)
		{
			ka[j] = ROL8_6(ka[j]);
			kb[j] = ROL8_6(kb[j]);
		}

		for(unsigned int j = 0; j < 16; j++)
		{
			uint8_t bias = EXP(17 * i + j + 1);
			
			if(i < 16)
			{
				bias = EXP(bias);
			}
			
			*k++ = ka[(i - 1 + j) % 17] + bias;
		}

		for(unsigned int j = 0; j < 16; j++)
		{
			uint8_t bias = EXP(17 * (i + 1) + j + 1);
			
			if(i < 15)
			{
				bias = EXP(bias);
			}
			
			*k++ = kb[(i + j) % 17] + bias;
		}
	}

	kripto_memory_wipe(ka, 17);
	kripto_memory_wipe(kb, 17);
}

static void saferpp_destroy(kripto_block *s)
{
	kripto_memory_wipe(s, sizeof(kripto_block) + (s->rounds << 5) + 16);
	free(s);
}

static kripto_block *saferpp_create
(
	unsigned int r,
	const void *key,
	unsigned int key_len
)
{
	kripto_block *s;

	if(!r)
	{
		if(key_len > 16) r = 10;
		else r = 7;
	}

	s = (kripto_block *)malloc(sizeof(kripto_block) + (r << 5) + 16);
	if(!s) return 0;

	s->obj.desc = kripto_block_saferpp;
	s->rounds = r;
	s->k = (uint8_t *)(s + 1);

	saferpp_setup(s, (const uint8_t *)key, key_len);

	return s;
}

static kripto_block *saferpp_recreate
(
	kripto_block *s,
	unsigned int r,
	const void *key,
	unsigned int key_len
)
{
	if(!r)
	{
		if(key_len > 16) r = 10;
		else r = 7;
	}

	if(r != s->rounds)
	{
		saferpp_destroy(s);
		s = saferpp_create(r, key, key_len);
	}
	else
	{
		saferpp_setup(s, (const uint8_t *)key, key_len);
	}

	return s;
}

static const kripto_block_desc saferpp =
{
	&saferpp_create,
	&saferpp_recreate,
	0, /* tweak */
	&saferpp_encrypt,
	&saferpp_decrypt,
	&saferpp_destroy,
	16, /* block size */
	32, /* max key */
	0 /* max tweak */
};

const kripto_block_desc *const kripto_block_saferpp = &saferpp;

