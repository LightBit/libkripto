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

#include <kripto/block/sm4.h>

struct kripto_block
{
	struct kripto_block_object obj;
	unsigned int r;
	uint32_t *k;
};

static const uint8_t S[256] =
{
	0xD6, 0x90, 0xE9, 0xFE, 0xCC, 0xE1, 0x3D, 0xB7,
	0x16, 0xB6, 0x14, 0xC2, 0x28, 0xFB, 0x2C, 0x05,
	0x2B, 0x67, 0x9A, 0x76, 0x2A, 0xBE, 0x04, 0xC3,
	0xAA, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
	0x9C, 0x42, 0x50, 0xF4, 0x91, 0xEF, 0x98, 0x7A,
	0x33, 0x54, 0x0B, 0x43, 0xED, 0xCF, 0xAC, 0x62,
	0xE4, 0xB3, 0x1C, 0xA9, 0xC9, 0x08, 0xE8, 0x95,
	0x80, 0xDF, 0x94, 0xFA, 0x75, 0x8F, 0x3F, 0xA6,
	0x47, 0x07, 0xA7, 0xFC, 0xF3, 0x73, 0x17, 0xBA,
	0x83, 0x59, 0x3C, 0x19, 0xE6, 0x85, 0x4F, 0xA8,
	0x68, 0x6B, 0x81, 0xB2, 0x71, 0x64, 0xDA, 0x8B,
	0xF8, 0xEB, 0x0F, 0x4B, 0x70, 0x56, 0x9D, 0x35,
	0x1E, 0x24, 0x0E, 0x5E, 0x63, 0x58, 0xD1, 0xA2,
	0x25, 0x22, 0x7C, 0x3B, 0x01, 0x21, 0x78, 0x87,
	0xD4, 0x00, 0x46, 0x57, 0x9F, 0xD3, 0x27, 0x52,
	0x4C, 0x36, 0x02, 0xE7, 0xA0, 0xC4, 0xC8, 0x9E,
	0xEA, 0xBF, 0x8A, 0xD2, 0x40, 0xC7, 0x38, 0xB5,
	0xA3, 0xF7, 0xF2, 0xCE, 0xF9, 0x61, 0x15, 0xA1,
	0xE0, 0xAE, 0x5D, 0xA4, 0x9B, 0x34, 0x1A, 0x55,
	0xAD, 0x93, 0x32, 0x30, 0xF5, 0x8C, 0xB1, 0xE3,
	0x1D, 0xF6, 0xE2, 0x2E, 0x82, 0x66, 0xCA, 0x60,
	0xC0, 0x29, 0x23, 0xAB, 0x0D, 0x53, 0x4E, 0x6F,
	0xD5, 0xDB, 0x37, 0x45, 0xDE, 0xFD, 0x8E, 0x2F,
	0x03, 0xFF, 0x6A, 0x72, 0x6D, 0x6C, 0x5B, 0x51,
	0x8D, 0x1B, 0xAF, 0x92, 0xBB, 0xDD, 0xBC, 0x7F,
	0x11, 0xD9, 0x5C, 0x41, 0x1F, 0x10, 0x5A, 0xD8,
	0x0A, 0xC1, 0x31, 0x88, 0xA5, 0xCD, 0x7B, 0xBD,
	0x2D, 0x74, 0xD0, 0x12, 0xB8, 0xE5, 0xB4, 0xB0,
	0x89, 0x69, 0x97, 0x4A, 0x0C, 0x96, 0x77, 0x7E,
	0x65, 0xB9, 0xF1, 0x09, 0xC5, 0x6E, 0xC6, 0x84,
	0x18, 0xF0, 0x7D, 0xEC, 0x3A, 0xDC, 0x4D, 0x20,
	0x79, 0xEE, 0x5F, 0x3E, 0xD7, 0xCB, 0x39, 0x48
};

static const uint32_t CK[32] =
{
	0x00070E15, 0x1C232A31, 0x383F464D, 0x545B6269,
	0x70777E85, 0x8C939AA1, 0xA8AFB6BD, 0xC4CBD2D9,
	0xE0E7EEF5, 0xFC030A11, 0x181F262D, 0x343B4249,
	0x50575E65, 0x6C737A81, 0x888F969D, 0xA4ABB2B9,
	0xC0C7CED5, 0xDCE3EAF1, 0xF8FF060D, 0x141B2229,
	0x30373E45, 0x4C535A61, 0x686F767D, 0x848B9299,
	0xA0A7AEB5, 0xBCC3CAD1, 0xD8DFE6ED, 0xF4FB0209,
	0x10171E25, 0x2C333A41, 0x484F565D, 0x646B7279
};

#define TAU(X)					\
(						\
	(S[(uint8_t)((X) >> 24)] << 24) |	\
	(S[(uint8_t)((X) >> 16)] << 16) |	\
	(S[(uint8_t)((X) >>  8)] <<  8) |	\
	(S[(uint8_t)((X)      )]      )		\
)

#define L(X) ((X) ^ ROL32_02(X) ^ ROL32_10(X) ^ ROL32_18(X) ^ ROL32_24(X))
#define LS(X) ((X) ^ ROL32_13(X) ^ ROL32_23(X))

#define F(A, B, C, D, RK)		\
{					\
	uint32_t T = B ^ C ^ D ^ RK;	\
	T = TAU(T);			\
	A ^= L(T);			\
}

#define FS(A, B, C, D, RK)		\
{					\
	uint32_t T = B ^ C ^ D ^ RK;	\
	T = TAU(T);			\
	A ^= LS(T);			\
}

static void sm4_encrypt
(
	const kripto_block *s,
	const void *pt,
	void *ct
)
{
	uint32_t a = LOAD32B(CU8(pt)     );
	uint32_t b = LOAD32B(CU8(pt) +  4);
	uint32_t c = LOAD32B(CU8(pt) +  8);
	uint32_t d = LOAD32B(CU8(pt) + 12);

	for(unsigned int i = 0; i < s->r;)
	{
		F(a, b, c, d, s->k[i]); i++;
		F(b, c, d, a, s->k[i]); i++;
		F(c, d, a, b, s->k[i]); i++;
		F(d, a, b, c, s->k[i]); i++;
	}

	STORE32B(d, U8(ct)     );
	STORE32B(c, U8(ct) +  4);
	STORE32B(b, U8(ct) +  8);
	STORE32B(a, U8(ct) + 12);
}

static void sm4_decrypt
(
	const kripto_block *s,
	const void *ct,
	void *pt
)
{
	uint32_t a = LOAD32B(CU8(ct)     );
	uint32_t b = LOAD32B(CU8(ct) +  4);
	uint32_t c = LOAD32B(CU8(ct) +  8);
	uint32_t d = LOAD32B(CU8(ct) + 12);

	for(unsigned int i = s->r; i > 0;)
	{
		i--; F(a, b, c, d, s->k[i]);
		i--; F(b, c, d, a, s->k[i]);
		i--; F(c, d, a, b, s->k[i]);
		i--; F(d, a, b, c, s->k[i]);
	}

	STORE32B(d, U8(pt)     );
	STORE32B(c, U8(pt) +  4);
	STORE32B(b, U8(pt) +  8);
	STORE32B(a, U8(pt) + 12);
}

static void sm4_setup
(
	kripto_block *s,
	const void *key,
	unsigned int key_len
)
{
	uint32_t k[4] = {0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC};

	for(unsigned int i = 0; i < key_len; i++)
	{
		k[i >> 2] ^= CU8(key)[i] << (24 - ((i & 3) << 3));
	}

	for(unsigned int i = 0; i < s->r;)
	{
		FS(k[0], k[1], k[2], k[3], CK[i]); s->k[i++] = k[0];
		FS(k[1], k[2], k[3], k[0], CK[i]); s->k[i++] = k[1];
		FS(k[2], k[3], k[0], k[1], CK[i]); s->k[i++] = k[2];
		FS(k[3], k[0], k[1], k[2], CK[i]); s->k[i++] = k[3];
	}

	kripto_memory_wipe(k, 16);
}

static kripto_block *sm4_create
(
	unsigned int r,
	const void *key,
	unsigned int key_len
)
{
	if(!r) r = 32;

	kripto_block *s = (kripto_block *)malloc(sizeof(kripto_block) + (r << 2));
	if(!s) return 0;

	s->obj.desc = kripto_block_sm4;
	s->k = (uint32_t *)(s + 1);
	s->r = r;
	sm4_setup(s, key, key_len);

	return s;
}

static void sm4_destroy(kripto_block *s)
{
	kripto_memory_wipe(s, sizeof(kripto_block) + (s->r << 2));
	free(s);
}

static kripto_block *sm4_recreate
(
	kripto_block *s,
	unsigned int r,
	const void *key,
	unsigned int key_len
)
{
	if(!r) r = 32;

	if(r != s->r)
	{
		sm4_destroy(s);
		s = sm4_create(r, key, key_len);
	}
	else
	{
		sm4_setup(s, key, key_len);
	}

	return s;
}

static const kripto_block_desc sm4 =
{
	&sm4_create,
	&sm4_recreate,
	0, /* tweak */
	&sm4_encrypt,
	&sm4_decrypt,
	&sm4_destroy,
	16, /* block size */
	16, /* max key */
	0 /* max tweak */
};

const kripto_block_desc *const kripto_block_sm4 = &sm4;
