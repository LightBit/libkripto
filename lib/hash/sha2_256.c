﻿/*
 * Written in 2013 by Gregor Pintar <grpintar@gmail.com>
 *
 * To the extent possible under law, the author(s) have dedicated
 * all copyright and related and neighboring rights to this software
 * to the public domain worldwide.
 * 
 * This software is distributed without any warranty.
 *
 * You should have received a copy of the CC0 Public Domain Dedication.
 * If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <limits.h>
#include <assert.h>

#include <kripto/cast.h>
#include <kripto/loadstore.h>
#include <kripto/rotate.h>
#include <kripto/memwipe.h>
#include <kripto/hash.h>
#include <kripto/desc/hash.h>
#include <kripto/object/hash.h>

#include <kripto/hash/sha2_256.h>

struct kripto_hash
{
	struct kripto_hash_object obj;
	uint64_t len;
	uint32_t h[8];
	uint8_t buf[64];
	unsigned int r;
	unsigned int i;
	int o;
};

static const uint32_t RC[128] =
{
	0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
	0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
	0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
	0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
	0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
	0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
	0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
	0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
	0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
	0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
	0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
	0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
	0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
	0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
	0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
	0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
	0xCA273ECE, 0xD186B8C7, 0xEADA7DD6, 0xF57D4F7F,
	0x06F067AA, 0x0A637DC5, 0x113F9804, 0x1B710B35,
	0x28DB77F5, 0x32CAAB7B, 0x3C9EBE0A, 0x431D67C4,
	0x4CC5D4BE, 0x597F299C, 0x5FCB6FAB, 0x6C44198C,
	0x7BA0EA2D, 0x7EABF2D0, 0x8DBE8D03, 0x90BB1721,
	0x99A2AD45, 0x9F86E289, 0xA84C4472, 0xB3DF34FC,
	0xB99BB8D7, 0xBC76CBAB, 0xC226A69A, 0xD304F19A,
	0xDE1BE20A, 0xE39BB437, 0xEE84927C, 0xF3EDD277,
	0xFBFDFE53, 0x0BEE2C7A, 0x0E90181C, 0x25F57204,
	0x2DA45582, 0x3A52C34C, 0x41DC0172, 0x495796FC,
	0x4BD31FC6, 0x533CDE21, 0x5F7ABFE3, 0x66C206B3,
	0x6DFCC6BC, 0x7062F20F, 0x778D5127, 0x7EABA3CC,
	0x8363ECCC, 0x85BE1C25, 0x93C04028, 0x9F4A205F,
	0xA1953565, 0xA627BB0F, 0xACFA8089, 0xB3C29B23,
	0xB602F6FA, 0xC36CEE0A, 0xC7DC81EE, 0xCE7B8471,
	0xD740288C, 0xE21DBA7A, 0xEABBFF66, 0xF56A9E60
};

static kripto_hash *sha2_256_recreate
(
	kripto_hash *s,
	unsigned int r,
	size_t len
)
{
	s->len = s->o = s->i = 0;

	s->r = r;
	if(!s->r) s->r = 64;

	if(len > 28)
	{
		/* 256 */
		s->h[0] = 0x6A09E667;
		s->h[1] = 0xBB67AE85;
		s->h[2] = 0x3C6EF372;
		s->h[3] = 0xA54FF53A;
		s->h[4] = 0x510E527F;
		s->h[5] = 0x9B05688C;
		s->h[6] = 0x1F83D9AB;
		s->h[7] = 0x5BE0CD19;
	}
	else
	{
		/* 224 */
		s->h[0] = 0xC1059ED8;
		s->h[1] = 0x367CD507;
		s->h[2] = 0x3070DD17;
		s->h[3] = 0xF70E5939;
		s->h[4] = 0xFFC00B31;
		s->h[5] = 0x68581511;
		s->h[6] = 0x64F98FA7;
		s->h[7] = 0xBEFA4FA4;
	}

	return s;
}

#define CH(X0, X1, X2) (X2 ^ (X0 & (X1 ^ X2)))
#define MAJ(X0, X1, X2) ((X0 & X1) | (X2 & (X0 | X1)))

#define S0(X) (ROR32_07(X) ^ ROR32_18(X) ^ ((X) >> 3))
#define S1(X) (ROR32_17(X) ^ ROR32_19(X) ^ ((X) >> 10))

#define E0(X) (ROR32_02(X) ^ ROR32_13(X) ^ ROR32_22(X))
#define E1(X) (ROR32_06(X) ^ ROR32_11(X) ^ ROR32_25(X))

#define ROUND(A, B, C, D, E, F, G, H, RC, RK) \
{ \
	H += E1(E) + CH(E, F, G) + RC + RK; \
	D += H; \
	H += E0(A) + MAJ(A, B, C); \
}

#define KI(K, I) \
( \
	K[I & 15] += S0(K[(I + 1) & 15]) \
		+ K[(I + 9) & 15] \
		+ S1(K[(I + 14) & 15]) \
)

static void sha2_256_process(kripto_hash *s, const uint8_t *data)
{
	uint32_t a = s->h[0];
	uint32_t b = s->h[1];
	uint32_t c = s->h[2];
	uint32_t d = s->h[3];
	uint32_t e = s->h[4];
	uint32_t f = s->h[5];
	uint32_t g = s->h[6];
	uint32_t h = s->h[7];
	uint32_t k[16];
	unsigned int i;

	k[ 0] = LOAD32B(data     );
	k[ 1] = LOAD32B(data +  4);
	k[ 2] = LOAD32B(data +  8);
	k[ 3] = LOAD32B(data + 12);
	k[ 4] = LOAD32B(data + 16);
	k[ 5] = LOAD32B(data + 20);
	k[ 6] = LOAD32B(data + 24);
	k[ 7] = LOAD32B(data + 28);
	k[ 8] = LOAD32B(data + 32);
	k[ 9] = LOAD32B(data + 36);
	k[10] = LOAD32B(data + 40);
	k[11] = LOAD32B(data + 44);
	k[12] = LOAD32B(data + 48);
	k[13] = LOAD32B(data + 52);
	k[14] = LOAD32B(data + 56);
	k[15] = LOAD32B(data + 60);

	ROUND(a, b, c, d, e, f, g, h, RC[ 0], k[ 0]);
	ROUND(h, a, b, c, d, e, f, g, RC[ 1], k[ 1]);
	ROUND(g, h, a, b, c, d, e, f, RC[ 2], k[ 2]);
	ROUND(f, g, h, a, b, c, d, e, RC[ 3], k[ 3]);
	ROUND(e, f, g, h, a, b, c, d, RC[ 4], k[ 4]);
	ROUND(d, e, f, g, h, a, b, c, RC[ 5], k[ 5]);
	ROUND(c, d, e, f, g, h, a, b, RC[ 6], k[ 6]);
	ROUND(b, c, d, e, f, g, h, a, RC[ 7], k[ 7]);
	
	ROUND(a, b, c, d, e, f, g, h, RC[ 8], k[ 8]);
	ROUND(h, a, b, c, d, e, f, g, RC[ 9], k[ 9]);
	ROUND(g, h, a, b, c, d, e, f, RC[10], k[10]);
	ROUND(f, g, h, a, b, c, d, e, RC[11], k[11]);
	ROUND(e, f, g, h, a, b, c, d, RC[12], k[12]);
	ROUND(d, e, f, g, h, a, b, c, RC[13], k[13]);
	ROUND(c, d, e, f, g, h, a, b, RC[14], k[14]);
	ROUND(b, c, d, e, f, g, h, a, RC[15], k[15]);

	for(i = 16; i < s->r;)
	{
		ROUND(a, b, c, d, e, f, g, h, RC[i], KI(k, i)); i++;
		ROUND(h, a, b, c, d, e, f, g, RC[i], KI(k, i)); i++;
		ROUND(g, h, a, b, c, d, e, f, RC[i], KI(k, i)); i++;
		ROUND(f, g, h, a, b, c, d, e, RC[i], KI(k, i)); i++;
		ROUND(e, f, g, h, a, b, c, d, RC[i], KI(k, i)); i++;
		ROUND(d, e, f, g, h, a, b, c, RC[i], KI(k, i)); i++;
		ROUND(c, d, e, f, g, h, a, b, RC[i], KI(k, i)); i++;
		ROUND(b, c, d, e, f, g, h, a, RC[i], KI(k, i)); i++;
	}

	kripto_memwipe(k, 16);

	s->h[0] += a;
	s->h[1] += b;
	s->h[2] += c;
	s->h[3] += d;
	s->h[4] += e;
	s->h[5] += f;
	s->h[6] += g;
	s->h[7] += h;
}

static void sha2_256_input
(
	kripto_hash *s,
	const void *in,
	size_t len
) 
{
	size_t i;

	s->len += len << 3;
	assert(s->len >= len << 3);

	for(i = 0; i < len; i++)
	{
		s->buf[s->i++] = CU8(in)[i];

		if(s->i == 64)
		{
			sha2_256_process(s, s->buf);
			s->i = 0;
		}
	}
}

static void sha2_256_finish(kripto_hash *s)
{
	s->buf[s->i++] = 0x80; /* pad */

	if(s->i > 56) /* not enough space for length */
	{
		while(s->i < 64) s->buf[s->i++] = 0;
		sha2_256_process(s, s->buf);
		s->i = 0;
	}
	while(s->i < 56) s->buf[s->i++] = 0;

	/* add length */
	//s->len << 3;
	STORE64B(s->len, s->buf + 56);

	sha2_256_process(s, s->buf);

	s->i = 0;
	s->o = -1;
}

static void sha2_256_output(kripto_hash *s, void *out, size_t len)
{
	unsigned int i;

	if(!s->o) sha2_256_finish(s);

	/* big endian */
	for(i = 0; i < len; s->i++, i++)
		U8(out)[i] = s->h[s->i >> 2] >> (24 - ((s->i & 3) << 3));
}

static kripto_hash *sha2_256_create(unsigned int r, size_t len)
{
	kripto_hash *s;

	s = malloc(sizeof(kripto_hash));
	if(!s) return 0;

	s->obj.desc = kripto_hash_sha2_256;

	(void)sha2_256_recreate(s, r, len);

	return s;
}

static void sha2_256_destroy(kripto_hash *s)
{
	kripto_memwipe(s, sizeof(kripto_hash));
	free(s);
}

static int sha2_256_hash
(
	unsigned int r,
	const void *in,
	size_t in_len,
	void *out,
	size_t out_len
)
{
	kripto_hash s;

	(void)sha2_256_recreate(&s, r, out_len);
	sha2_256_input(&s, in, in_len);
	sha2_256_output(&s, out, out_len);

	kripto_memwipe(&s, sizeof(kripto_hash));

	return 0;
}

static const kripto_hash_desc sha2_256 =
{
	&sha2_256_create,
	&sha2_256_recreate,
	&sha2_256_input,
	&sha2_256_output,
	&sha2_256_destroy,
	&sha2_256_hash,
	32, /* max output */
	64 /* block_size */
};

const kripto_hash_desc *const kripto_hash_sha2_256 = &sha2_256;
