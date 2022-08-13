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
#include <stddef.h>
#include <stdlib.h>
#include <assert.h>

#include <kripto/cast.h>
#include <kripto/loadstore.h>
#include <kripto/rotate.h>
#include <kripto/memory.h>
#include <kripto/hash.h>
#include <kripto/desc/hash.h>

#include <kripto/hash/blake2b.h>

struct kripto_hash
{
	const kripto_desc_hash *desc;
	unsigned int r;
	uint64_t h[8];
	uint64_t len[2];
	uint64_t f;
	uint8_t buf[128];
	unsigned int i;
};

static const uint8_t SIGMA[10][16] =
{
	{ 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15},
	{14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3},
	{11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4},
	{ 7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8},
	{ 9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13},
	{ 2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9},
	{12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11},
	{13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10},
	{ 6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5},
	{10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0}
};

static const uint64_t IV[8] =
{
	0x6A09E667F3BCC908, 0xBB67AE8584CAA73B,
	0x3C6EF372FE94F82B, 0xA54FF53A5F1D36F1,
	0x510E527FADE682D1, 0x9B05688C2B3E6C1F,
	0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179
};

static kripto_hash *blake2b_recreate
(
	kripto_hash *s,
	unsigned int r,
	const void *salt,
	unsigned int salt_len,
	unsigned int out_len
)
{
	uint64_t sw[2] = {0, 0};

	s->r = r;
	if(!s->r) s->r = 12;

	s->f = s->len[0] = s->len[1] = s->i = 0;

	LOAD64L_ARRAY(salt, sw, salt_len);

	/* s->h[0] = IV[0] ^ 0x0000000001010040; */
	s->h[0] = IV[0] ^ 0x0000000001010000 ^ out_len;
	s->h[1] = IV[1];
	s->h[2] = IV[2];
	s->h[3] = IV[3];
	s->h[4] = IV[4] ^ sw[0];
	s->h[5] = IV[5] ^ sw[1];
	s->h[6] = IV[6];
	s->h[7] = IV[7];

	return s;
}

#define G(A, B, C, D, M0, M1)	\
{				\
	A += B + (M0);		\
	D = ROR64_32(D ^ A);	\
	C += D;			\
	B = ROR64_24(B ^ C);	\
				\
	A += B + (M1);		\
	D = ROR64_16(D ^ A);	\
	C += D;			\
	B = ROR64_63(B ^ C);	\
}

static void blake2b_process(kripto_hash *s, const uint8_t *data)
{
	uint64_t x00 = s->h[0];
	uint64_t x01 = s->h[1];
	uint64_t x02 = s->h[2];
	uint64_t x03 = s->h[3];
	uint64_t x04 = s->h[4];
	uint64_t x05 = s->h[5];
	uint64_t x06 = s->h[6];
	uint64_t x07 = s->h[7];
	uint64_t x08 = IV[0];
	uint64_t x09 = IV[1];
	uint64_t x10 = IV[2];
	uint64_t x11 = IV[3];
	uint64_t x12 = IV[4] ^ s->len[0];
	uint64_t x13 = IV[5] ^ s->len[1];
	uint64_t x14 = IV[6] ^ s->f;
	uint64_t x15 = IV[7];
	uint64_t m[16];

	m[ 0] = LOAD64L(data      );
	m[ 1] = LOAD64L(data +   8);
	m[ 2] = LOAD64L(data +  16);
	m[ 3] = LOAD64L(data +  24);
	m[ 4] = LOAD64L(data +  32);
	m[ 5] = LOAD64L(data +  40);
	m[ 6] = LOAD64L(data +  48);
	m[ 7] = LOAD64L(data +  56);
	m[ 8] = LOAD64L(data +  64);
	m[ 9] = LOAD64L(data +  72);
	m[10] = LOAD64L(data +  80);
	m[11] = LOAD64L(data +  88);
	m[12] = LOAD64L(data +  96);
	m[13] = LOAD64L(data + 104);
	m[14] = LOAD64L(data + 112);
	m[15] = LOAD64L(data + 120);

	for(unsigned int r = 0, i = 0; r < s->r; r++, i++)
	{
		if(i == 10) i = 0;

		G(x00, x04, x08, x12, m[SIGMA[i][ 0]], m[SIGMA[i][ 1]]);
		G(x01, x05, x09, x13, m[SIGMA[i][ 2]], m[SIGMA[i][ 3]]);
		G(x02, x06, x10, x14, m[SIGMA[i][ 4]], m[SIGMA[i][ 5]]);
		G(x03, x07, x11, x15, m[SIGMA[i][ 6]], m[SIGMA[i][ 7]]);

		G(x00, x05, x10, x15, m[SIGMA[i][ 8]], m[SIGMA[i][ 9]]);
		G(x01, x06, x11, x12, m[SIGMA[i][10]], m[SIGMA[i][11]]);
		G(x02, x07, x08, x13, m[SIGMA[i][12]], m[SIGMA[i][13]]);
		G(x03, x04, x09, x14, m[SIGMA[i][14]], m[SIGMA[i][15]]);
	}

	kripto_memory_wipe(m, 128);

	s->h[0] ^= x00 ^ x08;
	s->h[1] ^= x01 ^ x09;
	s->h[2] ^= x02 ^ x10;
	s->h[3] ^= x03 ^ x11;
	s->h[4] ^= x04 ^ x12;
	s->h[5] ^= x05 ^ x13;
	s->h[6] ^= x06 ^ x14;
	s->h[7] ^= x07 ^ x15;
}

static void blake2b_input
(
	kripto_hash *s,
	const void *in,
	size_t len
) 
{
	for(size_t i = 0; i < len; i++)
	{
		if(s->i == 128)
		{
			s->len[0] += 128;
			if(s->len[0] < 128)
			{
				s->len[1]++;
				assert(s->len[1]);
			}

			blake2b_process(s, s->buf);
			s->i = 0;
		}

		s->buf[s->i++] = CU8(in)[i];
	}
}

static void blake2b_finish(kripto_hash *s)
{
	s->len[0] += s->i;
	if(s->len[0] < s->i)
	{
		s->len[1]++;
		assert(s->len[1]);
	}

	while(s->i < 128) s->buf[s->i++] = 0;

	s->f = 0xFFFFFFFFFFFFFFFF;

	blake2b_process(s, s->buf);

	s->i = 0;
}

static void blake2b_output(kripto_hash *s, void *out, size_t len)
{
	if(!s->f) blake2b_finish(s);

	STORE64L_ARRAY(s->h, s->i, out, len);
	s->i += len;
}

static kripto_hash *blake2b_create
(
	const kripto_desc_hash *desc,
	unsigned int r,
	const void *salt,
	unsigned int salt_len,
	unsigned int out_len
)
{
	kripto_hash *s = (kripto_hash *)malloc(sizeof(kripto_hash));
	if(!s) return 0;

	s->desc = desc;

	return blake2b_recreate(s, r, salt, salt_len, out_len);
}

static void blake2b_destroy(kripto_hash *s)
{
	kripto_memory_wipe(s, sizeof(kripto_hash));
	free(s);
}

static int blake2b_hash
(
	const kripto_desc_hash *desc,
	unsigned int r,
	const void *salt,
	unsigned int salt_len,
	const void *in,
	size_t in_len,
	void *out,
	size_t out_len
)
{
	kripto_hash s;
	(void)desc;

	(void)blake2b_recreate(&s, r, salt, salt_len, out_len);
	blake2b_input(&s, in, in_len);
	blake2b_output(&s, out, out_len);

	kripto_memory_wipe(&s, sizeof(kripto_hash));

	return 0;
}

static const kripto_desc_hash blake2b =
{
	&blake2b_create,
	&blake2b_recreate,
	&blake2b_input,
	&blake2b_output,
	&blake2b_destroy,
	&blake2b_hash,
	64, /* max output */
	128, /* block_size */
	16 /* max salt */
};

const kripto_desc_hash *const kripto_hash_blake2b = &blake2b;
