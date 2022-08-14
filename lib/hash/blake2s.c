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

#include <kripto/hash/blake2s.h>

struct kripto_hash
{
	const kripto_desc_hash *desc;
	unsigned int r;
	uint32_t h[8];
	uint32_t len[2];
	uint32_t f;
	uint8_t buf[64];
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

static const uint32_t IV[8] =
{
	0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
	0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
};

static kripto_hash *blake2s_recreate
(
	kripto_hash *s,
	unsigned int r,
	const void *salt,
	unsigned int salt_len,
	unsigned int out_len
)
{
	uint32_t sw[2] = {0, 0};

	s->r = r;
	if(!s->r) s->r = 10;

	s->f = s->len[0] = s->len[1] = s->i = 0;

	LOAD32L_ARRAY(salt, sw, salt_len);

	/* s->h[0] = IV[0] ^ 0x01010020; */
	s->h[0] = IV[0] ^ 0x01010000 ^ out_len;
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
	D = ROR32_16(D ^ A);	\
	C += D;			\
	B = ROR32_12(B ^ C);	\
				\
	A += B + (M1);		\
	D = ROR32_08(D ^ A);	\
	C += D;			\
	B = ROR32_07(B ^ C);	\
}

static void blake2s_process(kripto_hash *s, const uint8_t *data)
{
	uint32_t x00 = s->h[0];
	uint32_t x01 = s->h[1];
	uint32_t x02 = s->h[2];
	uint32_t x03 = s->h[3];
	uint32_t x04 = s->h[4];
	uint32_t x05 = s->h[5];
	uint32_t x06 = s->h[6];
	uint32_t x07 = s->h[7];
	uint32_t x08 = IV[0];
	uint32_t x09 = IV[1];
	uint32_t x10 = IV[2];
	uint32_t x11 = IV[3];
	uint32_t x12 = IV[4] ^ s->len[0];
	uint32_t x13 = IV[5] ^ s->len[1];
	uint32_t x14 = IV[6] ^ s->f;
	uint32_t x15 = IV[7];
	uint32_t m[16];

	m[ 0] = LOAD32L(data     );
	m[ 1] = LOAD32L(data +  4);
	m[ 2] = LOAD32L(data +  8);
	m[ 3] = LOAD32L(data + 12);
	m[ 4] = LOAD32L(data + 16);
	m[ 5] = LOAD32L(data + 20);
	m[ 6] = LOAD32L(data + 24);
	m[ 7] = LOAD32L(data + 28);
	m[ 8] = LOAD32L(data + 32);
	m[ 9] = LOAD32L(data + 36);
	m[10] = LOAD32L(data + 40);
	m[11] = LOAD32L(data + 44);
	m[12] = LOAD32L(data + 48);
	m[13] = LOAD32L(data + 52);
	m[14] = LOAD32L(data + 56);
	m[15] = LOAD32L(data + 60);

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

	kripto_memory_wipe(m, 64);

	s->h[0] ^= x00 ^ x08;
	s->h[1] ^= x01 ^ x09;
	s->h[2] ^= x02 ^ x10;
	s->h[3] ^= x03 ^ x11;
	s->h[4] ^= x04 ^ x12;
	s->h[5] ^= x05 ^ x13;
	s->h[6] ^= x06 ^ x14;
	s->h[7] ^= x07 ^ x15;
}

static void blake2s_input
(
	kripto_hash *s,
	const void *in,
	size_t len
) 
{
	for(size_t i = 0; i < len; i++)
	{
		s->buf[s->i++] = CU8(in)[i];

		if(s->i == 64)
		{
			s->len[0] += 64;
			if(s->len[0] < 64)
			{
				s->len[1]++;
				assert(s->len[1]);
			}

			blake2s_process(s, s->buf);
			s->i = 0;
		}
	}
}

static void blake2s_finish(kripto_hash *s)
{
	s->len[0] += s->i;
	if(s->len[0] < s->i)
	{
		s->len[1]++;
		assert(s->len[1]);
	}

	while(s->i < 64) s->buf[s->i++] = 0;

	s->f = 0xFFFFFFFF;

	blake2s_process(s, s->buf);

	s->i = 0;
}

static void blake2s_output(kripto_hash *s, void *out, size_t len)
{
	if(!s->f) blake2s_finish(s);

	assert(s->i + len <= 32);
	STORE32L_ARRAY(s->h, s->i, out, len);
	s->i += len;
}

static kripto_hash *blake2s_create
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

	return blake2s_recreate(s, r, salt, salt_len, out_len);
}

static void blake2s_destroy(kripto_hash *s)
{
	kripto_memory_wipe(s, sizeof(kripto_hash));
	free(s);
}

static int blake2s_hash
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

	(void)blake2s_recreate(&s, r, salt, salt_len, out_len);
	blake2s_input(&s, in, in_len);
	blake2s_output(&s, out, out_len);

	kripto_memory_wipe(&s, sizeof(kripto_hash));

	return 0;
}

static const kripto_desc_hash blake2s =
{
	&blake2s_create,
	&blake2s_recreate,
	&blake2s_input,
	&blake2s_output,
	&blake2s_destroy,
	&blake2s_hash,
	32, /* max output */
	64, /* block_size */
	8 /* max salt */
};

const kripto_desc_hash *const kripto_hash_blake2s = &blake2s;
