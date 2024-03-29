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

#include <kripto/hash/md5.h>

struct kripto_hash
{
	const kripto_desc_hash *desc;
	uint64_t len;
	uint32_t h[4];
	uint8_t buf[64];
	unsigned int i;
	int f;
};

static const uint32_t K[64] =
{
	0xD76AA478, 0xE8C7B756, 0x242070DB, 0xC1BDCEEE,
	0xF57C0FAF, 0x4787C62A, 0xA8304613, 0xFD469501,
	0x698098D8, 0x8B44F7AF, 0xFFFF5BB1, 0x895CD7BE,
	0x6B901122, 0xFD987193, 0xA679438E, 0x49B40821,
	0xF61E2562, 0xC040B340, 0x265E5A51, 0xE9B6C7AA,
	0xD62F105D, 0x02441453, 0xD8A1E681, 0xE7D3FBC8,
	0x21E1CDE6, 0xC33707D6, 0xF4D50D87, 0x455A14ED,
	0xA9E3E905, 0xFCEFA3F8, 0x676F02D9, 0x8D2A4C8A,
	0xFFFA3942, 0x8771F681, 0x6D9D6122, 0xFDE5380C,
	0xA4BEEA44, 0x4BDECFA9, 0xF6BB4B60, 0xBEBFBC70,
	0x289B7EC6, 0xEAA127FA, 0xD4EF3085, 0x04881D05,
	0xD9D4D039, 0xE6DB99E5, 0x1FA27CF8, 0xC4AC5665,
	0xF4292244, 0x432AFF97, 0xAB9423A7, 0xFC93A039,
	0x655B59C3, 0x8F0CCC92, 0xFFEFF47D, 0x85845DD1,
	0x6FA87E4F, 0xFE2CE6E0, 0xA3014314, 0x4E0811A1,
	0xF7537E82, 0xBD3AF235, 0x2AD7D2BB, 0xEB86D391
};

static const uint8_t ROT[64] =
{
	7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
	5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
	4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
	6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
};

#define F0(B, C, D) (D ^ (B & (C ^ D)))
#define F1(B, C, D) (C ^ (D & (B ^ C)))
#define F2(B, C, D) (B ^ C ^ D)
#define F3(B, C, D) (C ^ (B | (~D)))

#define G0(A, B, C, D, I)					\
{								\
	A = B + ROL32(A + F0(B, C, D) + K[I] + m[I], ROT[I]);	\
}

#define G1(A, B, C, D, I)							\
{										\
	A = B + ROL32(A + F1(B, C, D) + K[I] + m[(I * 5 + 1) & 15], ROT[I]);	\
}

#define G2(A, B, C, D, I)							\
{										\
	A = B + ROL32(A + F2(B, C, D) + K[I] + m[(I * 3 + 5) & 15], ROT[I]);	\
}

#define G3(A, B, C, D, I)							\
{										\
	A = B + ROL32(A + F3(B, C, D) + K[I] + m[(I * 7) & 15], ROT[I]);	\
}

static kripto_hash *md5_recreate
(
	kripto_hash *s,
	unsigned int r,
	const void *salt,
	unsigned int salt_len,
	unsigned int out_len
)
{
	(void)r;
	(void)salt;
	(void)salt_len;
	(void)out_len;
	s->len = s->f = s->i = 0;

	s->h[0] = 0x67452301;
	s->h[1] = 0xEFCDAB89;
	s->h[2] = 0x98BADCFE;
	s->h[3] = 0x10325476;

	return s;
}

static void md5_process(kripto_hash *s, const uint8_t *data)
{
	uint32_t a = s->h[0];
	uint32_t b = s->h[1];
	uint32_t c = s->h[2];
	uint32_t d = s->h[3];
	uint32_t m[16];
	unsigned int i;

	m[0] = LOAD32L(data);
	m[1] = LOAD32L(data + 4);
	m[2] = LOAD32L(data + 8);
	m[3] = LOAD32L(data + 12);
	m[4] = LOAD32L(data + 16);
	m[5] = LOAD32L(data + 20);
	m[6] = LOAD32L(data + 24);
	m[7] = LOAD32L(data + 28);
	m[8] = LOAD32L(data + 32);
	m[9] = LOAD32L(data + 36);
	m[10] = LOAD32L(data + 40);
	m[11] = LOAD32L(data + 44);
	m[12] = LOAD32L(data + 48);
	m[13] = LOAD32L(data + 52);
	m[14] = LOAD32L(data + 56);
	m[15] = LOAD32L(data + 60);

	for(i = 0; i < 16;)
	{
		G0(a, b, c, d, i); i++;
		G0(d, a, b, c, i); i++;
		G0(c, d, a, b, i); i++;
		G0(b, c, d, a, i); i++;
	}

	while(i < 32)
	{
		G1(a, b, c, d, i); i++;
		G1(d, a, b, c, i); i++;
		G1(c, d, a, b, i); i++;
		G1(b, c, d, a, i); i++;
	}

	while(i < 48)
	{
		G2(a, b, c, d, i); i++;
		G2(d, a, b, c, i); i++;
		G2(c, d, a, b, i); i++;
		G2(b, c, d, a, i); i++;
	}

	while(i < 64)
	{
		G3(a, b, c, d, i); i++;
		G3(d, a, b, c, i); i++;
		G3(c, d, a, b, i); i++;
		G3(b, c, d, a, i); i++;
	}

	kripto_memory_wipe(m, 64);

	s->h[0] += a;
	s->h[1] += b;
	s->h[2] += c;
	s->h[3] += d;
}

static void md5_input
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
			s->len += 512;
			assert(s->len >= 512);

			md5_process(s, s->buf);
			s->i = 0;
		}
	}
}

static void md5_finish(kripto_hash *s)
{
	s->len += s->i << 3;
	assert(s->len >= (s->i << 3));

	s->buf[s->i++] = 0x80; /* pad */

	if(s->i > 56) /* not enough space for length */
	{
		while(s->i < 64) s->buf[s->i++] = 0;
		md5_process(s, s->buf);
		s->i = 0;
	}
	while(s->i < 56) s->buf[s->i++] = 0;

	/* add length */
	STORE64L(s->len, s->buf + 56);

	md5_process(s, s->buf);

	s->i = 0;
	s->f = -1;
}

static void md5_output(kripto_hash *s, void *out, size_t len)
{
	if(!s->f) md5_finish(s);

	assert(s->i + len <= 16);
	STORE32L_ARRAY(s->h, s->i, out, len);
	s->i += len;
}

static kripto_hash *md5_create
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

	return md5_recreate(s, r, salt, salt_len, out_len);
}

static void md5_destroy(kripto_hash *s)
{
	kripto_memory_wipe(s, sizeof(kripto_hash));
	free(s);
}

static int md5_hash
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

	(void)md5_recreate(&s, r, salt, salt_len, out_len);
	md5_input(&s, in, in_len);
	md5_output(&s, out, out_len);

	kripto_memory_wipe(&s, sizeof(kripto_hash));

	return 0;
}

static const kripto_desc_hash md5 =
{
	&md5_create,
	&md5_recreate,
	&md5_input,
	&md5_output,
	&md5_destroy,
	&md5_hash,
	16, /* max output */
	64, /* block_size */
	0 /* max salt */
};

const kripto_desc_hash *const kripto_hash_md5 = &md5;
