/*
 * Copyright (C) 2011 by Gregor Pintar <grpintar@gmail.com>
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
#include <assert.h>

#include <kripto/loadstore.h>
#include <kripto/rotate.h>
#include <kripto/memory.h>
#include <kripto/stream.h>
#include <kripto/desc/stream.h>
#include <kripto/object/stream.h>

#include <kripto/stream/salsa20.h>

struct kripto_stream
{
	struct kripto_stream_object obj;
	unsigned int r;
	uint32_t x[16];
	uint8_t buf[64];
	unsigned int used;
};

#define QR(A, B, C, D)		\
{				\
	B ^= ROL32_07(A + D);	\
	C ^= ROL32_09(B + A);	\
	D ^= ROL32_13(C + B);	\
	A ^= ROL32_18(D + C);	\
}

static void salsa20_core
(
	unsigned int r,
	const uint32_t *x,
	void *out
)
{
	uint32_t x00 = x[ 0];
	uint32_t x01 = x[ 1];
	uint32_t x02 = x[ 2];
	uint32_t x03 = x[ 3];
	uint32_t x04 = x[ 4];
	uint32_t x05 = x[ 5];
	uint32_t x06 = x[ 6];
	uint32_t x07 = x[ 7];
	uint32_t x08 = x[ 8];
	uint32_t x09 = x[ 9];
	uint32_t x10 = x[10];
	uint32_t x11 = x[11];
	uint32_t x12 = x[12];
	uint32_t x13 = x[13];
	uint32_t x14 = x[14];
	uint32_t x15 = x[15];

	for(unsigned int i = 0; i < r; i++)
	{
		QR(x00, x04, x08, x12);
		QR(x05, x09, x13, x01);
		QR(x10, x14, x02, x06);
		QR(x15, x03, x07, x11);

		if(++i == r) break;

		QR(x00, x01, x02, x03);
		QR(x05, x06, x07, x04);
		QR(x10, x11, x08, x09);
		QR(x15, x12, x13, x14);
	}

	x00 += x[ 0];
	x01 += x[ 1];
	x02 += x[ 2];
	x03 += x[ 3];
	x04 += x[ 4];
	x05 += x[ 5];
	x06 += x[ 6];
	x07 += x[ 7];
	x08 += x[ 8];
	x09 += x[ 9];
	x10 += x[10];
	x11 += x[11];
	x12 += x[12];
	x13 += x[13];
	x14 += x[14];
	x15 += x[15];

	STORE32L(x00, U8(out)     );
	STORE32L(x01, U8(out) +  4);
	STORE32L(x02, U8(out) +  8);
	STORE32L(x03, U8(out) + 12);
	STORE32L(x04, U8(out) + 16);
	STORE32L(x05, U8(out) + 20);
	STORE32L(x06, U8(out) + 24);
	STORE32L(x07, U8(out) + 28);
	STORE32L(x08, U8(out) + 32);
	STORE32L(x09, U8(out) + 36);
	STORE32L(x10, U8(out) + 40);
	STORE32L(x11, U8(out) + 44);
	STORE32L(x12, U8(out) + 48);
	STORE32L(x13, U8(out) + 52);
	STORE32L(x14, U8(out) + 56);
	STORE32L(x15, U8(out) + 60);
}

static void salsa20_crypt
(
	kripto_stream *s,
	const void *in,
	void *out,
	size_t len
)
{
	size_t i;

	for(i = 0; i < len; i++)
	{
		if(s->used == 64)
		{
			salsa20_core(s->r, s->x, s->buf);
			s->used = 0;

			if(!++s->x[8])
			{
				++s->x[9];
				assert(s->x[9]);
			}
		}

		U8(out)[i] = CU8(in)[i] ^ s->buf[s->used++];
	}
}

static void salsa20_prng
(
	kripto_stream *s,
	void *out,
	size_t len
)
{
	size_t i;

	for(i = 0; i < len; i++)
	{
		if(s->used == 64)
		{
			salsa20_core(s->r, s->x, s->buf);
			s->used = 0;

			if(!++s->x[8])
			{
				++s->x[9];
				assert(s->x[9]);
			}
		}

		U8(out)[i] = s->buf[s->used++];
	}
}

static kripto_stream *salsa20_recreate
(
	kripto_stream *s,
	unsigned int r,
	const void *key,
	unsigned int key_len,
	const void *iv,
	unsigned int iv_len
)
{
	const uint32_t constant[4] =
	{
		0x61707865,				// "expa"
		0x3020646E + ((key_len / 10) << 24),	// "nd 0"
		0x79622D30 + (key_len % 10),		// "0-by"
		0x6B206574				// "te k"
	};

	s->x[ 0] = constant[0];
	s->x[ 5] = constant[1];
	s->x[10] = constant[2];
	s->x[15] = constant[3];

	/* KEY */
	s->x[1] = s->x[2] = s->x[3] = s->x[4] = 0;
	LOAD32L_ARRAY(key, s->x + 1, key_len > 16 ? 16 : key_len);

	/* IV */
	s->x[6] = s->x[7] = s->x[8] = s->x[9] = 0;
	LOAD32L_ARRAY(iv, s->x + 6, iv_len > 16 ? 16 : iv_len);

	/* KEY */
	s->x[11] = s->x[12] = s->x[13] = s->x[14] = 0;
	LOAD32L_ARRAY
	(
		key_len > 16 ? CU8(key) + 16 : key,
		s->x + 11,
		key_len > 16 ? key_len - 16 : key_len
	);

	s->r = r;
	if(!s->r) s->r = 20;

	if(iv_len > 8) /* XSalsa20 */
	{
		for(unsigned int i = 0; i < s->r; i++)
		{
			QR(s->x[ 0], s->x[ 4], s->x[ 8], s->x[12]);
			QR(s->x[ 5], s->x[ 9], s->x[13], s->x[ 1]);
			QR(s->x[10], s->x[14], s->x[ 2], s->x[ 6]);
			QR(s->x[15], s->x[ 3], s->x[ 7], s->x[11]);

			if(++i == s->r) break;

			QR(s->x[ 0], s->x[ 1], s->x[ 2], s->x[ 3]);
			QR(s->x[ 5], s->x[ 6], s->x[ 7], s->x[ 4]);
			QR(s->x[10], s->x[11], s->x[ 8], s->x[ 9]);
			QR(s->x[15], s->x[12], s->x[13], s->x[14]);
		}

		s->x[ 1] = s->x[ 0]; s->x[ 0] = constant[0];
		s->x[ 2] = s->x[ 5]; s->x[ 5] = constant[1];
		s->x[ 3] = s->x[10]; s->x[10] = constant[2];
		s->x[ 4] = s->x[15]; s->x[15] = constant[3];

		s->x[11] = s->x[6]; s->x[6] = 0;
		s->x[12] = s->x[7]; s->x[7] = 0;

		/* IV */
		if(iv_len > 16)
		{
			LOAD32L_ARRAY(CU8(iv) + 16, s->x + 6, iv_len - 16);
		}

		s->x[13] = s->x[8]; s->x[8] = 0;
		s->x[14] = s->x[9]; s->x[9] = 0;
	}

	s->used = 64;

	return s;
}

static kripto_stream *salsa20_create
(
	const kripto_stream_desc *desc,
	unsigned int r,
	const void *key,
	unsigned int key_len,
	const void *iv,
	unsigned int iv_len
)
{
	kripto_stream *s = (kripto_stream *)malloc(sizeof(kripto_stream));
	if(!s) return 0;

	(void)desc;

	s->obj.desc = kripto_stream_salsa20;
	s->obj.multof = 1;

	(void)salsa20_recreate(s, r, key, key_len, iv, iv_len);

	return s;
}

static void salsa20_destroy(kripto_stream *s)
{
	kripto_memory_wipe(s, sizeof(kripto_stream));
	free(s);
}

static const struct kripto_stream_desc salsa20 =
{
	&salsa20_create,
	&salsa20_recreate,
	&salsa20_crypt,
	&salsa20_crypt,
	&salsa20_prng,
	&salsa20_destroy,
	32, /* max key */
	24 /* max iv */
};

const kripto_stream_desc *const kripto_stream_salsa20 = &salsa20;
