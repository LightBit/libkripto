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
#include <string.h>
#include <assert.h>

#include <kripto/memory.h>
#include <kripto/cast.h>
#include <kripto/loadstore.h>
#include <kripto/rotate.h>
#include <kripto/mac.h>
#include <kripto/pbkdf2.h>

#include <kripto/scrypt.h>

#define QR(A, B, C, D)		\
{				\
	B ^= ROL32_07(A + D);	\
	C ^= ROL32_09(B + A);	\
	D ^= ROL32_13(C + B);	\
	A ^= ROL32_18(D + C);	\
}

static void salsa20_core(uint32_t *x)
{
	uint32_t x0 = x[0];
	uint32_t x1 = x[1];
	uint32_t x2 = x[2];
	uint32_t x3 = x[3];
	uint32_t x4 = x[4];
	uint32_t x5 = x[5];
	uint32_t x6 = x[6];
	uint32_t x7 = x[7];
	uint32_t x8 = x[8];
	uint32_t x9 = x[9];
	uint32_t x10 = x[10];
	uint32_t x11 = x[11];
	uint32_t x12 = x[12];
	uint32_t x13 = x[13];
	uint32_t x14 = x[14];
	uint32_t x15 = x[15];

	/* columnround 1 */
	QR(x0, x4, x8, x12);
	QR(x5, x9, x13, x1);
	QR(x10, x14, x2, x6);
	QR(x15, x3, x7, x11);

	/* rowround 2 */
	QR(x0, x1, x2, x3);
	QR(x5, x6, x7, x4);
	QR(x10, x11, x8, x9);
	QR(x15, x12, x13, x14);

	/* columnround 3 */
	QR(x0, x4, x8, x12);
	QR(x5, x9, x13, x1);
	QR(x10, x14, x2, x6);
	QR(x15, x3, x7, x11);

	/* rowround 4 */
	QR(x0, x1, x2, x3);
	QR(x5, x6, x7, x4);
	QR(x10, x11, x8, x9);
	QR(x15, x12, x13, x14);

	/* columnround 5 */
	QR(x0, x4, x8, x12);
	QR(x5, x9, x13, x1);
	QR(x10, x14, x2, x6);
	QR(x15, x3, x7, x11);

	/* rowround 6 */
	QR(x0, x1, x2, x3);
	QR(x5, x6, x7, x4);
	QR(x10, x11, x8, x9);
	QR(x15, x12, x13, x14);

	/* columnround 7 */
	QR(x0, x4, x8, x12);
	QR(x5, x9, x13, x1);
	QR(x10, x14, x2, x6);
	QR(x15, x3, x7, x11);

	/* rowround 8 */
	QR(x0, x1, x2, x3);
	QR(x5, x6, x7, x4);
	QR(x10, x11, x8, x9);
	QR(x15, x12, x13, x14);

	x[0] += x0;
	x[1] += x1;
	x[2] += x2;
	x[3] += x3;
	x[4] += x4;
	x[5] += x5;
	x[6] += x6;
	x[7] += x7;
	x[8] += x8;
	x[9] += x9;
	x[10] += x10;
	x[11] += x11;
	x[12] += x12;
	x[13] += x13;
	x[14] += x14;
	x[15] += x15;
}

static void blockmix(uint32_t *b, uint32_t *t, const size_t r)
{
	uint32_t x[16];
	size_t i;

	memcpy(x, b + (r << 5) - 16, 64);

	for(i = 0; i < (r << 5);)
	{
		x[0] ^= b[i++];
		x[1] ^= b[i++];
		x[2] ^= b[i++];
		x[3] ^= b[i++];
		x[4] ^= b[i++];
		x[5] ^= b[i++];
		x[6] ^= b[i++];
		x[7] ^= b[i++];
		x[8] ^= b[i++];
		x[9] ^= b[i++];
		x[10] ^= b[i++];
		x[11] ^= b[i++];
		x[12] ^= b[i++];
		x[13] ^= b[i++];
		x[14] ^= b[i++];
		x[15] ^= b[i++];

		salsa20_core(x);
		memcpy(t + i - 16, x, 64);
	}

	for(i = 0; i < r; i++)
	{
		memcpy(b + (i << 4), t + (i << 5), 64);
		memcpy(b + ((i + r) << 4), t + (i << 5) + 16, 64);
	}	
}

static void smix
(
	uint8_t *b,
	const size_t r,
	uint64_t n,
	uint32_t *t0,
	uint32_t *t1,
	uint32_t *t2
)
{
	uint64_t i;
	uint64_t tn;
	uint64_t j;

	for(i = 0; i < (r << 5); i++)
		t1[i] = LOAD32L(b + (i << 2));

	for(i = 0; i < n; i++)
	{
		memcpy(t0 + (r << 5) * i, t1, r << 7);
		blockmix(t1, t2, r);
	}

	for(i = 0; i < n; i++)
	{
		/* integrify */
		tn = (((uint64_t)t1[(r << 5) - 15] << 32)
			| t1[(r << 5) - 16])
			& (n - 1);

		for(j = 0; j < (r << 5); j++)
			t1[j] ^= t0[(r << 5) * tn + j];

		blockmix(t1, t2, r);
	}

	for(i = 0; i < (r << 5); i++)
		STORE32L(t1[i], b + (i << 2));
}

int kripto_scrypt
(
	const kripto_mac_desc *mac,
	unsigned int mac_rounds,
	uint64_t n,
	uint32_t r,
	uint32_t p,
	const void *pass,
	unsigned int pass_len,
	const void *salt,
	unsigned int salt_len,
	void *out,
	size_t out_len
)
{
	uint8_t *b;
	uint32_t *t0;
	uint32_t *t1;
	uint32_t *t2;
	uint32_t i;

	b = (uint8_t *)malloc((r << 7) * p + (r << 7) * n + (r << 8));
	if(!b) return -1;

	t0 = (uint32_t *)(void *)(b + (r << 7) * p);
	t1 = t0 + (r << 5);
	t2 = t1 + (r << 5);

	if(kripto_pbkdf2
	(
		mac,
		mac_rounds,
		1,
		pass,
		pass_len,
		salt,
		salt_len,
		b,
		p * (r << 7)
	)) goto err;

	for(i = 0; i < p; i++)
		smix(b + (r << 7) * i, r, n, t0, t1, t2);

	if(kripto_pbkdf2
	(
		mac,
		mac_rounds,
		1,
		pass,
		pass_len,
		b,
		p * (r << 7),
		out,
		out_len
	)) goto err;

	kripto_memory_wipe(b, (r << 7) * p + (r << 7) * n + (r << 8));
	free(b);

	return 0;

err:
	kripto_memory_wipe(b, (r << 7) * p + (r << 7) * n + (r << 8));
	free(b);

	return -1;
}
