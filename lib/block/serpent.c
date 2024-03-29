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

/* The S-box functions by Dag Arne Osvik */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include <kripto/cast.h>
#include <kripto/loadstore.h>
#include <kripto/rotate.h>
#include <kripto/memory.h>
#include <kripto/block.h>
#include <kripto/desc/block.h>

#include <kripto/block/serpent.h>

struct kripto_block
{
	const kripto_desc_block *desc;
	unsigned int rounds;
	uint32_t *k;
};

/* ENCRYPT S-boxes */

/* 38F1A65BED42709C */
#define S0(A, B, C, D, T)	\
{				\
	T  = D;			\
	D |= A;			\
	A ^= T;			\
	T ^= C;			\
	T =~ T;			\
	D ^= B;			\
	B &= A;			\
	B ^= T;			\
	C ^= A;			\
	A ^= D;			\
	T |= A;			\
	A ^= C;			\
	C &= B;			\
	D ^= C;			\
	B =~ B;			\
	C ^= T;			\
	B ^= C;			\
}

/* FC27905A1BE86D34 */
#define S1(A, B, C, D, T)	\
{				\
	T  = B;			\
	B ^= A;			\
	A ^= D;			\
	D =~ D;			\
	T &= B;			\
	A |= B;			\
	D ^= C;			\
	A ^= D;			\
	B ^= D;			\
	D ^= T;			\
	B |= T;			\
	T ^= C;			\
	C &= A;			\
	C ^= B;			\
	B |= A;			\
	A =~ A;			\
	A ^= C;			\
	T ^= B;			\
}

/* 86793CAFD1E40B52 */
#define S2(A, B, C, D, T)	\
{				\
	D =~ D;			\
	B ^= A;			\
	T  = A;			\
	A &= C;			\
	A ^= D;			\
	D |= T;			\
	C ^= B;			\
	D ^= B;			\
	B &= A;			\
	A ^= C;			\
	C &= D;			\
	D |= B;			\
	A =~ A;			\
	D ^= A;			\
	T ^= A;			\
	A ^= C;			\
	B |= C;			\
}

/* 0FB8C963D124A75E */
#define S3(A, B, C, D, T)	\
{				\
	T  = B;			\
	B ^= D;			\
	D |= A;			\
	T &= A;			\
	A ^= C;			\
	C ^= B;			\
	B &= D;			\
	C ^= D;			\
	A |= T;			\
	T ^= D;			\
	B ^= A;			\
	A &= D;			\
	D &= T;			\
	D ^= C;			\
	T |= B;			\
	C &= B;			\
	T ^= D;			\
	A ^= D;			\
	D ^= C;			\
}

/* 1F83C0B6254A9E7D */
#define S4(A, B, C, D, T)	\
{				\
	T  = D;			\
	D &= A;			\
	A ^= T;			\
	D ^= C;			\
	C |= T;			\
	A ^= B;			\
	T ^= D;			\
	C |= A;			\
	C ^= B;			\
	B &= A;			\
	B ^= T;			\
	T &= C;			\
	C ^= D;			\
	T ^= A;			\
	D |= B;			\
	B =~ B;			\
	D ^= A;			\
}

/* F52B4A9C03E8D671 */
#define S5(A, B, C, D, T)	\
{				\
	T  = B;			\
	B |= A;			\
	C ^= B;			\
	D =~ D;			\
	T ^= A;			\
	A ^= C;			\
	B &= T;			\
	T |= D;			\
	T ^= A;			\
	A &= D;			\
	B ^= D;			\
	D ^= C;			\
	A ^= B;			\
	C &= T;			\
	B ^= C;			\
	C &= A;			\
	D ^= C;			\
}

/* 72C5846BE91FD3A0 */
#define S6(A, B, C, D, T)	\
{				\
	T  = B;			\
	D ^= A;			\
	B ^= C;			\
	C ^= A;			\
	A &= D;			\
	B |= D;			\
	T =~ T;			\
	A ^= B;			\
	B ^= C;			\
	D ^= T;			\
	T ^= A;			\
	C &= A;			\
	T ^= B;			\
	C ^= D;			\
	D &= B;			\
	D ^= A;			\
	B ^= C;			\
}

/* 1DF0E82B74CA9356 */
#define S7(A, B, C, D, T)	\
{				\
	B =~ B;			\
	T  = B;			\
	A =~ A;			\
	B &= C;			\
	B ^= D;			\
	D |= T;			\
	T ^= C;			\
	C ^= D;			\
	D ^= A;			\
	A |= B;			\
	C &= A;			\
	A ^= T;			\
	T ^= D;			\
	D &= A;			\
	T ^= B;			\
	C ^= T;			\
	D ^= B;			\
	T |= A;			\
	T ^= B;			\
}


/* DECRYPT S-boxes */

/* D3B0A65C1E47F982 */
#define IS0(A, B, C, D, T)	\
{				\
	T  = D;			\
	B ^= A;			\
	D |= B;			\
	T ^= B;			\
	A =~ A;			\
	C ^= D;			\
	D ^= A;			\
	A &= B;			\
	A ^= C;			\
	C &= D;			\
	D ^= T;			\
	C ^= D;			\
	B ^= D;			\
	D &= A;			\
	B ^= A;			\
	A ^= C;			\
	T ^= D;			\
}

/* 582EF6C3B4791DA0 */
#define IS1(A, B, C, D, T)	\
{				\
	B ^= D;			\
	T  = A;			\
	A ^= C;			\
	C =~ C;			\
	T |= B;			\
	T ^= D;			\
	D &= B;			\
	B ^= C;			\
	C &= T;			\
	T ^= B;			\
	B |= D;			\
	D ^= A;			\
	C ^= A;			\
	A |= T;			\
	C ^= T;			\
	B ^= A;			\
	T ^= B;			\
}

/* C9F4BE12036D58A7 */
#define IS2(A, B, C, D, T)	\
{				\
	C ^= B;			\
	T  = D;			\
	D =~ D;			\
	D |= C;			\
	C ^= T;			\
	T ^= A;			\
	D ^= B;			\
	B |= C;			\
	C ^= A;			\
	B ^= T;			\
	T |= D;			\
	C ^= D;			\
	T ^= C;			\
	C &= B;			\
	C ^= D;			\
	D ^= T;			\
	T ^= A;			\
}

/* 09A7BE6D35C248F1 */
#define IS3(A, B, C, D, T)	\
{				\
	C ^= B;			\
	T  = B;			\
	B &= C;			\
	B ^= A;			\
	A |= T;			\
	T ^= D;			\
	A ^= D;			\
	D |= B;			\
	B ^= C;			\
	B ^= D;			\
	A ^= C;			\
	C ^= D;			\
	D &= B;			\
	B ^= A;			\
	A &= C;			\
	T ^= D;			\
	D ^= A;			\
	A ^= B;			\
}

/* 5083A97E2CB64FD1 */
#define IS4(A, B, C, D, T)	\
{				\
	C ^= D;			\
	T  = A;			\
	A &= B;			\
	A ^= C;			\
	C |= D;			\
	T =~ T;			\
	B ^= A;			\
	A ^= C;			\
	C &= T;			\
	C ^= A;			\
	A |= T;			\
	A ^= D;			\
	D &= C;			\
	T ^= D;			\
	D ^= B;			\
	B &= A;			\
	T ^= B;			\
	A ^= D;			\
}

/* 8F2941DEB6537CA0 */
#define IS5(A, B, C, D, T)	\
{				\
	T  = B;			\
	B |= C;			\
	C ^= T;			\
	B ^= D;			\
	D &= T;			\
	C ^= D;			\
	D |= A;			\
	A =~ A;			\
	D ^= C;			\
	C |= A;			\
	T ^= B;			\
	C ^= T;			\
	T &= A;			\
	A ^= B;			\
	B ^= D;			\
	A &= C;			\
	C ^= D;			\
	A ^= C;			\
	C ^= T;			\
	T ^= D;			\
}

/* FA1D536049E72C8B */
#define IS6(A, B, C, D, T)	\
{				\
	A ^= C;			\
	T  = A;			\
	A &= D;			\
	C ^= D;			\
	A ^= C;			\
	D ^= B;			\
	C |= T;			\
	C ^= D;			\
	D &= A;			\
	A =~ A;			\
	D ^= B;			\
	B &= C;			\
	T ^= A;			\
	D ^= T;			\
	T ^= C;			\
	A ^= B;			\
	C ^= A;			\
}

/* 306D9EF85CB7A142 */
#define IS7(A, B, C, D, T)	\
{				\
	T  = D;			\
	D &= A;			\
	A ^= C;			\
	C |= T;			\
	T ^= B;			\
	A =~ A;			\
	B |= D;			\
	T ^= A;			\
	A &= C;			\
	A ^= B;			\
	B &= C;			\
	D ^= C;			\
	T ^= D;			\
	C &= D;			\
	D |= A;			\
	B ^= T;			\
	D ^= T;			\
	T &= A;			\
	T ^= C;			\
}

#define LT(A, B, C, D)		\
{				\
	A = ROL32_13(A);	\
	C = ROL32_03(C);	\
	D ^= C ^ (A << 3);	\
	B ^= A ^ C;		\
	D = ROL32_07(D);	\
	B = ROL32_01(B);	\
	A ^= B ^ D;		\
	C ^= D ^ (B << 7);	\
	A = ROL32_05(A);	\
	C = ROL32_22(C);	\
}

#define ILT(A, B, C, D)		\
{				\
	C = ROR32_22(C);	\
	A = ROR32_05(A);	\
	C ^= D ^ (B << 7);	\
	A ^= B ^ D;		\
	D = ROR32_07(D);	\
	B = ROR32_01(B);	\
	D ^= C ^ (A << 3);	\
	B ^= A ^ C;		\
	C = ROR32_03(C);	\
	A = ROR32_13(A);	\
}

#define K(A, B, C, D, K)	\
{				\
	(A) ^= (K)[0];		\
	(B) ^= (K)[1];		\
	(C) ^= (K)[2];		\
	(D) ^= (K)[3];		\
}

#define LOAD_K(A, B, C, D, K)	\
{				\
	(A) = (K)[0];		\
	(B) = (K)[1];		\
	(C) = (K)[2];		\
	(D) = (K)[3];		\
}

#define STOR_K(A, B, C, D, K)	\
{				\
	(K)[0] = (A);		\
	(K)[1] = (B);		\
	(K)[2] = (C);		\
	(K)[3] = (D);		\
}

static void serpent_encrypt
(
	const kripto_block *s,
	const void *pt,
	void *ct
)
{
	uint32_t a = LOAD32L(CU8(pt));
	uint32_t b = LOAD32L(CU8(pt) + 4);
	uint32_t c = LOAD32L(CU8(pt) + 8);
	uint32_t d = LOAD32L(CU8(pt) + 12);
	uint32_t t;
	unsigned int i;

	for(i = 0;;)
	{
		K(a, b, c, d, s->k + i); i += 4;
		S0(a, b, c, d, t);
		LT(c, b, d, a);

		K(c, b, d, a, s->k + i); i += 4;
		S1(c, b, d, a, t);
		LT(t, d, a, c);

		K(t, d, a, c, s->k + i); i += 4;
		S2(t, d, a, c, b);
		LT(b, d, t, c);

		K(b, d, t, c, s->k + i); i += 4;
		S3(b, d, t, c, a);
		LT(c, a, d, b);

		K(c, a, d, b, s->k + i); i += 4;
		S4(c, a, d, b, t);
		LT(a, d, b, t);

		K(a, d, b, t, s->k + i); i += 4;
		S5(a, d, b, t, c);
		LT(c, a, d, t);

		K(c, a, d, t, s->k + i); i += 4;
		S6(c, a, d, t, b);
		LT(d, b, a, t);

		K(d, b, a, t, s->k + i); i += 4;
		S7(d, b, a, t, c);

		b = a; a = c; c = t;

		if(i >= s->rounds << 2) break;

		LT(a, b, c, d);
	}

	K(a, b, c, d, s->k + i);

	STORE32L(a, U8(ct));
	STORE32L(b, U8(ct) + 4);
	STORE32L(c, U8(ct) + 8);
	STORE32L(d, U8(ct) + 12);
}

static void serpent_decrypt
(
	const kripto_block *s,
	const void *ct,
	void *pt
)
{
	uint32_t a = LOAD32L(CU8(ct));
	uint32_t b = LOAD32L(CU8(ct) + 4);
	uint32_t c = LOAD32L(CU8(ct) + 8);
	uint32_t d = LOAD32L(CU8(ct) + 12);
	uint32_t t;
	unsigned int i = s->rounds << 2;

	K(a, b, c, d, s->k + i);

	for(;;)
	{
		IS7(a, b, c, d, t);
		i -= 4; K(b, d, a, t, s->k + i);

		ILT(b, d, a, t);
		IS6(b, d, a, t, c);
		i -= 4; K(a, c, t, b, s->k + i);

		ILT(a, c, t, b);
		IS5(a, c, t, b, d);
		i -= 4; K(c, d, a, t, s->k + i);

		ILT(c, d, a, t);
		IS4(c, d, a, t, b);
		i -= 4; K(c, a, b, t, s->k + i);

		ILT(c, a, b, t);
		IS3(c, a, b, t, d);
		i -= 4; K(b, c, d, t, s->k + i);

		ILT(b, c, d, t);
		IS2(b, c, d, t, a);
		i -= 4; K(c, a, t, d, s->k + i);

		ILT(c, a, t, d);
		IS1(c, a, t, d, b);
		i -= 4; K(b, a, t, d, s->k + i);

		ILT(b, a, t, d);
		IS0(b, a, t, d, c);
		i -= 4; K(t, c, a, b, s->k + i);

		d = b; b = c; c = a; a = t;

		if(i < 32) break; /* if(!i) break; */

		ILT(a, b, c, d);
	}

	STORE32L(a, U8(pt));
	STORE32L(b, U8(pt) + 4);
	STORE32L(c, U8(pt) + 8);
	STORE32L(d, U8(pt) + 12);
}

static void serpent_setup
(
	kripto_block *s,
	const void *key,
	unsigned int key_len
)
{
	uint32_t a;
	uint32_t b;
	uint32_t c;
	uint32_t d;
	uint32_t t;
	unsigned int i;

	for(i = 0; i < 32; i++) s->k[i] = 0;
	LOAD32L_ARRAY(key, s->k, key_len);

	if(key_len < 32)
		s->k[(key_len) >> 2] |= 1 << ((key_len & 3) << 3);

	for(i = 8; i < 16; i++)
	{
		s->k[i] = s->k[i - 8]
			^ s->k[i - 5]
			^ s->k[i - 3]
			^ s->k[i - 1]
			^ 0x9E3779B9
			^ (i - 8);

		s->k[i - 8] = s->k[i] = ROL32_11(s->k[i]);
	}

	for(i = 8; i < (s->rounds + 1) << 2; i++)
	{
		s->k[i] = s->k[i - 8]
			^ s->k[i - 5]
			^ s->k[i - 3]
			^ s->k[i - 1]
			^ 0x9E3779B9
			^ i;

		s->k[i] = ROL32_11(s->k[i]);
	}

	for(i = 0; i < s->rounds << 2;)
	{
		LOAD_K(a, b, c, d, s->k + i);
		S3(a, b, c, d, t);
		STOR_K(d, t, b, a, s->k + i); i += 4;
		
		LOAD_K(a, b, c, d, s->k + i);
		S2(a, b, c, d, t);
		STOR_K(t, b, a, d, s->k + i); i += 4;

		LOAD_K(a, b, c, d, s->k + i);
		S1(a, b, c, d, t);
		STOR_K(t, c, d, a, s->k + i); i += 4;

		LOAD_K(a, b, c, d, s->k + i);
		S0(a, b, c, d, t);
		STOR_K(c, b, d, a, s->k + i); i += 4;

		LOAD_K(a, b, c, d, s->k + i);
		S7(a, b, c, d, t);
		STOR_K(t, c, d, a, s->k + i); i += 4;

		LOAD_K(a, b, c, d, s->k + i);
		S6(a, b, c, d, t);
		STOR_K(c, t, b, d, s->k + i); i += 4;
		
		LOAD_K(a, b, c, d, s->k + i);
		S5(a, b, c, d, t);
		STOR_K(t, a, b, d, s->k + i); i += 4;

		LOAD_K(a, b, c, d, s->k + i);
		S4(a, b, c, d, t);
		STOR_K(b, c, d, t, s->k + i); i += 4;
	}

	LOAD_K(a, b, c, d, s->k + i);
	S3(a, b, c, d, t);
	STOR_K(d, t, b, a, s->k + i);
}

static kripto_block *serpent_create
(
	const kripto_desc_block *desc,
	unsigned int r,
	const void *key,
	unsigned int key_len
)
{
	kripto_block *s;

	if(!r) r = 32;

	s = (kripto_block *)malloc(sizeof(kripto_block) + ((r + 1) << 4));
	if(!s) return 0;

	s->desc = desc;
	s->rounds = r;
	s->k = (uint32_t *)(s + 1);

	serpent_setup(s, key, key_len);

	return s;
}

static void serpent_destroy(kripto_block *s)
{
	kripto_memory_wipe(s, sizeof(kripto_block) + ((s->rounds + 1) << 4));
	free(s);
}

static kripto_block *serpent_recreate
(
	kripto_block *s,
	unsigned int r,
	const void *key,
	unsigned int key_len
)
{
	if(!r) r = 32;

	if(r != s->rounds)
	{
		serpent_destroy(s);
		s = serpent_create(s->desc, r, key, key_len);
	}
	else
	{
		serpent_setup(s, key, key_len);
	}

	return s;
}

static const kripto_desc_block serpent =
{
	&serpent_create,
	&serpent_recreate,
	0, /* tweak */
	&serpent_encrypt,
	&serpent_decrypt,
	&serpent_destroy,
	16, /* block size */
	32, /* max key */
	0 /* max tweak */
};

const kripto_desc_block *const kripto_block_serpent = &serpent;
