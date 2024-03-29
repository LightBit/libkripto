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
#include <string.h>

#include <kripto/cast.h>
#include <kripto/loadstore.h>
#include <kripto/rotate.h>
#include <kripto/memory.h>
#include <kripto/hash.h>
#include <kripto/desc/hash.h>

#include <kripto/hash/keccak800.h>

struct kripto_hash
{
	const kripto_desc_hash *desc;
	unsigned int r;
	unsigned int rate;
	unsigned int i;
	int o;
	uint8_t s[100];
};

static const uint32_t rc[40] = 
{
	0x00000001, 0x00008082, 0x8000808A, 0x00008000,
	0x0000808B, 0x80000001, 0x00008081, 0x80008009,
	0x0000008A, 0x00000088, 0x80008009, 0x8000000A,
	0x8000808B, 0x8000008B, 0x80008089, 0x80008003,
	0x80008002, 0x80000080, 0x0000800A, 0x0000000A,
	0x00008081, 0x80008080, 0x80000001, 0x00008008,
	0x00008082, 0x0000800A, 0x80000003, 0x00000009,
	0x80008082, 0x00008009, 0x80000080, 0x00008083,
	0x80000081, 0x00000001, 0x0000800B, 0x00008001,
	0x00000080, 0x80008000, 0x00008001, 0x00000009
};

static void keccak800_F(kripto_hash *s)
{
	uint32_t a0 = LOAD32L(s->s);
	uint32_t a1 = LOAD32L(s->s + 4);
	uint32_t a2 = LOAD32L(s->s + 8);
	uint32_t a3 = LOAD32L(s->s + 12);
	uint32_t a4 = LOAD32L(s->s + 16);
	uint32_t a5 = LOAD32L(s->s + 20);
	uint32_t a6 = LOAD32L(s->s + 24);
	uint32_t a7 = LOAD32L(s->s + 28);
	uint32_t a8 = LOAD32L(s->s + 32);
	uint32_t a9 = LOAD32L(s->s + 36);
	uint32_t a10 = LOAD32L(s->s + 40);
	uint32_t a11 = LOAD32L(s->s + 44);
	uint32_t a12 = LOAD32L(s->s + 48);
	uint32_t a13 = LOAD32L(s->s + 52);
	uint32_t a14 = LOAD32L(s->s + 56);
	uint32_t a15 = LOAD32L(s->s + 60);
	uint32_t a16 = LOAD32L(s->s + 64);
	uint32_t a17 = LOAD32L(s->s + 68);
	uint32_t a18 = LOAD32L(s->s + 72);
	uint32_t a19 = LOAD32L(s->s + 76);
	uint32_t a20 = LOAD32L(s->s + 80);
	uint32_t a21 = LOAD32L(s->s + 84);
	uint32_t a22 = LOAD32L(s->s + 88);
	uint32_t a23 = LOAD32L(s->s + 92);
	uint32_t a24 = LOAD32L(s->s + 96);

	uint32_t b0;
	uint32_t b1;
	uint32_t b2;
	uint32_t b3;
	uint32_t b4;
	uint32_t b5;
	uint32_t b6;
	uint32_t b7;
	uint32_t b8;
	uint32_t b9;
	uint32_t b10;
	uint32_t b11;
	uint32_t b12;
	uint32_t b13;
	uint32_t b14;
	uint32_t b15;
	uint32_t b16;
	uint32_t b17;
	uint32_t b18;
	uint32_t b19;
	uint32_t b20;
	uint32_t b21;
	uint32_t b22;
	uint32_t b23;
	uint32_t b24;

	uint32_t c0;
	uint32_t c1;
	uint32_t c2;
	uint32_t c3;
	uint32_t c4;

	uint32_t d0;
	uint32_t d1;
	uint32_t d2;
	uint32_t d3;
	uint32_t d4;

	unsigned int i;

	for(i = 0; i < s->r; i++)
	{
		c0 = a0 ^ a5 ^ a10 ^ a15 ^ a20;
		c1 = a1 ^ a6 ^ a11 ^ a16 ^ a21;
		c2 = a2 ^ a7 ^ a12 ^ a17 ^ a22;
		c3 = a3 ^ a8 ^ a13 ^ a18 ^ a23;
		c4 = a4 ^ a9 ^ a14 ^ a19 ^ a24;

		d0 = ROL32_01(c1) ^ c4;
		d1 = ROL32_01(c2) ^ c0;
		d2 = ROL32_01(c3) ^ c1;
		d3 = ROL32_01(c4) ^ c2;
		d4 = ROL32_01(c0) ^ c3;

		a0 ^= d0;
		c0 = a0;
		a6 ^= d1;
		c1 = ROL32_12(a6);
		a12 ^= d2;
		c2 = ROL32_11(a12);
		a18 ^= d3;
		c3 = ROL32_21(a18);
		a24 ^= d4;
		c4 = ROL32_14(a24);

		b0 = c0 ^ ((~c1) & c2) ^ rc[i];
		b1 = c1 ^ ((~c2) & c3);
		b2 = c2 ^ ((~c3) & c4);
		b3 = c3 ^ ((~c4) & c0);
		b4 = c4 ^ ((~c0) & c1);

		a3 ^= d3;
		c0 = ROL32_28(a3);
		a9 ^= d4;
		c1 = ROL32_20(a9);
		a10 ^= d0;
		c2 = ROL32_03(a10);
		a16 ^= d1;
		c3 = ROL32_13(a16);
		a22 ^= d2;
		c4 = ROL32_29(a22);

		b5 = c0 ^ ((~c1) & c2);
		b6 = c1 ^ ((~c2) & c3);
		b7 = c2 ^ ((~c3) & c4);
		b8 = c3 ^ ((~c4) & c0);
		b9 = c4 ^ ((~c0) & c1);

		a1 ^= d1;
		c0 = ROL32_01(a1);
		a7 ^= d2;
		c1 = ROL32_06(a7);
		a13 ^= d3;
		c2 = ROL32_25(a13);
		a19 ^= d4;
		c3 = ROL32_08(a19);
		a20 ^= d0;
		c4 = ROL32_18(a20);

		b10 = c0 ^ ((~c1) & c2);
		b11 = c1 ^ ((~c2) & c3);
		b12 = c2 ^ ((~c3) & c4);
		b13 = c3 ^ ((~c4) & c0);
		b14 = c4 ^ ((~c0) & c1);

		a4 ^= d4;
		c0 = ROL32_27(a4);
		a5 ^= d0;
		c1 = ROL32_04(a5);
		a11 ^= d1;
		c2 = ROL32_10(a11);
		a17 ^= d2;
		c3 = ROL32_15(a17);
		a23 ^= d3;
		c4 = ROL32_24(a23);

		b15 = c0 ^ ((~c1) & c2);
		b16 = c1 ^ ((~c2) & c3);
		b17 = c2 ^ ((~c3) & c4);
		b18 = c3 ^ ((~c4) & c0);
		b19 = c4 ^ ((~c0) & c1);

		a2 ^= d2;
		c0 = ROL32_30(a2);
		a8 ^= d3;
		c1 = ROL32_23(a8);
		a14 ^= d4;
		c2 = ROL32_07(a14);
		a15 ^= d0;
		c3 = ROL32_09(a15);
		a21 ^= d1;
		c4 = ROL32_02(a21);

		b20 = c0 ^ ((~c1) & c2);
		b21 = c1 ^ ((~c2) & c3);
		b22 = c2 ^ ((~c3) & c4);
		b23 = c3 ^ ((~c4) & c0);
		b24 = c4 ^ ((~c0) & c1);

		a0 = b0;
		a1 = b1;
		a2 = b2;
		a3 = b3;
		a4 = b4;
		a5 = b5;
		a6 = b6;
		a7 = b7;
		a8 = b8;
		a9 = b9;
		a10 = b10;
		a11 = b11;
		a12 = b12;
		a13 = b13;
		a14 = b14;
		a15 = b15;
		a16 = b16;
		a17 = b17;
		a18 = b18;
		a19 = b19;
		a20 = b20;
		a21 = b21;
		a22 = b22;
		a23 = b23;
		a24 = b24;
	}

	STORE32L(a0, s->s);
	STORE32L(a1, s->s + 4);
	STORE32L(a2, s->s + 8);
	STORE32L(a3, s->s + 12);
	STORE32L(a4, s->s + 16);
	STORE32L(a5, s->s + 20);
	STORE32L(a6, s->s + 24);
	STORE32L(a7, s->s + 28);
	STORE32L(a8, s->s + 32);
	STORE32L(a9, s->s + 36);
	STORE32L(a10, s->s + 40);
	STORE32L(a11, s->s + 44);
	STORE32L(a12, s->s + 48);
	STORE32L(a13, s->s + 52);
	STORE32L(a14, s->s + 56);
	STORE32L(a15, s->s + 60);
	STORE32L(a16, s->s + 64);
	STORE32L(a17, s->s + 68);
	STORE32L(a18, s->s + 72);
	STORE32L(a19, s->s + 76);
	STORE32L(a20, s->s + 80);
	STORE32L(a21, s->s + 84);
	STORE32L(a22, s->s + 88);
	STORE32L(a23, s->s + 92);
	STORE32L(a24, s->s + 96);
}

static kripto_hash *keccak800_recreate
(
	kripto_hash *s,
	unsigned int r,
	const void *salt,
	unsigned int salt_len,
	unsigned int out_len
)
{
	(void)salt;
	(void)salt_len;

	s->o = s->i = 0;

	s->r = r;
	if(!s->r) s->r = 20;

	s->rate = 100 - (out_len << 1);

	memset(s->s, 0, 100);

	return s;
}

static void keccak800_input
(
	kripto_hash *s,
	const void *in,
	size_t len
) 
{
	/* switch back to input mode */
	if(s->o) s->o = s->i = 0;

	/* input */
	for(size_t i = 0; i < len; i++)
	{
		s->s[s->i++] ^= CU8(in)[i];

		if(s->i == s->rate)
		{
			keccak800_F(s);
			s->i = 0;
		}
	}
}

static void keccak800_output(kripto_hash *s, void *out, size_t len)
{
	/* switch to output mode */
	if(!s->o)
	{
		/* pad */
		s->s[s->i] ^= 0x01;
		s->s[s->rate - 1] ^= 0x80;

		keccak800_F(s);

		s->i = 0;
		s->o = -1;
	}

	/* output */
	for(size_t i = 0; i < len; i++)
	{
		if(s->i == s->rate)
		{
			keccak800_F(s);
			s->i = 0;
		}

		U8(out)[i] = s->s[s->i++];
	}
}

static kripto_hash *keccak800_create
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

	return keccak800_recreate(s, r, salt, salt_len, out_len);
}

static void keccak800_destroy(kripto_hash *s) 
{
	kripto_memory_wipe(s, sizeof(kripto_hash));
	free(s);
}

static int keccak800_hash
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

	(void)keccak800_recreate(&s, r, salt, salt_len, out_len);
	keccak800_input(&s, in, in_len);
	keccak800_output(&s, out, out_len);

	kripto_memory_wipe(&s, sizeof(kripto_hash));

	return 0;
}

static const kripto_desc_hash keccak800 =
{
	&keccak800_create,
	&keccak800_recreate,
	&keccak800_input,
	&keccak800_output,
	&keccak800_destroy,
	&keccak800_hash,
	0, /* max output */
	100, /* block_size */
	0 /* max salt */
};

const kripto_desc_hash *const kripto_hash_keccak800 = &keccak800;
