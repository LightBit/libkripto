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
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <assert.h>

#include <kripto/cast.h>
#include <kripto/loadstore.h>
#include <kripto/memory.h>
#include <kripto/block.h>
#include <kripto/block/threefish256.h>
#include <kripto/stream.h>
#include <kripto/desc/stream.h>
#include <kripto/object/stream.h>

#include <kripto/stream/skein256.h>

struct kripto_stream
{
	struct kripto_stream_object obj;
	kripto_block *block;
	unsigned int r;
	unsigned int i;
	uint8_t ctr[32];
	uint8_t buf[32];
};

#define POS_ADD(TWEAK, ADD)		\
{					\
	TWEAK[0] += ADD;		\
	if(TWEAK[0] < ADD)			\
	if(!++TWEAK[1])			\
	if(!++TWEAK[2])			\
	if(!++TWEAK[3])			\
	if(!++TWEAK[4])			\
	if(!++TWEAK[5])			\
	if(!++TWEAK[6])			\
	if(!++TWEAK[7])			\
	if(!++TWEAK[8])			\
	if(!++TWEAK[9])			\
	if(!++TWEAK[10])		\
	{				\
		TWEAK[11]++;		\
		assert(TWEAK[11]);	\
	}				\
}

static kripto_stream *skein256_recreate
(
	kripto_stream *s,
	unsigned int r,
	const void *key,
	unsigned int key_len,
	const void *iv,
	unsigned int iv_len
)
{
	uint8_t tweak[16];
	uint8_t k[32];
	unsigned int block;
	unsigned int i;

	s->r = r;
	s->i = 0;
	memset(k, 0, 32);
	memset(s->ctr, 0, 32);

	/* KEY */
	memset(tweak, 0, 16);
	tweak[15] = 0x40; /* type KEY, first */

	while(key_len)
	{
		if(key_len > 32) block = 32;
		else block = key_len;

		memcpy(s->buf, key, block);
		memset(s->buf, 0, 32 - block);

		POS_ADD(tweak, block);

		key_len -= block;

		if(!key_len) tweak[15] |= 0x80; /* add final */

		/* process */
		(void)kripto_block_recreate(s->block, s->r, k, 32);
		kripto_block_tweak(s->block, tweak, 16);
		kripto_block_encrypt(s->block, s->buf, k);
		for(i = 0; i < 32; i++) k[i] ^= s->buf[i];

		tweak[15] &= 0xBF; /* remove first */
	}

	/* CFG */
	s->buf[0] = 'S';
	s->buf[1] = 'H';
	s->buf[2] = 'A';
	s->buf[3] = '3';
	s->buf[4] = 1;
	s->buf[5] = 0;
	s->buf[6] = 0;
	s->buf[7] = 0;
	memset(s->buf + 8, 0xFF, 8); /* output UINT64_MAX */
	memset(s->buf + 16, 0, 16);
	memset(tweak, 0, 12);
	tweak[0] = 32;
	tweak[15] = 0xC4; /* type CFG, first, final */

	/* process */
	(void)kripto_block_recreate(s->block, s->r, k, 32);
	kripto_block_tweak(s->block, tweak, 16);
	kripto_block_encrypt(s->block, s->buf, k);
	for(i = 0; i < 32; i++) k[i] ^= s->buf[i];

	/* NONCE */
	memset(tweak, 0, 12);
	tweak[15] = 0x54; /* type NONCE, first */

	while(iv_len)
	{
		if(iv_len > 32) block = 32;
		else block = iv_len;

		memcpy(s->buf, iv, block);
		memset(s->buf, 0, 32 - block);

		POS_ADD(tweak, block);

		iv_len -= block;

		if(!iv_len) tweak[15] |= 0x80; /* add final */

		/* process */
		(void)kripto_block_recreate(s->block, s->r, k, 32);
		kripto_block_tweak(s->block, tweak, 16);
		kripto_block_encrypt(s->block, s->buf, k);
		for(i = 0; i < 32; i++) k[i] ^= s->buf[i];

		tweak[15] &= 0xBF; /* remove first */
	}

	/* final setup */
	(void)kripto_block_recreate(s->block, s->r, k, 32);
	memset(tweak, 0, 12);
	tweak[0] = 8; /* 8 byte counter */
	tweak[15] = 0xFF; /* type OUTPUT, first, final */
	kripto_block_tweak(s->block, tweak, 16);

	kripto_memory_wipe(k, 32);

	return s;
}

static void skein256_crypt
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
		if(s->i == 32)
		{
			kripto_block_encrypt(s->block, s->ctr, s->buf);
			for(s->i = 0; s->i < 32; s->i++)
				s->buf[s->i] ^= s->ctr[s->i];

			if(!++s->ctr[0])
			if(!++s->ctr[1])
			if(!++s->ctr[2])
			if(!++s->ctr[3])
			if(!++s->ctr[4])
			if(!++s->ctr[5])
			if(!++s->ctr[6])
			{
				s->ctr[7]++;
				assert(s->ctr[7]);
			}

			s->i = 0;
		}

		U8(out)[i] = CU8(in)[i] ^ s->buf[s->i++];
	}
}

static void skein256_prng(kripto_stream *s, void *out, size_t len)
{
	size_t i;

	for(i = 0; i < len; i++)
	{
		if(s->i == 32)
		{
			kripto_block_encrypt(s->block, s->ctr, s->buf);
			for(s->i = 0; s->i < 32; s->i++)
				s->buf[s->i] ^= s->ctr[s->i];

			if(!++s->ctr[0])
			if(!++s->ctr[1])
			if(!++s->ctr[2])
			if(!++s->ctr[3])
			if(!++s->ctr[4])
			if(!++s->ctr[5])
			if(!++s->ctr[6])
			{
				s->ctr[7]++;
				assert(s->ctr[7]);
			}

			s->i = 0;
		}

		U8(out)[i] = s->buf[s->i++];
	}
}

static kripto_stream *skein256_create
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

	s->obj.desc = kripto_stream_skein256;
	s->obj.multof = 1;

	s->block = kripto_block_create(kripto_block_threefish256, r, "", 1);
	if(!s->block)
	{
		free(s);
		return 0;
	}

	(void)skein256_recreate(s, r, key, key_len, iv, iv_len);

	return s;
}

static void skein256_destroy(kripto_stream *s)
{
	kripto_block_destroy(s->block);
	kripto_memory_wipe(s, sizeof(kripto_stream));
	free(s);
}

static const kripto_stream_desc skein256 =
{
	&skein256_create,
	&skein256_recreate,
	&skein256_crypt,
	&skein256_crypt,
	&skein256_prng,
	&skein256_destroy,
	UINT_MAX, /* max key */
	UINT_MAX /* max iv */
};

const kripto_stream_desc *const kripto_stream_skein256 = &skein256;
