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
#include <kripto/block/threefish1024.h>
#include <kripto/hash.h>
#include <kripto/desc/hash.h>

#include <kripto/hash/skein1024.h>

struct kripto_hash
{
	const kripto_desc_hash *desc;
	kripto_block *block;
	unsigned int r;
	unsigned int i;
	unsigned int out_len;
	int f;
	uint8_t h[128];
	uint8_t buf[128];
	uint8_t tweak[16];
};

#define POS_ADD(TWEAK, ADD)		\
{					\
	TWEAK[0] += ADD;		\
	if(TWEAK[0] < ADD)		\
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

static void skein1024_process(kripto_hash *s) 
{
	unsigned int i;

	(void)kripto_block_recreate(s->block, s->r, s->h, 128);
	kripto_block_tweak(s->block, s->tweak, 16);
	kripto_block_encrypt(s->block, s->buf, s->h);

	for(i = 0; i < 128; i++) s->h[i] ^= s->buf[i];
}

static kripto_hash *skein1024_recreate
(
	kripto_hash *s,
	unsigned int r,
	const void *salt,
	unsigned int salt_len,
	unsigned int out_len
)
{
	uint64_t t;

	s->r = r;
	s->i = 0;
	s->f = 0;
	memset(s->h, 0, 128);
	memset(s->tweak, 0, 16);

	s->out_len = out_len;
	t = out_len << 3;

	/* CFG */
	s->buf[0] = 'S';
	s->buf[1] = 'H';
	s->buf[2] = 'A';
	s->buf[3] = '3';
	s->buf[4] = 1;
	s->buf[5] = 0;
	s->buf[6] = 0;
	s->buf[7] = 0;
	STORE64L(t, s->buf + 8);
	memset(s->buf + 16, 0, 112);
	s->tweak[0] = 32;
	s->tweak[15] = 0xC4; /* type CFG, first, final */
	skein1024_process(s);

	/* NONCE */
	s->tweak[0] = 0;
	s->tweak[15] = 0x54; /* type NONCE, first */

	while(salt_len)
	{
		unsigned int len = salt_len > 128 ? 128 : salt_len;

		memcpy(s->buf, salt, len);
		memset(s->buf, 0, 128 - len);

		POS_ADD(s->tweak, len);
		salt_len -= len;

		if(!salt_len) s->tweak[15] |= 0x80; /* add final */

		skein1024_process(s);

		s->tweak[15] &= 0xBF; /* remove first */
	}

	/* MSG */
	memset(s->tweak, 0, 12);
	s->tweak[15] = 0x70; /* type MSG, first */

	return s;
}

static void skein1024_input
(
	kripto_hash *s,
	const void *in,
	size_t len
) 
{
	for(size_t i = 0; i < len; i++)
	{
		s->buf[s->i++] = CU8(in)[i];

		if(s->i == 128)
		{
			POS_ADD(s->tweak, 128);
			skein1024_process(s);
			s->tweak[15] = 0x30; /* type MSG */
			s->i = 0;
		}
	}
}

static void skein1024_output(kripto_hash *s, void *out, size_t len)
{
	if(!s->f)
	{
		POS_ADD(s->tweak, s->i);
		memset(s->buf + s->i, 0, 128 - s->i);
		s->tweak[15] |= 0x80; /* add final */
		skein1024_process(s);
		s->f = -1;
		s->i = 128;
		memset(s->buf, 0, 128);
		memset(s->tweak, 0, 12);
		s->tweak[0] = 8; /* 8 byte counter */
		s->tweak[15] = 0x7F; /* type OUT, first */
	}

	assert(s->out_len >= len);

	for(size_t i = 0; i < len; i++)
	{
		if(s->i == 128)
		{
			s->out_len -= 128;
			if(!s->out_len) s->tweak[15] |= 0x80; /* add final */
			skein1024_process(s);
			s->tweak[15] &= 0xBF; /* remove first */
			POS_ADD(s->tweak, 128);
			s->i = 0;
		}
		
		U8(out)[i] = s->h[s->i++];
	}
}

static kripto_hash *skein1024_create
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

	s->block = kripto_block_create(kripto_block_threefish1024, r, "", 1);
	if(!s->block)
	{
		free(s);
		return 0;
	}

	return skein1024_recreate(s, r, salt, salt_len, out_len);
}

static void skein1024_destroy(kripto_hash *s)
{
	kripto_block_destroy(s->block);
	kripto_memory_wipe(s, sizeof(kripto_hash));
	free(s);
}

static int skein1024_hash
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

	s.block = kripto_block_create(kripto_block_threefish1024, r, "", 1);
	if(!s.block) return -1;

	(void)skein1024_recreate(&s, r, salt, salt_len, out_len);
	skein1024_input(&s, in, in_len);
	skein1024_output(&s, out, out_len);

	kripto_block_destroy(s.block);
	kripto_memory_wipe(&s, sizeof(kripto_hash));

	return 0;
}

static const kripto_desc_hash skein1024 =
{
	&skein1024_create,
	&skein1024_recreate,
	&skein1024_input,
	&skein1024_output,
	&skein1024_destroy,
	&skein1024_hash,
	0, /* max output */
	128, /* block_size */
	UINT_MAX /* max salt */
};

const kripto_desc_hash *const kripto_hash_skein1024 = &skein1024;
