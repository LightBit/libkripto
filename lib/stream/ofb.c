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

#include <kripto/cast.h>
#include <kripto/memory.h>
#include <kripto/block.h>
#include <kripto/stream.h>
#include <kripto/desc/stream.h>

#include <kripto/stream/ofb.h>

struct kripto_stream
{
	const kripto_desc_stream *desc;
	unsigned int multof;
	kripto_block *block;
	uint8_t *prev;
	unsigned int blocksize;
	unsigned int used;
};

static void ofb_crypt
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
		if(s->used == s->blocksize)
		{
			kripto_block_encrypt(s->block, s->prev, s->prev);
			s->used = 0;
		}

		U8(out)[i] = CU8(in)[i] ^ s->prev[s->used++];
	}
}

static void ofb_prng
(
	kripto_stream *s,
	void *out,
	size_t len
)
{
	size_t i;

	for(i = 0; i < len; i++)
	{
		if(s->used == s->blocksize)
		{
			kripto_block_encrypt(s->block, s->prev, s->prev);
			s->used = 0;
		}

		U8(out)[i] = s->prev[s->used++];
	}
}

static void ofb_destroy(kripto_stream *s)
{
	kripto_block_destroy(s->block);
	kripto_memory_wipe(s, sizeof(kripto_stream) + s->blocksize);
	free(s);
}

struct ext
{
	kripto_desc_stream desc;
	const kripto_desc_block *block;
};

#define EXT(X) ((const struct ext *)(X))

static kripto_stream *ofb_create
(
	const kripto_desc_stream *desc,
	unsigned int rounds,
	const void *key,
	unsigned int key_len,
	const void *iv,
	unsigned int iv_len
)
{
	kripto_stream *s = (kripto_stream *)malloc(sizeof(kripto_stream) + desc->maxiv);
	if(!s) return 0;

	s->desc = desc;
	s->multof = 1;

	s->used = s->blocksize = desc->maxiv;

	s->prev = (uint8_t *)s + sizeof(kripto_stream);

	/* block cipher */
	s->block = kripto_block_create(EXT(desc)->block, rounds, key, key_len);
	if(!s->block)
	{
		kripto_memory_wipe(s, sizeof(kripto_stream) + s->blocksize);
		free(s);
		return 0;
	}

	/* IV */
	if(iv_len) memcpy(s->prev, iv, iv_len);
	memset(s->prev + iv_len, 0, s->blocksize - iv_len);

	return s;
}

static kripto_stream *ofb_recreate
(
	kripto_stream *s,
	unsigned int rounds,
	const void *key,
	unsigned int key_len,
	const void *iv,
	unsigned int iv_len
)
{
	/* block cipher */
	s->block = kripto_block_recreate(s->block, rounds, key, key_len);
	if(!s->block)
	{
		kripto_memory_wipe(s, sizeof(kripto_stream) + s->blocksize);
		free(s);
		return 0;
	}

	/* IV */
	if(iv_len) memcpy(s->prev, iv, iv_len);
	memset(s->prev + iv_len, 0, s->blocksize - iv_len);

	s->used = s->blocksize;

	return s;
}

kripto_desc_stream *kripto_stream_ofb(const kripto_desc_block *block)
{
	struct ext *s = (struct ext *)malloc(sizeof(struct ext));
	if(!s) return 0;

	s->block = block;

	s->desc.create = &ofb_create;
	s->desc.recreate = &ofb_recreate;
	s->desc.encrypt = &ofb_crypt;
	s->desc.decrypt = &ofb_crypt;
	s->desc.prng = &ofb_prng;
	s->desc.destroy = &ofb_destroy;
	s->desc.maxkey = kripto_block_maxkey(block);
	s->desc.maxiv = kripto_block_size(block);

	return (kripto_desc_stream *)s;
}
