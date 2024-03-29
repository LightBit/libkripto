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
#include <string.h>
#include <stdlib.h>

#include <kripto/cast.h>
#include <kripto/memory.h>
#include <kripto/block.h>
#include <kripto/stream.h>
#include <kripto/desc/stream.h>

#include <kripto/stream/ctr.h>

struct kripto_stream
{
	const kripto_desc_stream *desc;
	unsigned int multof;
	kripto_block *block;
	uint8_t *x;
	uint8_t *buf;
	unsigned int blocksize;
	unsigned int used;
};

static void ctr_crypt
(
	kripto_stream *s,
	const void *in,
	void *out,
	size_t len
)
{
	size_t i;
	unsigned int n;

	for(i = 0; i < len; i++)
	{
		if(s->used == s->blocksize)
		{
			kripto_block_encrypt(s->block, s->x, s->buf);
			s->used = 0;

			for(n = s->blocksize - 1; n; n--)
				if(++s->x[n]) break;
		}

		U8(out)[i] = CU8(in)[i] ^ s->buf[s->used++];
	}
}

static void ctr_prng
(
	kripto_stream *s,
	void *out,
	size_t len
)
{
	size_t i;
	unsigned int n;

	for(i = 0; i < len; i++)
	{
		if(s->used == s->blocksize)
		{
			kripto_block_encrypt(s->block, s->x, s->buf);
			s->used = 0;

			for(n = s->blocksize - 1; n; n--)
				if(++s->x[n]) break;
		}

		U8(out)[i] = s->buf[s->used++];
	}
}

static void ctr_destroy(kripto_stream *s)
{
	kripto_block_destroy(s->block);
	kripto_memory_wipe(s, sizeof(kripto_stream) + (s->blocksize << 1));
	free(s);
}

struct ext
{
	kripto_desc_stream desc;
	const kripto_desc_block *block;
};

#define EXT(X) ((const struct ext *)(X))

static kripto_stream *ctr_create
(
	const kripto_desc_stream *desc,
	unsigned int rounds,
	const void *key,
	unsigned int key_len,
	const void *iv,
	unsigned int iv_len
)
{
	kripto_stream *s = (kripto_stream *)malloc(sizeof(kripto_stream) + (desc->maxiv << 1));
	if(!s) return 0;

	s->desc = desc;
	s->multof = 1;

	s->used = s->blocksize = desc->maxiv;

	s->x = (uint8_t *)s + sizeof(kripto_stream);
	s->buf = s->x + s->blocksize;

	/* block cipher */
	s->block = kripto_block_create(EXT(desc)->block, rounds, key, key_len);
	if(!s->block)
	{
		kripto_memory_wipe(s, sizeof(kripto_stream) + (s->blocksize << 1));
		free(s);
		return 0;
	}

	/* IV (nonce) */
	if(iv_len) memcpy(s->x, iv, iv_len);
	memset(s->x + iv_len, 0, s->blocksize - iv_len);

	return s;
}

static kripto_stream *ctr_recreate
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
		kripto_memory_wipe(s, sizeof(kripto_stream) + (s->blocksize << 1));
		free(s);
		return 0;
	}

	/* IV (nonce) */
	if(iv_len) memcpy(s->x, iv, iv_len);
	memset(s->x + iv_len, 0, s->blocksize - iv_len);

	s->used = s->blocksize;

	return s;
}

kripto_desc_stream *kripto_stream_ctr(const kripto_desc_block *block)
{
	struct ext *s = (struct ext *)malloc(sizeof(struct ext));
	if(!s) return 0;

	s->block = block;

	s->desc.create = &ctr_create;
	s->desc.recreate = &ctr_recreate;
	s->desc.encrypt = &ctr_crypt;
	s->desc.decrypt = &ctr_crypt;
	s->desc.prng = &ctr_prng;
	s->desc.destroy = &ctr_destroy;
	s->desc.maxkey = kripto_block_maxkey(block);
	s->desc.maxiv = kripto_block_size(block);

	return (kripto_desc_stream *)s;
}
