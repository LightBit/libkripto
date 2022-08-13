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

#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>

#include <kripto/loadstore.h>
#include <kripto/memory.h>
#include <kripto/block.h>
#include <kripto/mac.h>
#include <kripto/desc/mac.h>

#include <kripto/mac/xcbc.h>

struct kripto_mac
{
	const kripto_desc_mac *desc;
	kripto_block *block;
	uint8_t *buf;
	uint8_t *k2;
	uint8_t *k3;
	unsigned int len;
	unsigned int i;
	int f;
};

static int xcbc_init(kripto_mac *s, unsigned int r)
{
	unsigned int i;

	/* key 1 */
	for(i = 0; i < s->len; i++) s->buf[i] = 1;
	kripto_block_encrypt(s->block, s->buf, s->buf);

	/* key 2 */
	for(i = 0; i < s->len; i++) s->k2[i] = 2;
	kripto_block_encrypt(s->block, s->k2, s->k2);

	/* key 3 */
	for(i = 0; i < s->len; i++) s->k3[i] = 3;
	kripto_block_encrypt(s->block, s->k3, s->k3);

	s->block = kripto_block_recreate(s->block, r, s->buf, s->len);
	if(!s->block) return -1;

	memset(s->buf, 0, s->len);
	s->i = 0;
	s->f = 0;

	return 0;
}

static void xcbc_input(kripto_mac *s, const void *in, size_t len)
{
	size_t i;

	for(i = 0; i < len; i++)
	{
		s->buf[s->i++] ^= CU8(in)[i];

		if(s->i == s->len)
		{
			kripto_block_encrypt(s->block, s->buf, s->buf);
			s->i = 0;
		}
	}
}

static void xcbc_tag(kripto_mac *s, void *tag, unsigned int len)
{
	unsigned int i;

	if(!s->f)
	{
		/* finish */
		if(s->i)
		{
			/* pad */
			s->buf[s->i] ^= 0x80;

			/* key 3 */
			for(i = 0; i < s->len; i++)
				s->buf[i] ^= s->k3[i];
		}
		else
		{
			/* key 2 */
			for(i = 0; i < s->len; i++)
				s->buf[i] ^= s->k2[i];
		}

		kripto_block_encrypt(s->block, s->buf, s->buf);
		s->i = 0;
		s->f = -1;
	}

	/* output */
	for(i = 0; i < len; i++)
	{
		assert(s->i < s->len);
		U8(tag)[i] = s->buf[s->i++];
	}
}

static void xcbc_destroy(kripto_mac *s)
{
	kripto_block_destroy(s->block);

	kripto_memory_wipe(s, sizeof(kripto_mac) + s->len * 3);
	free(s);
}

struct ext
{
	kripto_desc_mac desc;
	const kripto_desc_block *block;
};

#define EXT(X) ((const struct ext *)(X))

static kripto_mac *xcbc_create
(
	const kripto_desc_mac *desc,
	unsigned int r,
	const void *key,
	unsigned int key_len,
	unsigned int tag_len
)
{
	kripto_mac *s = (kripto_mac *)malloc(sizeof(kripto_mac) + desc->maxtag * 3);
	if(!s) return 0;

	(void)tag_len;

	s->desc = desc;
	s->len = desc->maxtag;
	s->buf = (uint8_t *)s + sizeof(kripto_mac);
	s->k2 = s->buf + s->len;
	s->k3 = s->k2 + s->len;
	s->block = kripto_block_create(EXT(desc)->block, r, key, key_len);
	if(!s->block)
	{
		free(s);
		return 0;
	}

	if(xcbc_init(s, r))
	{
		free(s);
		return 0;
	}

	return s;
}

static kripto_mac *xcbc_recreate
(
	kripto_mac *s,
	unsigned int r,
	const void *key,
	unsigned int key_len,
	unsigned int tag_len
)
{
	(void)tag_len;

	s->block = kripto_block_recreate(s->block, r, key, key_len);
	if(!s->block) goto err;

	if(xcbc_init(s, r)) goto err;

	return s;

err:
	kripto_memory_wipe(s, sizeof(kripto_mac) + s->desc->maxtag * 3);
	free(s);
	return 0;
}

kripto_desc_mac *kripto_mac_xcbc(const kripto_desc_block *block)
{
	struct ext *s = (struct ext *)malloc(sizeof(struct ext));
	if(!s) return 0;

	s->block = block;

	s->desc.create = &xcbc_create;
	s->desc.recreate = &xcbc_recreate;
	s->desc.input = &xcbc_input;
	s->desc.tag = &xcbc_tag;
	s->desc.destroy = &xcbc_destroy;
	s->desc.maxtag = kripto_block_size(block);
	s->desc.maxkey = kripto_block_maxkey(block);

	return (kripto_desc_mac *)s;
}
