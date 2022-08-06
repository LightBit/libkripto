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
#include <limits.h>

#include <kripto/cast.h>
#include <kripto/memwipe.h>
#include <kripto/hash.h>
#include <kripto/hash/keccak1600.h>
#include <kripto/hash/keccak800.h>
#include <kripto/mac.h>
#include <kripto/desc/mac.h>
#include <kripto/object/mac.h>

#include <kripto/mac/keccak1600.h>
#include <kripto/mac/keccak800.h>

struct kripto_mac
{
	struct kripto_mac_object obj;
	kripto_hash *hash;
};

static void keccak_input
(
	kripto_mac *s,
	const void *in,
	size_t len
) 
{
	kripto_hash_input(s->hash, in, len);
}

static void keccak_tag(kripto_mac *s, void *tag, unsigned int len)
{
	kripto_hash_output(s->hash, tag, len);
}

static kripto_mac *keccak_recreate
(
	kripto_mac *s,
	unsigned int r,
	const void *key,
	unsigned int key_len,
	unsigned int tag_len
)
{
	(void)kripto_hash_recreate(s->hash, r, tag_len);

	kripto_hash_input(s->hash, key, key_len);

	return s;
}

static kripto_mac *keccak1600_create
(
	const kripto_mac_desc *desc,
	unsigned int r,
	const void *key,
	unsigned int key_len,
	unsigned int tag_len
)
{
	kripto_mac *s = (kripto_mac *)malloc(sizeof(kripto_mac));
	if(!s) return 0;

	(void)desc;

	s->obj.desc = kripto_mac_keccak1600;

	s->hash = kripto_hash_create(kripto_hash_keccak1600, r, tag_len);
	if(!s->hash)
	{
		free(s);
		return 0;
	}

	kripto_hash_input(s->hash, key, key_len);

	return s;
}

static kripto_mac *keccak800_create
(
	const kripto_mac_desc *desc,
	unsigned int r,
	const void *key,
	unsigned int key_len,
	unsigned int tag_len
)
{
	kripto_mac *s = (kripto_mac *)malloc(sizeof(kripto_mac));
	if(!s) return 0;

	(void)desc;

	s->obj.desc = kripto_mac_keccak800;

	s->hash = kripto_hash_create(kripto_hash_keccak800, r, tag_len);
	if(!s->hash)
	{
		free(s);
		return 0;
	}

	kripto_hash_input(s->hash, key, key_len);

	return s;
}

static void keccak_destroy(kripto_mac *s)
{
	kripto_hash_destroy(s->hash);
	free(s);
}

static const kripto_mac_desc keccak1600 =
{
	&keccak1600_create,
	&keccak_recreate,
	&keccak_input,
	&keccak_tag,
	&keccak_destroy,
	99, /* max tag */
	UINT_MAX /* max key */
};

const kripto_mac_desc *const kripto_mac_keccak1600 = &keccak1600;

static const kripto_mac_desc keccak800 =
{
	&keccak800_create,
	&keccak_recreate,
	&keccak_input,
	&keccak_tag,
	&keccak_destroy,
	49, /* max tag */
	UINT_MAX /* max key */
};

const kripto_mac_desc *const kripto_mac_keccak800 = &keccak800;
