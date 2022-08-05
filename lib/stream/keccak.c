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
#include <kripto/stream.h>
#include <kripto/desc/stream.h>
#include <kripto/object/stream.h>

#include <kripto/stream/keccak1600.h>
#include <kripto/stream/keccak800.h>

struct kripto_stream
{
	struct kripto_stream_object obj;
	kripto_hash *hash;
};

static void keccak_crypt
(
	kripto_stream *s,
	const void *in,
	void *out,
	size_t len
)
{
	size_t i;
	uint8_t buf[64];
	unsigned int n;

	for(i = 0, n = 64; i < len; i++)
	{
		if(n == 64)
		{
			if(len - i < 64)
				kripto_hash_output(s->hash, buf, len - i);
			else
				kripto_hash_output(s->hash, buf, 64);

			n = 0;
		}

		U8(out)[i] = CU8(in)[i] ^ buf[n++];
	}

	kripto_memwipe(buf, 64);
}

static void keccak_prng(kripto_stream *s, void *out, size_t len)
{
	kripto_hash_output(s->hash, out, len);
}

static kripto_stream *keccak_recreate
(
	kripto_stream *s,
	unsigned int r,
	const void *key,
	unsigned int key_len,
	const void *iv,
	unsigned int iv_len
)
{
	(void)kripto_hash_recreate(s->hash, r, key_len);

	kripto_hash_input(s->hash, key, key_len);
	kripto_hash_input(s->hash, iv, iv_len);

	return s;
}

static void keccak_destroy(kripto_stream *s)
{
	kripto_hash_destroy(s->hash);
	free(s);
}

/* 1600 */
static kripto_stream *keccak1600_create
(
	const kripto_stream_desc *desc,
	unsigned int r,
	const void *key,
	unsigned int key_len,
	const void *iv,
	unsigned int iv_len
)
{
	kripto_stream *s;

	(void)desc;

	s = malloc(sizeof(kripto_stream));
	if(!s) return 0;

	s->obj.desc = kripto_stream_keccak1600;
	s->obj.multof = 1;

	s->hash = kripto_hash_create(kripto_hash_keccak1600, r, key_len);
	if(!s->hash)
	{
		free(s);
		return 0;
	}

	kripto_hash_input(s->hash, key, key_len);
	kripto_hash_input(s->hash, iv, iv_len);

	return s;
}

static const kripto_stream_desc keccak1600 =
{
	&keccak1600_create,
	&keccak_recreate,
	&keccak_crypt,
	&keccak_crypt,
	&keccak_prng,
	&keccak_destroy,
	99, /* max key */
	UINT_MAX /* max iv */
};

const kripto_stream_desc *const kripto_stream_keccak1600 = &keccak1600;

/* 800 */
static kripto_stream *keccak800_create
(
	const kripto_stream_desc *desc,
	unsigned int r,
	const void *key,
	unsigned int key_len,
	const void *iv,
	unsigned int iv_len
)
{
	kripto_stream *s;

	(void)desc;

	s = malloc(sizeof(kripto_stream));
	if(!s) return 0;

	s->obj.desc = kripto_stream_keccak800;
	s->obj.multof = 1;

	s->hash = kripto_hash_create(kripto_hash_keccak800, r, key_len);
	if(!s->hash)
	{
		free(s);
		return 0;
	}

	kripto_hash_input(s->hash, key, key_len);
	kripto_hash_input(s->hash, iv, iv_len);

	return s;
}

static const kripto_stream_desc keccak800 =
{
	&keccak800_create,
	&keccak_recreate,
	&keccak_crypt,
	&keccak_crypt,
	&keccak_prng,
	&keccak_destroy,
	49, /* max key */
	UINT_MAX /* max iv */
};

const kripto_stream_desc *const kripto_stream_keccak800 = &keccak800;
