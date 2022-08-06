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
#include <stdlib.h>
#include <limits.h>

#include <kripto/cast.h>
#include <kripto/memwipe.h>
#include <kripto/stream.h>
#include <kripto/desc/stream.h>
#include <kripto/object/stream.h>

#include <kripto/stream/rc4.h>

struct kripto_stream
{
	struct kripto_stream_object obj;
	uint8_t p[256];
	uint8_t i;
	uint8_t j;
};

static void rc4_setup
(
	kripto_stream *s,
	const void *key,
	unsigned int key_len
)
{
	unsigned int i;
	unsigned int j;
	uint8_t t;

	s->i = s->j = 0;

	for(i = 0; i < 256; i++) s->p[i] = i;

	if(key && key_len)
	{
		j = 0;
		for(i = 0; i < 256; i++)
		{
			s->j = s->j + s->p[s->i] + CU8(key)[j++];
			if(j == key_len) j = 0;

			t = s->p[s->i];
			s->p[s->i] = s->p[s->j];
			s->p[s->j] = t;

			s->i++;
		}
	}

	s->i = s->j = 0;
}

static inline uint8_t rc4(kripto_stream *s)
{
	uint8_t t;

	s->i++;
	s->j = s->j + s->p[s->i];

	t = s->p[s->i];
	s->p[s->i] = s->p[s->j];
	s->p[s->j] = t;

	return(s->p[(uint8_t)(s->p[s->i] + s->p[s->j])]);
}

static void rc4_crypt
(
	kripto_stream *s,
	const void *in,
	void *out,
	size_t len
)
{
	size_t i;

	for(i = 0; i < len; i++)
		U8(out)[i] = CU8(in)[i] ^ rc4(s);
}

static void rc4_prng
(
	kripto_stream *s,
	void *out,
	size_t len
)
{
	size_t i;

	for(i = 0; i < len; i++)
		U8(out)[i] = rc4(s);
}

static kripto_stream *rc4_recreate
(
	kripto_stream *s,
	unsigned int r,
	const void *key,
	unsigned int key_len,
	const void *iv,
	unsigned int iv_len
)
{
	unsigned int i;

	rc4_setup(s, key, key_len);
	(void)iv;
	(void)iv_len;

	s->i = s->j = 0;

	/* drop ? */
	for(i = 0; i < r; i++) (void)rc4(s);

	return s;
}

static kripto_stream *rc4_create
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

	s->obj.desc = kripto_stream_rc4;
	s->obj.multof = 1;

	(void)rc4_recreate(s, r, key, key_len, iv, iv_len);

	return s;
}

static void rc4_destroy(kripto_stream *s)
{
	kripto_memwipe(s, sizeof(kripto_stream));
	free(s);
}

static const struct kripto_stream_desc rc4_desc =
{
	&rc4_create,
	&rc4_recreate,
	&rc4_crypt,
	&rc4_crypt,
	&rc4_prng,
	&rc4_destroy,
	256, /* max key */
	0 /* max iv */
};

const kripto_stream_desc *const kripto_stream_rc4 = &rc4_desc;
