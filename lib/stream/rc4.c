/*
 * Written in 2011 by Gregor Pintar <grpintar@gmail.com>
 *
 * To the extent possible under law, the author(s) have dedicated
 * all copyright and related and neighboring rights to this software
 * to the public domain worldwide.
 * 
 * This software is distributed without any warranty.
 *
 * You should have received a copy of the CC0 Public Domain Dedication.
 * If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
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
	kripto_stream *s;

	(void)desc;

	s = malloc(sizeof(kripto_stream));
	if(!s) return 0;

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
