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

#include <kripto/assert.h>
#include <kripto/stream.h>
#include <kripto/desc/stream.h>

struct kripto_stream
{
	const kripto_desc_stream *desc;
	unsigned int multof;
};

kripto_stream *kripto_stream_create
(
	const kripto_desc_stream *desc,
	unsigned int rounds,
	const void *key,
	unsigned int key_len,
	const void *iv,
	unsigned int iv_len
)
{
	kripto_assert(desc);
	kripto_assert(desc->create);

	kripto_assert(key);
	kripto_assert(key_len);
	kripto_assert(key_len <= desc->maxkey);
	kripto_assert(iv_len <= desc->maxiv);
	kripto_assert(!iv_len || iv);

	return desc->create(desc, rounds, key, key_len, iv, iv_len);
}

kripto_stream *kripto_stream_recreate
(
	kripto_stream *s,
	unsigned int rounds,
	const void *key,
	unsigned int key_len,
	const void *iv,
	unsigned int iv_len
)
{
	kripto_assert(s);
	kripto_assert(s->desc);
	kripto_assert(s->desc->recreate);

	kripto_assert(key);
	kripto_assert(key_len);
	kripto_assert(key_len <= s->desc->maxkey);
	kripto_assert(iv_len <= s->desc->maxiv);
	kripto_assert(!iv_len || iv);

	return s->desc->recreate(s, rounds, key, key_len, iv, iv_len);
}

void kripto_stream_encrypt
(
	kripto_stream *s,
	const void *pt,
	void *ct,
	size_t len
)
{
	kripto_assert(s);
	kripto_assert(s->desc);
	kripto_assert(s->desc->encrypt);
	kripto_assert(len % s->multof == 0);

	s->desc->encrypt(s, pt, ct, len);
}

void kripto_stream_decrypt
(
	kripto_stream *s,
	const void *ct,
	void *pt,
	size_t len
)
{
	kripto_assert(s);
	kripto_assert(s->desc);
	kripto_assert(s->desc->decrypt);
	kripto_assert(len % s->multof == 0);

	s->desc->decrypt(s, ct, pt, len);
}

void kripto_stream_prng
(
	kripto_stream *s,
	void *out,
	size_t len
)
{
	kripto_assert(s);
	kripto_assert(s->desc);
	kripto_assert(s->desc->prng);

	s->desc->prng(s, out, len);
}

void kripto_stream_destroy(kripto_stream *s)
{
	kripto_assert(s);
	kripto_assert(s->desc);
	kripto_assert(s->desc->destroy);

	s->desc->destroy(s);
}

unsigned int kripto_stream_multof(const kripto_stream *s)
{
	kripto_assert(s);
	kripto_assert(s->multof);

	return s->multof;
}

const kripto_desc_stream *kripto_stream_getdesc(const kripto_stream *s)
{
	kripto_assert(s);
	kripto_assert(s->desc);

	return s->desc;
}

unsigned int kripto_stream_maxkey(const kripto_desc_stream *desc)
{
	kripto_assert(desc);
	kripto_assert(desc->maxkey);

	return desc->maxkey;
}

unsigned int kripto_stream_maxiv(const kripto_desc_stream *desc)
{
	kripto_assert(desc);

	return desc->maxiv;
}
