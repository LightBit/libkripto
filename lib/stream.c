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

#include <assert.h>
#include <stdint.h>

#include <kripto/stream.h>
#include <kripto/desc/stream.h>

struct kripto_stream
{
	const kripto_stream_desc *desc;
	unsigned int multof;
};

kripto_stream *kripto_stream_create
(
	const kripto_stream_desc *desc,
	unsigned int rounds,
	const void *key,
	unsigned int key_len,
	const void *iv,
	unsigned int iv_len
)
{
	assert(desc);
	assert(desc->create);

	assert(key);
	assert(key_len);
	assert(key_len <= kripto_stream_maxkey(desc));
	assert(iv_len <= kripto_stream_maxiv(desc));
	if(iv_len) assert(iv);

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
	assert(s);
	assert(s->desc);
	assert(s->desc->recreate);

	assert(key);
	assert(key_len);
	assert(key_len <= kripto_stream_maxkey(s->desc));
	assert(iv_len <= kripto_stream_maxiv(s->desc));
	if(iv_len) assert(iv);

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
	assert(s);
	assert(s->desc);
	assert(s->desc->encrypt);
	assert(len % kripto_stream_multof(s) == 0);

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
	assert(s);
	assert(s->desc);
	assert(s->desc->decrypt);
	assert(len % kripto_stream_multof(s) == 0);

	s->desc->decrypt(s, ct, pt, len);
}

void kripto_stream_prng
(
	kripto_stream *s,
	void *out,
	size_t len
)
{
	assert(s);
	assert(s->desc);
	assert(s->desc->prng);

	s->desc->prng(s, out, len);
}

void kripto_stream_destroy(kripto_stream *s)
{
	assert(s);
	assert(s->desc);
	assert(s->desc->destroy);

	s->desc->destroy(s);
}

unsigned int kripto_stream_multof(const kripto_stream *s)
{
	assert(s);
	assert(s->multof);

	return s->multof;
}

const kripto_stream_desc *kripto_stream_getdesc(const kripto_stream *s)
{
	assert(s);
	assert(s->desc);

	return s->desc;
}

unsigned int kripto_stream_maxkey(const kripto_stream_desc *desc)
{
	assert(desc);
	assert(desc->maxkey);

	return desc->maxkey;
}

unsigned int kripto_stream_maxiv(const kripto_stream_desc *desc)
{
	assert(desc);

	return desc->maxiv;
}
