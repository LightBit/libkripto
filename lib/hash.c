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

#include <kripto/hash.h>
#include <kripto/desc/hash.h>

struct kripto_hash
{
	const kripto_hash_desc *desc;
};

kripto_hash *kripto_hash_create
(
	const kripto_hash_desc *desc,
	unsigned int rounds,
	size_t len
)
{
	assert(desc);
	assert(desc->create);
	assert(!desc->maxout || len <= desc->maxout);

	return desc->create(rounds, len);
}

kripto_hash *kripto_hash_recreate
(
	kripto_hash *s,
	unsigned int rounds,
	size_t len
)
{
	assert(s);
	assert(s->desc);
	assert(s->desc->recreate);
	assert(!s->desc->maxout || len <= s->desc->maxout);

	return s->desc->recreate(s, rounds, len);
}

void kripto_hash_input(kripto_hash *s, const void *in, size_t len)
{
	assert(s);
	assert(s->desc);
	assert(s->desc->input);

	s->desc->input(s, in, len);
}

void kripto_hash_output(kripto_hash *s, void *out, size_t len)
{
	assert(s);
	assert(s->desc);
	assert(s->desc->output);
	assert(!s->desc->maxout || len <= s->desc->maxout);

	s->desc->output(s, out, len);
}

void kripto_hash_destroy(kripto_hash *s)
{
	assert(s);
	assert(s->desc);
	assert(s->desc->destroy);

	s->desc->destroy(s);
}

int kripto_hash_all
(
	const kripto_hash_desc *desc,
	unsigned int rounds,
	const void *in,
	size_t in_len,
	void *out,
	size_t out_len
)
{
	assert(desc);
	assert(desc->hash_all);
	assert(!desc->maxout || out_len <= desc->maxout);

	return desc->hash_all(rounds, in, in_len, out, out_len);
}

const kripto_hash_desc *kripto_hash_getdesc(const kripto_hash *s)
{
	assert(s);
	assert(s->desc);

	return s->desc;
}

size_t kripto_hash_maxout(const kripto_hash_desc *desc)
{
	assert(desc);

	return desc->maxout;
}

unsigned int kripto_hash_blocksize(const kripto_hash_desc *desc)
{
	assert(desc);

	return desc->blocksize;
}
