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
	const kripto_desc_hash *desc;
};

kripto_hash *kripto_hash_create
(
	const kripto_desc_hash *desc,
	unsigned int rounds,
	const void *salt,
	unsigned int salt_len,
	unsigned int out_len
)
{
	assert(desc);
	assert(desc->create);
	assert(salt_len <= desc->maxsalt);
	assert(!desc->maxout || out_len <= desc->maxout);

	return desc->create(desc, rounds, salt, salt_len, out_len);
}

kripto_hash *kripto_hash_recreate
(
	kripto_hash *s,
	unsigned int rounds,
	const void *salt,
	unsigned int salt_len,
	unsigned int out_len
)
{
	assert(s);
	assert(s->desc);
	assert(s->desc->recreate);
	assert(salt_len <= s->desc->maxsalt);
	assert(!s->desc->maxout || out_len <= s->desc->maxout);

	return s->desc->recreate(s, rounds, salt, salt_len, out_len);
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
	const kripto_desc_hash *desc,
	unsigned int rounds,
	const void *salt,
	unsigned int salt_len,
	const void *in,
	size_t in_len,
	void *out,
	size_t out_len
)
{
	assert(desc);
	assert(desc->hash_all);
	assert(salt_len <= desc->maxsalt);
	assert(!desc->maxout || out_len <= desc->maxout);

	return desc->hash_all(desc, rounds, salt, salt_len, in, in_len, out, out_len);
}

const kripto_desc_hash *kripto_hash_getdesc(const kripto_hash *s)
{
	assert(s);
	assert(s->desc);

	return s->desc;
}

unsigned int kripto_hash_maxout(const kripto_desc_hash *desc)
{
	assert(desc);

	return desc->maxout;
}

unsigned int kripto_hash_maxsalt(const kripto_desc_hash *desc)
{
	assert(desc);

	return desc->maxsalt;
}

unsigned int kripto_hash_blocksize(const kripto_desc_hash *desc)
{
	assert(desc);

	return desc->blocksize;
}
