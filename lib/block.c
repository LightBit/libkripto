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

#include <kripto/block.h>
#include <kripto/desc/block.h>

struct kripto_block
{
	const kripto_desc_block *desc;
};

kripto_block *kripto_block_create
(
	const kripto_desc_block *desc,
	unsigned int rounds,
	const void *key,
	unsigned int key_len
)
{
	assert(desc);
	assert(desc->create);

	assert(key);
	assert(key_len);
	assert(key_len <= kripto_block_maxkey(desc));

	return desc->create(desc, rounds, key, key_len);
}

kripto_block *kripto_block_recreate
(
	kripto_block *s,
	unsigned int rounds,
	const void *key,
	unsigned int key_len
)
{
	assert(s);
	assert(s->desc);
	assert(s->desc->recreate);

	assert(key);
	assert(key_len);
	assert(key_len <= kripto_block_maxkey(s->desc));

	return s->desc->recreate(s, rounds, key, key_len);
}

void kripto_block_tweak
(
	kripto_block *s,
	const void *tweak,
	unsigned int len
)
{
	assert(s);
	assert(s->desc);
	assert(s->desc->tweak);

	assert(tweak);
	assert(len);

	s->desc->tweak(s, tweak, len);
}

void kripto_block_encrypt
(
	const kripto_block *s,
	const void *pt,
	void *ct
)
{
	assert(s);
	assert(s->desc);
	assert(s->desc->encrypt);
	assert(pt);
	assert(ct);

	s->desc->encrypt(s, pt, ct);
}

void kripto_block_decrypt
(
	const kripto_block *s,
	const void *ct,
	void *pt
)
{
	assert(s);
	assert(s->desc);
	assert(s->desc->decrypt);
	assert(ct);
	assert(pt);

	s->desc->decrypt(s, ct, pt);
}

void kripto_block_destroy(kripto_block *s)
{
	assert(s);
	assert(s->desc);
	assert(s->desc->destroy);

	s->desc->destroy(s);
}

const kripto_desc_block *kripto_block_getdesc(const kripto_block *s)
{
	assert(s);
	assert(s->desc);

	return s->desc;
}

unsigned int kripto_block_size(const kripto_desc_block *desc)
{
	assert(desc);
	assert(desc->blocksize);

	return desc->blocksize;
}

unsigned int kripto_block_maxkey(const kripto_desc_block *desc)
{
	assert(desc);
	assert(desc->maxkey);

	return desc->maxkey;
}

unsigned int kripto_block_maxtweak(const kripto_desc_block *desc)
{
	assert(desc);

	return desc->maxtweak;
}
