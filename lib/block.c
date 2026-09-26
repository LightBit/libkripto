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

#include <kripto/assert.h>
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
	kripto_assert(desc);
	kripto_assert(desc->create);

	kripto_assert(key);
	kripto_assert(key_len);
	kripto_assert(key_len <= desc->maxkey);

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
	kripto_assert(s);
	kripto_assert(s->desc);
	kripto_assert(s->desc->recreate);

	kripto_assert(key);
	kripto_assert(key_len);
	kripto_assert(key_len <= s->desc->maxkey);

	return s->desc->recreate(s, rounds, key, key_len);
}

void kripto_block_tweak
(
	kripto_block *s,
	const void *tweak,
	unsigned int len
)
{
	kripto_assert(s);
	kripto_assert(s->desc);
	kripto_assert(s->desc->tweak);

	kripto_assert(tweak);
	kripto_assert(len);
	kripto_assert(len <= s->desc->maxtweak);

	s->desc->tweak(s, tweak, len);
}

void kripto_block_encrypt
(
	const kripto_block *s,
	const void *pt,
	void *ct
)
{
	kripto_assert(s);
	kripto_assert(s->desc);
	kripto_assert(s->desc->encrypt);
	kripto_assert(pt);
	kripto_assert(ct);

	s->desc->encrypt(s, pt, ct);
}

void kripto_block_decrypt
(
	const kripto_block *s,
	const void *ct,
	void *pt
)
{
	kripto_assert(s);
	kripto_assert(s->desc);
	kripto_assert(s->desc->decrypt);
	kripto_assert(ct);
	kripto_assert(pt);

	s->desc->decrypt(s, ct, pt);
}

void kripto_block_destroy(kripto_block *s)
{
	kripto_assert(s);
	kripto_assert(s->desc);
	kripto_assert(s->desc->destroy);

	s->desc->destroy(s);
}

const kripto_desc_block *kripto_block_getdesc(const kripto_block *s)
{
	kripto_assert(s);
	kripto_assert(s->desc);

	return s->desc;
}

unsigned int kripto_block_size(const kripto_desc_block *desc)
{
	kripto_assert(desc);
	kripto_assert(desc->blocksize);

	return desc->blocksize;
}

unsigned int kripto_block_maxkey(const kripto_desc_block *desc)
{
	kripto_assert(desc);
	kripto_assert(desc->maxkey);

	return desc->maxkey;
}

unsigned int kripto_block_maxtweak(const kripto_desc_block *desc)
{
	kripto_assert(desc);

	return desc->maxtweak;
}
