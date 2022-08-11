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

#include <kripto/memory.h>
#include <kripto/mac.h>
#include <kripto/desc/mac.h>

struct kripto_mac
{
	const kripto_mac_desc *desc;
};

kripto_mac *kripto_mac_create
(
	const kripto_mac_desc *desc,
	unsigned int rounds,
	const void *key,
	unsigned int key_len,
	unsigned int tag_len
)
{
	assert(desc);
	assert(desc->create);

	assert(key);
	assert(key_len);

	return desc->create(desc, rounds, key, key_len, tag_len);
}

kripto_mac *kripto_mac_recreate
(
	kripto_mac *s,
	unsigned int rounds,
	const void *key,
	unsigned int key_len,
	unsigned int tag_len
)
{
	assert(s);
	assert(s->desc);
	assert(s->desc->recreate);

	assert(key);
	assert(key_len);

	return s->desc->recreate(s, rounds, key, key_len, tag_len);
}

void kripto_mac_input(kripto_mac *s, const void *in, size_t len)
{
	assert(s);
	assert(s->desc);
	assert(s->desc->input);

	s->desc->input(s, in, len);
}

void kripto_mac_tag(kripto_mac *s, void *tag, unsigned int len)
{
	assert(s);
	assert(s->desc);
	assert(s->desc->tag);

	s->desc->tag(s, tag, len);
}

int kripto_mac_verify(kripto_mac *s, const void *tag, unsigned int len)
{
	assert(s);
	assert(s->desc);
	assert(s->desc->tag);

	char t[len];
	s->desc->tag(s, t, len);
	return kripto_memory_equals(t, tag, len);
}

void kripto_mac_destroy(kripto_mac *s)
{
	assert(s);
	assert(s->desc);
	assert(s->desc->destroy);

	s->desc->destroy(s);
}

int kripto_mac_all
(
	const kripto_mac_desc *desc,
	unsigned int rounds,
	const void *key,
	unsigned int key_len,
	const void *in,
	unsigned int in_len,
	void *tag,
	unsigned int tag_len
)
{
	kripto_mac *s;

	assert(desc);

	s = kripto_mac_create(desc, rounds, key, key_len, tag_len);
	if(!s) return -1;

	kripto_mac_input(s, in, in_len);
	kripto_mac_tag(s, tag, tag_len);

	kripto_mac_destroy(s);

	return 0;
}

const kripto_mac_desc *kripto_mac_getdesc(const kripto_mac *s)
{
	assert(s);
	assert(s->desc);

	return s->desc;
}

unsigned int kripto_mac_maxtag(const kripto_mac_desc *desc)
{
	assert(desc);

	return desc->maxtag;
}

unsigned int kripto_mac_maxkey(const kripto_mac_desc *desc)
{
	assert(desc);

	return desc->maxkey;
}
