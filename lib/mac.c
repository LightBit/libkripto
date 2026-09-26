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
#include <kripto/memory.h>
#include <kripto/mac.h>
#include <kripto/desc/mac.h>

struct kripto_mac
{
	const kripto_desc_mac *desc;
};

kripto_mac *kripto_mac_create
(
	const kripto_desc_mac *desc,
	unsigned int rounds,
	const void *key,
	unsigned int key_len,
	unsigned int tag_len
)
{
	kripto_assert(desc);
	kripto_assert(desc->create);

	kripto_assert(key);
	kripto_assert(key_len);
	kripto_assert(!desc->maxkey || key_len <= desc->maxkey);

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
	kripto_assert(s);
	kripto_assert(s->desc);
	kripto_assert(s->desc->recreate);

	kripto_assert(key);
	kripto_assert(key_len);
	kripto_assert(!s->desc->maxkey || key_len <= s->desc->maxkey);

	return s->desc->recreate(s, rounds, key, key_len, tag_len);
}

void kripto_mac_input(kripto_mac *s, const void *in, size_t len)
{
	kripto_assert(s);
	kripto_assert(s->desc);
	kripto_assert(s->desc->input);

	s->desc->input(s, in, len);
}

void kripto_mac_tag(kripto_mac *s, void *tag, unsigned int len)
{
	kripto_assert(s);
	kripto_assert(s->desc);
	kripto_assert(s->desc->tag);

	kripto_assert(!s->desc->maxtag || len <= s->desc->maxtag);

	s->desc->tag(s, tag, len);
}

int kripto_mac_verify(kripto_mac *s, const void *tag, unsigned int len)
{
	kripto_assert(s);
	kripto_assert(s->desc);
	kripto_assert(s->desc->tag);

	kripto_assert(!s->desc->maxtag || len <= s->desc->maxtag);

	char t[len];
	s->desc->tag(s, t, len);
	return kripto_memory_equals(t, tag, len);
}

void kripto_mac_destroy(kripto_mac *s)
{
	kripto_assert(s);
	kripto_assert(s->desc);
	kripto_assert(s->desc->destroy);

	s->desc->destroy(s);
}

int kripto_mac_all
(
	const kripto_desc_mac *desc,
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

	s = kripto_mac_create(desc, rounds, key, key_len, tag_len);
	if(!s) return -1;

	kripto_mac_input(s, in, in_len);
	kripto_mac_tag(s, tag, tag_len);

	kripto_mac_destroy(s);

	return 0;
}

const kripto_desc_mac *kripto_mac_getdesc(const kripto_mac *s)
{
	kripto_assert(s);
	kripto_assert(s->desc);

	return s->desc;
}

unsigned int kripto_mac_maxtag(const kripto_desc_mac *desc)
{
	kripto_assert(desc);

	return desc->maxtag;
}

unsigned int kripto_mac_maxkey(const kripto_desc_mac *desc)
{
	kripto_assert(desc);

	return desc->maxkey;
}
