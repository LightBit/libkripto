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
#include <kripto/ae.h>
#include <kripto/desc/ae.h>

struct kripto_ae
{
	const kripto_desc_ae *desc;
	unsigned int multof;
};

kripto_ae *kripto_ae_create
(
	const kripto_desc_ae *desc,
	unsigned int rounds,
	const void *key,
	unsigned int key_len,
	const void *iv,
	unsigned int iv_len,
	unsigned int tag_len
)
{
	kripto_assert(desc);
	kripto_assert(desc->create);

	kripto_assert(key);
	kripto_assert(key_len);
	kripto_assert(key_len <= desc->maxkey);
	kripto_assert(iv_len <= desc->maxiv);
	kripto_assert(!iv_len || iv);
	kripto_assert(tag_len <= desc->maxtag);

	return desc->create(desc, rounds, key, key_len, iv, iv_len, tag_len);
}

kripto_ae *kripto_ae_recreate
(
	kripto_ae *s,
	unsigned int rounds,
	const void *key,
	unsigned int key_len,
	const void *iv,
	unsigned int iv_len,
	unsigned int tag_len
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
	kripto_assert(tag_len <= s->desc->maxtag);

	return s->desc->recreate(s, rounds, key, key_len, iv, iv_len, tag_len);
}

void kripto_ae_encrypt
(
	kripto_ae *s,
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

void kripto_ae_decrypt
(
	kripto_ae *s,
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

void kripto_ae_header
(
	kripto_ae *s,
	const void *header,
	size_t len
)
{
	kripto_assert(s);
	kripto_assert(s->desc);
	kripto_assert(s->desc->header);

	s->desc->header(s, header, len);
}

void kripto_ae_tag
(
	kripto_ae *s,
	void *tag,
	unsigned int len
)
{
	kripto_assert(s);
	kripto_assert(s->desc);
	kripto_assert(s->desc->tag);

	kripto_assert(!s->desc->maxtag || len <= s->desc->maxtag);

	s->desc->tag(s, tag, len);
}

int kripto_ae_verify
(
	kripto_ae *s,
	const void *tag,
	unsigned int len
)
{
	kripto_assert(s);
	kripto_assert(s->desc);
	kripto_assert(s->desc->tag);

	kripto_assert(!s->desc->maxtag || len <= s->desc->maxtag);

	char t[len];
	s->desc->tag(s, t, len);
	return kripto_memory_equals(t, tag, len);
}

void kripto_ae_destroy(kripto_ae *s)
{
	kripto_assert(s);
	kripto_assert(s->desc);
	kripto_assert(s->desc->destroy);

	s->desc->destroy(s);
}

unsigned int kripto_ae_multof(const kripto_ae *s)
{
	kripto_assert(s);
	kripto_assert(s->multof);

	return s->multof;
}

const kripto_desc_ae *kripto_ae_getdesc(const kripto_ae *s)
{
	kripto_assert(s);
	kripto_assert(s->desc);

	return s->desc;
}

unsigned int kripto_ae_maxkey(const kripto_desc_ae *desc)
{
	kripto_assert(desc);
	kripto_assert(desc->maxkey);

	return desc->maxkey;
}

unsigned int kripto_ae_maxiv(const kripto_desc_ae *desc)
{
	kripto_assert(desc);

	return desc->maxiv;
}

unsigned int kripto_ae_maxtag(const kripto_desc_ae *desc)
{
	kripto_assert(desc);

	return desc->maxtag;
}
