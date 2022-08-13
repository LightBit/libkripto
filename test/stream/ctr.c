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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <kripto/macros.h>
#include <kripto/block.h>
#include <kripto/block_desc.h>
#include <kripto/mode.h>
#include <kripto/mode_ctr.h>
#include <kripto/stream.h>

struct kripto_block
{
	kripto_desc_block *desc;
};

kripto_desc_block *const kripto_block_dummy;

void dummy_crypt(const kripto_block *s, const void *pt, void *ct)
{
	printf("%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x\n", U8(pt)[0], U8(pt)[1], U8(pt)[2], U8(pt)[3], U8(pt)[4], U8(pt)[5], U8(pt)[6], U8(pt)[7],U8(pt)[8], U8(pt)[9], U8(pt)[10], U8(pt)[11],U8(pt)[12], U8(pt)[13], U8(pt)[14], U8(pt)[15]);
	memcpy(ct, pt, 16);
}

kripto_block *dummy_create
(
	const void *key,
	unsigned int key_len,
	unsigned int r
)
{
	kripto_block *s;

	s = malloc(sizeof(struct kripto_block));
	s->desc = kripto_block_dummy;

	return s;
}

void dummy_destroy(kripto_block *s)
{
	free(s);
}

const struct kripto_desc_block dummy =
{
	&dummy_crypt,
	&dummy_crypt,
	&dummy_create,
	&dummy_destroy,
	16,
	0,
	0,
	0
};

kripto_desc_block *const kripto_block_dummy = &dummy;

int main(void)
{
	kripto_stream *s;
	kripto_block *b;
	char buf[640];

	b = kripto_block_create(kripto_block_dummy, "987654321", 8, 0);
	if(b) puts("BLOCK CREATED");
	s = kripto_mode_create(kripto_mode_ctr, b, "123456789", 8);
	if(s) puts("MODE CREATED");
	kripto_stream_prng(s, buf, 640);

	return 0;
}
