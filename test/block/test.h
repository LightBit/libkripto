/*
 * Copyright (C) 2022 by Gregor Pintar <grpintar@gmail.com>
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

#ifndef TEST_BLOCK_TEST_H
#define TEST_BLOCK_TEST_H

#include "../test.h"

struct vector
{
	unsigned int key_len;
	unsigned int tweak_len;
	unsigned int rounds;
	unsigned int iterations;
	const char *key;
	const char *tweak;
	const char *pt;
	const char *ct;
};

int test
(
	const char *file,
	unsigned int line,
	const kripto_desc_block *desc,
	const struct vector *vectors,
	unsigned int vectors_len
);
#define TEST(DESC, VECTORS, VECTORS_LEN) test(__FILE__, __LINE__, DESC, VECTORS, VECTORS_LEN)

int test
(
	const char *file,
	unsigned int line,
	const kripto_desc_block *desc,
	const struct vector *vectors,
	unsigned int vectors_len
)
{
	unsigned int block_size = kripto_block_size(desc);
	char t[block_size];

	for(unsigned int i = 0; i < vectors_len; i++)
	{
		kripto_block *s = kripto_block_create(desc, vectors[i].rounds, vectors[i].key, vectors[i].key_len);
		if(!s) test_error(file, line, "Create vector %u", i);

		if(vectors[i].tweak_len > 0)
		{
			kripto_block_tweak(s, vectors[i].tweak, vectors[i].tweak_len);
		}

		memcpy(t, vectors[i].pt, block_size);
		for(unsigned int r = 0; r < vectors[i].iterations; r++)
		{
			kripto_block_encrypt(s, t, t);
		}
		test_cmp(t, vectors[i].ct, block_size, file, line, "Encrypt vector %u", i);

		memcpy(t, vectors[i].ct, block_size);
		for(unsigned int r = 0; r < vectors[i].iterations; r++)
		{
			kripto_block_decrypt(s, t, t);
		}
		test_cmp(t, vectors[i].pt, block_size, file, line, "Decrypt vector %u", i);

		kripto_block_destroy(s);
	}

	return test_result;
}

#endif
