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

#ifndef TEST_STREAM_TEST_H
#define TEST_STREAM_TEST_H

#include "../test.h"

struct vector
{
	unsigned int key_len;
	unsigned int iv_len;
	unsigned int rounds;
	unsigned int len;
	const char *key;
	const char *iv;
	const char *pt;
	const char *ct;
};

int test
(
	const char *file,
	unsigned int line,
	const kripto_desc_stream *desc,
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
	for(unsigned int i = 0; i < vectors_len; i++)
	{
		char t[vectors[i].len];

		kripto_stream *s = kripto_stream_create
		(
			desc, vectors[i].rounds,
			vectors[i].key, vectors[i].key_len,
			vectors[i].iv, vectors[i].iv_len
		);
		if(!s) test_error(file, line, "Create vector %u", i);

		kripto_stream_encrypt(s, vectors[i].pt, t, vectors[i].len);
		test_cmp(t, vectors[i].ct, block_size, file, line, "Encrypt vector %u", i);

		kripto_stream_decrypt(s, vectors[i].ct, t, vectors[i].len);
		test_cmp(t, vectors[i].pt, block_size, file, line, "Decrypt vector %u", i);

		kripto_stream_destroy(s);
	}

	return test_result;
}

#endif
