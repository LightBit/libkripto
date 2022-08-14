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

#ifndef TEST_HASH_TEST_H
#define TEST_HASH_TEST_H

#include "../test.h"

struct vector
{
	unsigned int hash_len;
	unsigned int message_len;
	unsigned int message_repeat;
	unsigned int salt_len;
	unsigned int rounds;
	const char *message;
	const char *salt;
	const char *hash;
};

int test
(
	const char *file,
	unsigned int line,
	const kripto_desc_hash *desc,
	const struct vector *vectors,
	unsigned int vectors_len
);
#define TEST(DESC, VECTORS, VECTORS_LEN) test(__FILE__, __LINE__, DESC, VECTORS, VECTORS_LEN)

int test
(
	const char *file,
	unsigned int line,
	const kripto_desc_hash *desc,
	const struct vector *vectors,
	unsigned int vectors_len
)
{
	for(unsigned int i = 0; i < vectors_len; i++)
	{
		char t[vectors[i].hash_len];

		kripto_hash *s = kripto_hash_create
		(
			desc, vectors[i].rounds,
			vectors[i].salt, vectors[i].salt_len,
			vectors[i].hash_len
		);
		if(!s) test_error(file, line, "Create vector %u", i);

		for(unsigned int r = 0; r < vectors[i].message_repeat; r++)
		{
			kripto_hash_input(s, vectors[i].message, vectors[i].message_len);
		}

		kripto_hash_output(s, t, vectors[i].hash_len);
		test_cmp(t, vectors[i].hash, vectors[i].hash_len, file, line, "Hash vector %u", i);

		kripto_hash_destroy(s);

		if(vectors[i].message_repeat == 1)
		{
			if(kripto_hash_all
			(
				desc, vectors[i].rounds,
				vectors[i].salt, vectors[i].salt_len,
				vectors[i].message, vectors[i].message_len,
				t, vectors[i].hash_len
			)) test_error(file, line, "Hash vector %u", i);
			test_cmp(t, vectors[i].hash, vectors[i].hash_len, file, line, "Hash all vector %u", i);
		}
	}

	return test_result;
}

#endif
