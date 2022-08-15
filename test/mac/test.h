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

#ifndef TEST_MAC_TEST_H
#define TEST_MAC_TEST_H

#include "../test.h"

struct vector
{
	unsigned int tag_len;
	unsigned int key_len;
	unsigned int message_len;
	unsigned int message_repeat;
	unsigned int rounds;
	const char *key;
	const char *message;
	const char *tag;
};

int test
(
	const char *file,
	unsigned int line,
	const kripto_desc_mac *desc,
	const struct vector *vectors,
	unsigned int vectors_len
);
#define TEST(DESC, VECTORS, VECTORS_LEN) test(__FILE__, __LINE__, DESC, VECTORS, VECTORS_LEN)

int test
(
	const char *file,
	unsigned int line,
	const kripto_desc_mac *desc,
	const struct vector *vectors,
	unsigned int vectors_len
)
{
	for(unsigned int i = 0; i < vectors_len; i++)
	{
		char t[vectors[i].tag_len];

		kripto_mac *s = kripto_mac_create
		(
			desc, vectors[i].rounds,
			vectors[i].key, vectors[i].key_len,
			vectors[i].tag_len
		);
		if(!s) test_error(file, line, "Create vector %u", i);

		for(unsigned int r = 0; r < vectors[i].message_repeat; r++)
		{
			kripto_mac_input(s, vectors[i].message, vectors[i].message_len);
		}

		kripto_mac_tag(s, t, vectors[i].tag_len);
		test_cmp(t, vectors[i].tag, vectors[i].tag_len, file, line, "Tag vector %u", i);

		s = kripto_mac_recreate
		(
			s, vectors[i].rounds,
			vectors[i].key, vectors[i].key_len,
			vectors[i].tag_len
		);

		for(unsigned int r = 0; r < vectors[i].message_repeat; r++)
		{
			kripto_mac_input(s, vectors[i].message, vectors[i].message_len);
		}

		if(kripto_mac_verify(s, vectors[i].tag, vectors[i].tag_len))
		{
			test_pass(file, line, "Verify vector %u", i);
		}
		else
		{
			test_fail(file, line, "Verify vector %u", i);
		}

		kripto_mac_destroy(s);

		if(vectors[i].message_repeat == 1)
		{
			if(kripto_mac_all
			(
				desc, vectors[i].rounds,
				vectors[i].key, vectors[i].key_len,
				vectors[i].message, vectors[i].message_len,
				t, vectors[i].tag_len
			)) test_error(file, line, "MAC vector %u", i);
			test_cmp(t, vectors[i].tag, vectors[i].tag_len, file, line, "MAC vector %u", i);
		}
	}

	return test_result;
}

#endif
