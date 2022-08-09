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
#include <stdint.h>
#include <string.h>

#include <kripto/hash.h>
#include <kripto/hash/tiger.h>

int main(void)
{
	uint8_t hash[24];
	unsigned int i;

	puts("3293ac630c13f0245f92bbb1766e16167a4e58492dde73f3");
	kripto_hash_all(kripto_hash_tiger, 0, 0, 0, "", 0, hash, 24);
	for(i = 0; i < 24; i++) printf("%.2x", hash[i]);
	putchar('\n');

	puts("6d12a41e72e644f017b6f0e2f7b44c6285f06dd5d2c5b075");
	kripto_hash_all(kripto_hash_tiger, 0, 0, 0, "The quick brown fox jumps over the lazy dog", 43, hash, 24);
	for(i = 0; i < 24; i++) printf("%.2x", hash[i]);
	putchar('\n');

	return 0;
}
