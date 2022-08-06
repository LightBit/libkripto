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

/* gcc -Wall -Wextra -std=c99 -pedantic perf/hash.c -Iinclude lib/libkripto.a -O2 -DPERF_UNIX -D_GNU_SOURCE */
/* gcc -Wall -Wextra -std=c99 -pedantic perf/hash.c -Iinclude lib/libkripto.a -O2 -DPERF_WINDOWS /lib/w32api/libpowrprof.a */

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <kripto/hash.h>

#include <kripto/hash/sha2_256.h>

#include "perf.h"

#define MAXBLOCK 255

int main(void)
{
	unsigned int n;
	unsigned int hash;
	uint8_t t[MAXBLOCK];
	perf_int cycles;
	struct
	{
		const char *name;
		const kripto_hash_desc *desc;
	} hashes[1] =
	{
		{"SHA-2 256", kripto_hash_sha2_256}
	};

	memset(t, 0, MAXBLOCK);

	perf_init();

	for(hash = 0; hash < 1; hash++)
	{
		if(!hashes[hash].desc) continue;
		
		kripto_hash_all(hashes[hash].desc, 0, t, 32, t, 32);

		for(n = 0; n < 3; n++)
		{
			PERF_START
			kripto_hash_all(hashes[hash].desc, 0, t, 32, t, 32);
			PERF_STOP

			printf("%s: %lu cycles\n", hashes[hash].name, cycles);

			//perf_rest();
			//fflush(stdout);
			//putchar('\n');
		}
	}

	return 0;
}
