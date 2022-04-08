/*
 * Written in 2013 by Gregor Pintar <grpintar@gmail.com>
 *
 * To the extent possible under law, the author(s) have dedicated
 * all copyright and related and neighboring rights to this software
 * to the public domain worldwide.
 * 
 * This software is distributed without any warranty.
 *
 * You should have received a copy of the CC0 Public Domain Dedication.
 * If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
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
