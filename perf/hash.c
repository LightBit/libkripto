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

/* cc -Wall -Wextra -std=c99 -pedantic perf/hash.c -Iinclude lib/libkripto.a -O2 -DPERF_UNIX -D_GNU_SOURCE */
/* cc -Wall -Wextra -std=c99 -pedantic perf/hash.c -Iinclude lib/libkripto.a -O2 -DPERF_WINDOWS /lib/w32api/libpowrprof.a */

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <kripto/hash.h>

#include <kripto/hash/blake256.h>
#include <kripto/hash/blake512.h>
#include <kripto/hash/blake2s.h>
#include <kripto/hash/blake2b.h>
#include <kripto/hash/keccak800.h>
#include <kripto/hash/keccak1600.h>
#include <kripto/hash/md5.h>
#include <kripto/hash/sha1.h>
#include <kripto/hash/sha2_256.h>
#include <kripto/hash/sha2_512.h>
#include <kripto/hash/sha3.h>
#include <kripto/hash/skein256.h>
#include <kripto/hash/skein512.h>
#include <kripto/hash/skein1024.h>
#include <kripto/hash/tiger.h>
#include <kripto/hash/whirlpool.h>

#include "perf.h"

#define INPUT_LEN 1000

int main(void)
{
	struct
	{
		const char *name;
		const kripto_desc_hash *desc;
		unsigned int out_len;
	} hashes[20] =
	{
		{"BLAKE-256", kripto_hash_blake256, 32},
		{"BLAKE-512", kripto_hash_blake512, 64},
		{"BLAKE2s", kripto_hash_blake2s, 32},
		{"BLAKE2b", kripto_hash_blake2b, 64},
		{"Keccak800-128", kripto_hash_keccak800, 16},
		{"Keccak800-256", kripto_hash_keccak800, 32},
		{"Keccak1600-128", kripto_hash_keccak1600, 16},
		{"Keccak1600-256", kripto_hash_keccak1600, 32},
		{"Keccak1600-512", kripto_hash_keccak1600, 64},
		{"MD5", kripto_hash_md5, 16},
		{"SHA1", kripto_hash_sha1, 20},
		{"SHA2-256", kripto_hash_sha2_256, 32},
		{"SHA2-512", kripto_hash_sha2_512, 64},
		{"SHA3-256", kripto_hash_sha3, 32},
		{"SHA3-512", kripto_hash_sha3, 64},
		{"Skein256", kripto_hash_skein256, 32},
		{"Skein512", kripto_hash_skein512, 64},
		{"Skein1024", kripto_hash_skein1024, 128},
		{"Tiger", kripto_hash_tiger, 24},
		{"WHIRLPOOL", kripto_hash_whirlpool, 64}
	};
	perf_int cycles;
	uint8_t t[INPUT_LEN];

	perf_init();

	memset(t, 0x5A, INPUT_LEN);

	for(unsigned int i = 0; i < 20; i++)
	{
		kripto_hash *s = kripto_hash_create
		(
			hashes[i].desc,
			0, 0, 0,
			hashes[i].out_len
		);

		PERF_START
		s = kripto_hash_recreate(s, 0, 0, 0, hashes[i].out_len);
		kripto_hash_input(s, t, INPUT_LEN);
		kripto_hash_output(s, t, hashes[i].out_len);
		PERF_STOP

		printf("%s: %.1f cpb\n", hashes[i].name, cycles / (float)INPUT_LEN);

		kripto_hash_destroy(s);

		perf_rest();
		fflush(stdout);
	}

	return 0;
}
