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

/* cc -Wall -Wextra -std=c99 -pedantic perf/block.c -Iinclude lib/libkripto.a -O2 -DPERF_UNIX -D_GNU_SOURCE */
/* cc -Wall -Wextra -std=c99 -pedantic perf/block.c -Iinclude lib/libkripto.a -O2 -DPERF_WINDOWS /lib/w32api/libpowrprof.a */

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <kripto/block.h>

#include <kripto/block/3way.h>
#include <kripto/block/anubis.h>
#include <kripto/block/aria.h>
#include <kripto/block/blowfish.h>
#include <kripto/block/camellia.h>
#include <kripto/block/cast5.h>
#include <kripto/block/des.h>
#include <kripto/block/gost.h>
#include <kripto/block/idea.h>
#include <kripto/block/khazad.h>
#include <kripto/block/lea.h>
#include <kripto/block/noekeon.h>
#include <kripto/block/rc2.h>
#include <kripto/block/rc5.h>
#include <kripto/block/rc6.h>
#include <kripto/block/rijndael128.h>
#include <kripto/block/rijndael256.h>
#include <kripto/block/safer.h>
#include <kripto/block/safer_sk.h>
#include <kripto/block/saferpp.h>
#include <kripto/block/seed.h>
#include <kripto/block/serpent.h>
#include <kripto/block/shacal2.h>
#include <kripto/block/simon32.h>
#include <kripto/block/simon64.h>
#include <kripto/block/simon128.h>
#include <kripto/block/skipjack.h>
#include <kripto/block/sm4.h>
#include <kripto/block/speck32.h>
#include <kripto/block/speck64.h>
#include <kripto/block/speck128.h>
#include <kripto/block/tea.h>
#include <kripto/block/threefish256.h>
#include <kripto/block/threefish512.h>
#include <kripto/block/threefish1024.h>
#include <kripto/block/twofish.h>
#include <kripto/block/xtea.h>

#include "perf.h"

#ifndef KEYSTART
#define KEYSTART 16
#endif

#ifndef KEYSTEP
#define KEYSTEP 8
#endif

#define MAXKEY 32

static void die(const char *str)
{
	perror(str);
	exit(-1);
}

int main(void)
{
	struct
	{
		const char *name;
		const kripto_block_desc *desc;
	} ciphers[37] =
	{
		{"3-Way", kripto_block_3way},
		{"Anubis", kripto_block_anubis},
		{"ARIA", kripto_block_aria},
		{"Blowfish", kripto_block_blowfish},
		{"Camellia", kripto_block_camellia},
		{"CAST5", kripto_block_cast5},
		{"DES", kripto_block_des},
		{"GOST 28147-89", kripto_block_gost_r34_12_2015()},
		{"IDEA", kripto_block_idea},
		{"KHAZAD", kripto_block_khazad},
		{"LEA", kripto_block_khazad},
		{"Noekeon", kripto_block_noekeon},
		{"RC2", kripto_block_rc2},
		{"RC5", kripto_block_rc5},
		{"RC6", kripto_block_rc6},
		{"Rijndael-128", kripto_block_rijndael128},
		{"Rijndael-256", kripto_block_rijndael256},
		{"SAFER", kripto_block_safer},
		{"SAFER-SK", kripto_block_safer_sk},
		{"SAFER++", kripto_block_saferpp},
		{"SEED", kripto_block_seed},
		{"Serpent", kripto_block_serpent},
		{"SHACAL-2", kripto_block_shacal2},
		{"Simon32", kripto_block_simon32},
		{"Simon64", kripto_block_simon64},
		{"Simon128", kripto_block_simon128},
		{"Skipjack", kripto_block_skipjack},
		{"SM4", kripto_block_sm4},
		{"Speck32", kripto_block_speck32},
		{"Speck64", kripto_block_speck64},
		{"Speck128", kripto_block_speck128},
		{"TEA", kripto_block_tea},
		{"Threefish-256", kripto_block_threefish256},
		{"Threefish-512", kripto_block_threefish512},
		{"Threefish-1024", kripto_block_threefish1024},
		{"Twofish", kripto_block_twofish},
		{"XTEA", kripto_block_xtea}
	};
	perf_int cycles;

	perf_init();

	uint8_t k[MAXKEY];
	memset(k, 0x5A, MAXKEY);

	for(unsigned int i = 0; i < 37; i++)
	{
		puts(ciphers[i].name);

		unsigned int maxkey = kripto_block_maxkey(ciphers[i].desc);
		if(maxkey > MAXKEY) maxkey = MAXKEY;

		unsigned int minkey = kripto_block_maxkey(ciphers[i].desc);
		if(minkey > KEYSTART) minkey = KEYSTART;

		unsigned int size = kripto_block_size(ciphers[i].desc);
		uint8_t t[size];
		memset(t, 0, size);

		for(unsigned int n = minkey; n <= maxkey; n += KEYSTEP)
		{
			kripto_block *s = kripto_block_create(ciphers[i].desc, 0, k, n);
			if(!s) die("kripto_block_create()");

			/* setup */
			PERF_START
			s = kripto_block_recreate(s, 0, k, n);
			if(!s) die("kripto_block_recreate()");
			PERF_STOP

			printf("%u-bit setup: %lu cycles\n", n * 8, cycles);

			/* encrypt */
			PERF_START
			kripto_block_encrypt(s, t, t);
			PERF_STOP

			printf("%u-bit encrypt: %.1f cpb\n",
				n * 8, cycles / (float)size);

			/* decrypt */
			PERF_START
			kripto_block_decrypt(s, t, t);
			PERF_STOP

			printf("%u-bit decrypt: %.1f cpb\n",
				n * 8, cycles / (float)size);

			kripto_block_destroy(s);

			perf_rest();
			fflush(stdout);
			putchar('\n');
		}
		putchar('\n');
	}

	return 0;
}
