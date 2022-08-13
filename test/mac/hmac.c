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
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <kripto/mac.h>
#include <kripto/mac/hmac.h>
#include <kripto/hash/sha1.h>
#include <kripto/hash/sha2_256.h>

int main(void)
{
	kripto_desc_mac *desc;
	uint8_t hash[32];
	unsigned int i;

	/* SHA1 */
	desc = kripto_mac_hmac(kripto_hash_sha1);
	if(!desc) return -1;

	puts("de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9");
	kripto_mac_all(
		desc, 0,
		"key", 3,
		"The quick brown fox jumps over the lazy dog", 43,
		hash, 20
	);

	free(desc);

	for(i = 0; i < 20; i++) printf("%.2x", hash[i]);
	putchar('\n');

	/* SHA2_256 */
	desc = kripto_mac_hmac(kripto_hash_sha2_256);
	if(!desc) return -1;

	puts("f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8");
	kripto_mac_all(
		desc, 0,
		"key", 3,
		"The quick brown fox jumps over the lazy dog", 43,
		hash, 32
	);

	free(desc);

	for(i = 0; i < 32; i++) printf("%.2x", hash[i]);
	putchar('\n');

	return 0;
}
