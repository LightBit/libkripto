/*
 * Copyright (C) 2026 by Gregor Pintar <grpintar@gmail.com>
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

#include <kripto/stream.h>
#include <kripto/stream/rc4.h>

#include "test.h"

int main(void)
{
	/*
	 * RFC 6229 RC4 test vectors (key length 40 bits, key 0x0102030405).
	 * https://datatracker.ietf.org/doc/html/rfc6229
	 * rounds = 0 selects plain RC4 (no keystream drop); with an all-zero
	 * plaintext the ciphertext equals the keystream. This covers the first
	 * 32 keystream bytes (offset 0..31).
	 */
	const struct vector vectors[1] =
	{
		{
			.rounds = 0,
			.key = "\x01\x02\x03\x04\x05",
			.key_len = 5,
			.iv = 0,
			.iv_len = 0,
			.pt = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
				"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
			.pt_len = 32,
			.ct = "\xB2\x39\x63\x05\xF0\x3D\xC0\x27\xCC\xC3\x52\x4A\x0A\x11\x18\xA8"
				"\x69\x82\x94\x4F\x18\xFC\x82\xD5\x89\xC4\x03\xA4\x7A\x0D\x09\x19",
			.ct_len = 32
		}
	};

	return TEST(kripto_stream_rc4, vectors, 1);
}
