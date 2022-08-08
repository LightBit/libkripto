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

#include <stddef.h>

#include <kripto/memory.h>

void kripto_memory_wipe(void *dst, size_t len)
{
	volatile unsigned char *x = (volatile unsigned char *)dst;

	while(len--) *x++ = '\0';
}

unsigned char kripto_memory_equals(const void *a, const void *b, size_t len)
{
	const volatile unsigned char *ax = (const volatile unsigned char *)a;
	const volatile unsigned char *bx = (const volatile unsigned char *)b;
	volatile unsigned char x = 0;

	for (size_t i = 0; i < len; i++)
	{
		x |= ax[i] ^ bx[i];
	}

	return !x;
}
