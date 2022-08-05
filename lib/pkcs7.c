/*
 * Copyright (C) 2011 by Gregor Pintar <grpintar@gmail.com>
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
#include <stdint.h>

#include <kripto/cast.h>

#include <kripto/pkcs7.h>

size_t kripto_pkcs7_add
(
	void *buf,
	size_t len,
	unsigned int pad,
	size_t maxlen
)
{
	unsigned int i;

	pad = pad - (len & (pad - 1));

	if(pad + len > maxlen) return 0;

	for(i = 0; i < pad; i++)
		U8(buf)[len + i] = pad;

	return (len + pad);
}

size_t kripto_pkcs7_rem(void *buf, size_t len)
{
	if(U8(buf)[len - 1] < len)
		return (len - U8(buf)[len - 1]);
	else
		return len;
}
