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

#include <stddef.h>
#include <stdint.h>

#include <kripto/pkcs7.h>

#include "test.h"

int main(void)
{
	uint8_t buf[16] = {0x10, 0x20, 0x30, 0x40, 0x50};
	const uint8_t data[5] = {0x10, 0x20, 0x30, 0x40, 0x50};
	const uint8_t padding[3] = {0x03, 0x03, 0x03};
	size_t len;

	len = kripto_pkcs7_add(buf, sizeof data, 8, sizeof buf);
	if(len != 8) TEST_FAIL("PKCS#7 add returned %zu, expected 8", len);
	TEST_CMP(buf, data, sizeof data, "PKCS#7 preserves input");
	TEST_CMP(buf + sizeof data, padding, sizeof padding, "PKCS#7 adds padding bytes");
	if(kripto_pkcs7_rem(buf, len) != sizeof data)
		TEST_FAIL("PKCS#7 rem did not restore input length");

	len = kripto_pkcs7_add(buf, 8, 8, sizeof buf);
	if(len != 16) TEST_FAIL("PKCS#7 add did not add a full block to aligned input");
	if(kripto_pkcs7_rem(buf, len) != 8)
		TEST_FAIL("PKCS#7 rem did not remove full-block padding");

	memset(buf, 0xA5, sizeof buf);
	if(kripto_pkcs7_add(buf, 5, 8, 7) != 0)
		TEST_FAIL("PKCS#7 add accepted insufficient capacity");
	for(size_t i = 0; i < sizeof buf; i++)
		if(buf[i] != 0xA5)
			TEST_FAIL("PKCS#7 add modified buffer on insufficient capacity");

	if(kripto_pkcs7_rem(buf, 0) != 0)
		TEST_FAIL("PKCS#7 rem did not return zero for empty input");

	return test_result;
}