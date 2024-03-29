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

#ifndef KRIPTO_LOADSTORE_H
#define KRIPTO_LOADSTORE_H

#if defined(KRIPTO_LITTLE_ENDIAN) || defined(KRIPTO_BIG_ENDIAN)
#include <string.h>
#endif

#include <kripto/cast.h>

/* 16-bit */

static inline uint16_t LOAD16L(const void *src)
{
	#ifdef KRIPTO_LITTLE_ENDIAN
	uint16_t t;
	memcpy(&t, src, 2);
	return t;
	#else
	return (uint16_t)CU8(src)[0]
		| ((uint16_t)CU8(src)[1] << 8);
	#endif
}

static inline uint16_t LOAD16B(const void *src)
{
	#ifdef KRIPTO_BIG_ENDIAN
	uint16_t t;
	memcpy(&t, src, 2);
	return t;
	#else
	return (uint16_t)CU8(src)[1]
		| ((uint16_t)CU8(src)[0] << 8);
	#endif
}

static inline void LOAD16L_ARRAY(const void *src, uint16_t *dst, unsigned int bytes)
{
	#ifdef KRIPTO_LITTLE_ENDIAN
	memcpy(dst, src, bytes);
	#else
	for(unsigned int i = 0; i < bytes; i++)
	{
		dst[i >> 1] |= (uint16_t)CU8(src)[i] << ((i & 1) << 3);
	}
	#endif
}

static inline void LOAD16B_ARRAY(const void *src, uint16_t *dst, unsigned int bytes)
{
	#ifdef KRIPTO_BIG_ENDIAN
	memcpy(dst, src, bytes);
	#else
	for(unsigned int i = 0; i < bytes; i++)
	{
		dst[i >> 1] |= (uint16_t)CU8(src)[i] << (8 - ((i & 1) << 3));
	}
	#endif
}

static inline void STORE16L(const uint16_t src, void *dst)
{
	#ifdef KRIPTO_LITTLE_ENDIAN
	memcpy(dst, &src, 2);
	#else
	U8(dst)[0] = (const uint8_t)(src);
	U8(dst)[1] = (const uint8_t)(src >> 8);
	#endif
}

static inline void STORE16B(const uint16_t src, void *dst)
{
	#ifdef KRIPTO_BIG_ENDIAN
	memcpy(dst, &src, 2);
	#else
	U8(dst)[1] = (const uint8_t)(src);
	U8(dst)[0] = (const uint8_t)(src >> 8);
	#endif
}

static inline void STORE16L_ARRAY(const uint16_t *src, unsigned int src_byte, void *dst, unsigned int bytes)
{
	#ifdef KRIPTO_LITTLE_ENDIAN
	memcpy(dst, CU8(src) + src_byte, bytes);
	#else
	for(unsigned int i = 0; i < bytes; src_byte++, i++)
	{
		U8(dst)[i] = src[src_byte >> 1] >> ((src_byte & 1) << 3);
	}
	#endif
}

static inline void STORE16B_ARRAY(const uint16_t *src, unsigned int src_byte, void *dst, unsigned int bytes)
{
	#ifdef KRIPTO_BIG_ENDIAN
	memcpy(dst, CU8(src) + src_byte, bytes);
	#else
	for(unsigned int i = 0; i < bytes; src_byte++, i++)
	{
		U8(dst)[i] = src[src_byte >> 1] >> (8 - ((src_byte & 1) << 3));
	}
	#endif
}


/* 32-bit */

static inline uint32_t LOAD32L(const void *src)
{
	#ifdef KRIPTO_LITTLE_ENDIAN
	uint32_t t;
	memcpy(&t, src, 4);
	return t;
	#else
	return (uint32_t)CU8(src)[0]
		| ((uint32_t)CU8(src)[1] << 8)
		| ((uint32_t)CU8(src)[2] << 16)
		| ((uint32_t)CU8(src)[3] << 24);
	#endif
}

static inline uint32_t LOAD32B(const void *src)
{
	#ifdef KRIPTO_BIG_ENDIAN
	uint32_t t;
	memcpy(&t, src, 4);
	return t;
	#else
	return (uint32_t)CU8(src)[3]
		| ((uint32_t)CU8(src)[2] << 8)
		| ((uint32_t)CU8(src)[1] << 16)
		| ((uint32_t)CU8(src)[0] << 24);
	#endif
}

static inline void LOAD32L_ARRAY(const void *src, uint32_t *dst, unsigned int bytes)
{
	#ifdef KRIPTO_LITTLE_ENDIAN
	memcpy(dst, src, bytes);
	#else
	for(unsigned int i = 0; i < bytes; i++)
	{
		dst[i >> 2] |= (uint32_t)CU8(src)[i] << ((i & 3) << 3);
	}
	#endif
}

static inline void LOAD32B_ARRAY(const void *src, uint32_t *dst, unsigned int bytes)
{
	#ifdef KRIPTO_BIG_ENDIAN
	memcpy(dst, src, bytes);
	#else
	for(unsigned int i = 0; i < bytes; i++)
	{
		dst[i >> 2] |= (uint32_t)CU8(src)[i] << (24 - ((i & 3) << 3));
	}
	#endif
}

static inline void STORE32L(const uint32_t src, void *dst)
{
	#ifdef KRIPTO_LITTLE_ENDIAN
	memcpy(dst, &src, 4);
	#else
	U8(dst)[0] = (const uint8_t)(src);
	U8(dst)[1] = (const uint8_t)(src >> 8);
	U8(dst)[2] = (const uint8_t)(src >> 16);
	U8(dst)[3] = (const uint8_t)(src >> 24);
	#endif
}

static inline void STORE32B(const uint32_t src, void *dst)
{
	#ifdef KRIPTO_BIG_ENDIAN
	memcpy(dst, &src, 4);
	#else
	U8(dst)[3] = (const uint8_t)(src);
	U8(dst)[2] = (const uint8_t)(src >> 8);
	U8(dst)[1] = (const uint8_t)(src >> 16);
	U8(dst)[0] = (const uint8_t)(src >> 24);
	#endif
}

static inline void STORE32L_ARRAY(const uint32_t *src, unsigned int src_byte, void *dst, unsigned int bytes)
{
	#ifdef KRIPTO_LITTLE_ENDIAN
	memcpy(dst, CU8(src) + src_byte, bytes);
	#else
	for(unsigned int i = 0; i < bytes; src_byte++, i++)
	{
		U8(dst)[i] = src[src_byte >> 2] >> ((src_byte & 3) << 3);
	}
	#endif
}

static inline void STORE32B_ARRAY(const uint32_t *src, unsigned int src_byte, void *dst, unsigned int bytes)
{
	#ifdef KRIPTO_BIG_ENDIAN
	memcpy(dst, CU8(src) + src_byte, bytes);
	#else
	for(unsigned int i = 0; i < bytes; src_byte++, i++)
	{
		U8(dst)[i] = src[src_byte >> 2] >> (24 - ((src_byte & 3) << 3));
	}
	#endif
}


/* 64-bit */

static inline uint64_t LOAD64L(const void *src)
{
	#ifdef KRIPTO_LITTLE_ENDIAN
	uint64_t t;
	memcpy(&t, src, 8);
	return t;
	#else
	return (uint64_t)CU8(src)[0]
		| ((uint64_t)CU8(src)[1] << 8)
		| ((uint64_t)CU8(src)[2] << 16)
		| ((uint64_t)CU8(src)[3] << 24)
		| ((uint64_t)CU8(src)[4] << 32)
		| ((uint64_t)CU8(src)[5] << 40)
		| ((uint64_t)CU8(src)[6] << 48)
		| ((uint64_t)CU8(src)[7] << 56);
	#endif
}

static inline uint64_t LOAD64B(const void *src)
{
	#ifdef KRIPTO_BIG_ENDIAN
	uint64_t t;
	memcpy(&t, src, 8);
	return t;
	#else
	return (uint64_t)CU8(src)[7]
		| ((uint64_t)CU8(src)[6] << 8)
		| ((uint64_t)CU8(src)[5] << 16)
		| ((uint64_t)CU8(src)[4] << 24)
		| ((uint64_t)CU8(src)[3] << 32)
		| ((uint64_t)CU8(src)[2] << 40)
		| ((uint64_t)CU8(src)[1] << 48)
		| ((uint64_t)CU8(src)[0] << 56);
	#endif
}

static inline void LOAD64L_ARRAY(const void *src, uint64_t *dst, unsigned int bytes)
{
	#ifdef KRIPTO_LITTLE_ENDIAN
	memcpy(dst, src, bytes);
	#else
	for(unsigned int i = 0; i < bytes; i++)
	{
		dst[i >> 3] |= (uint64_t)CU8(src)[i] << ((i & 7) << 3);
	}
	#endif
}

static inline void LOAD64B_ARRAY(const void *src, uint64_t *dst, unsigned int bytes)
{
	#ifdef KRIPTO_BIG_ENDIAN
	memcpy(dst, src, bytes);
	#else
	for(unsigned int i = 0; i < bytes; i++)
	{
		dst[i >> 3] |= (uint64_t)CU8(src)[i] << (56 - ((i & 7) << 3));
	}
	#endif
}

static inline void STORE64L(const uint64_t src, void *dst)
{
	#ifdef KRIPTO_LITTLE_ENDIAN
	memcpy(dst, &src, 8);
	#else
	U8(dst)[0] = (const uint8_t)(src);
	U8(dst)[1] = (const uint8_t)(src >> 8);
	U8(dst)[2] = (const uint8_t)(src >> 16);
	U8(dst)[3] = (const uint8_t)(src >> 24);
	U8(dst)[4] = (const uint8_t)(src >> 32);
	U8(dst)[5] = (const uint8_t)(src >> 40);
	U8(dst)[6] = (const uint8_t)(src >> 48);
	U8(dst)[7] = (const uint8_t)(src >> 56);
	#endif
}

static inline void STORE64B(const uint64_t src, void *dst)
{
	#ifdef KRIPTO_BIG_ENDIAN
	memcpy(dst, &src, 8);
	#else
	U8(dst)[7] = (const uint8_t)(src);
	U8(dst)[6] = (const uint8_t)(src >> 8);
	U8(dst)[5] = (const uint8_t)(src >> 16);
	U8(dst)[4] = (const uint8_t)(src >> 24);
	U8(dst)[3] = (const uint8_t)(src >> 32);
	U8(dst)[2] = (const uint8_t)(src >> 40);
	U8(dst)[1] = (const uint8_t)(src >> 48);
	U8(dst)[0] = (const uint8_t)(src >> 56);
	#endif
}

static inline void STORE64L_ARRAY(const uint64_t *src, unsigned int src_byte, void *dst, unsigned int bytes)
{
	#ifdef KRIPTO_LITTLE_ENDIAN
	memcpy(dst, CU8(src) + src_byte, bytes);
	#else
	for(unsigned int i = 0; i < bytes; src_byte++, i++)
	{
		U8(dst)[i] = src[src_byte >> 3] >> ((src_byte & 7) << 3);
	}
	#endif
}

static inline void STORE64B_ARRAY(const uint64_t *src, unsigned int src_byte, void *dst, unsigned int bytes)
{
	#ifdef KRIPTO_BIG_ENDIAN
	memcpy(dst, CU8(src) + src_byte, bytes);
	#else
	for(unsigned int i = 0; i < bytes; src_byte++, i++)
	{
		U8(dst)[i] = src[src_byte >> 3] >> (56 - ((src_byte & 7) << 3));
	}
	#endif
}

#endif
