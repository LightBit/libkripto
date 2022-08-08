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

#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include <kripto/cast.h>
#include <kripto/memory.h>
#include <kripto/block.h>
#include <kripto/stream.h>
#include <kripto/stream/ctr.h>
#include <kripto/mac.h>
#include <kripto/mac/omac.h>
#include <kripto/ae.h>
#include <kripto/desc/ae.h>
#include <kripto/object/ae.h>

#include <kripto/ae/eax.h>

struct kripto_ae
{
	struct kripto_ae_object obj;
	kripto_stream_desc *ctr_desc;
	kripto_mac_desc *omac_desc;
	kripto_stream *ctr;
	kripto_mac *omac;
	kripto_mac *header;
	uint8_t *iv;
	unsigned int len;
};

static void eax_encrypt
(
	kripto_ae *s,
	const void *pt,
	void *ct,
	size_t len
)
{
	kripto_stream_encrypt(s->ctr, pt, ct, len);
	kripto_mac_input(s->omac, ct, len);
}

static void eax_decrypt
(
	kripto_ae *s,
	const void *ct,
	void *pt,
	size_t len
)
{
	kripto_mac_input(s->omac, ct, len);
	kripto_stream_decrypt(s->ctr, ct, pt, len);
}

static void eax_header
(
	kripto_ae *s,
	const void *header,
	size_t len
)
{
	kripto_mac_input(s->header, header, len);
}

static void eax_tag
(
	kripto_ae *s,
	void *tag,
	unsigned int len
)
{
	unsigned int i;

	kripto_mac_tag(s->omac, tag, len);
	for(i = 0; i < len; i++)
		U8(tag)[i] ^= s->iv[i];

	kripto_mac_tag(s->header, s->iv, len);
	for(i = 0; i < len; i++)
		U8(tag)[i] ^= s->iv[i];
}

static void eax_destroy(kripto_ae *s)
{
	kripto_stream_destroy(s->ctr);
	kripto_mac_destroy(s->omac);
	kripto_mac_destroy(s->header);

	kripto_memory_wipe(s->iv, s->len);

	free(s->ctr_desc);
	free(s->omac_desc);

	free(s);
}

struct ext
{
	kripto_ae_desc desc;
	const kripto_block_desc *block;
};

#define EXT(X) ((const struct ext *)(X))

static kripto_ae *eax_create
(
	const kripto_ae_desc *desc,
	unsigned int rounds,
	const void *key,
	unsigned int key_len,
	const void *iv,
	unsigned int iv_len,
	unsigned int tag_len
)
{
	kripto_ae *s;
	uint8_t *buf;
	unsigned int len;

	(void)tag_len;

	len = kripto_block_size(EXT(desc)->block);
	buf = (uint8_t *)malloc(len);
	if(!buf) goto err0;

	s = (kripto_ae *)malloc(sizeof(kripto_ae) + len);
	if(!s) goto err1;

	s->obj.desc = desc;
	s->obj.multof = 1;
	s->iv = (uint8_t *)s + sizeof(kripto_ae);
	s->len = len;

	/* create CTR descriptor */
	s->ctr_desc = kripto_stream_ctr(EXT(desc)->block);
	if(!s->ctr_desc) goto err2;

	/* create OMAC descriptor */
	s->omac_desc = kripto_mac_omac(EXT(desc)->block);
	if(!s->omac_desc) goto err3;

	/* OMAC IV (nonce) */
	s->omac = kripto_mac_create(s->omac_desc, rounds, key, key_len, len);
	if(!s->omac) goto err4;
	memset(buf, 0, len);
	kripto_mac_input(s->omac, buf, len);
	kripto_mac_input(s->omac, iv, iv_len);
	kripto_mac_tag(s->omac, s->iv, iv_len);

	/* recreate OMAC for encryption/decryption */
	s->omac = kripto_mac_recreate(s->omac, rounds, key, key_len, len);
	if(!s->omac) goto err5;
	buf[len - 1] = 2;
	kripto_mac_input(s->omac, buf, len);

	/* create CTR */
	s->ctr = kripto_stream_create(s->ctr_desc, rounds, key, key_len, s->iv, iv_len);
	if(!s->ctr) goto err6;

	/* create OMAC for header */
	s->header = kripto_mac_create(s->omac_desc, rounds, key, key_len, len);
	if(!s->header) goto err7;
	buf[len - 1] = 1;
	kripto_mac_input(s->header, buf, len);

	free(buf);

	return s;

err7: kripto_stream_destroy(s->ctr);
err6: kripto_mac_destroy(s->omac);
err5: kripto_memory_wipe(s->iv, len);
err4: free(s->omac_desc);
err3: free(s->ctr_desc);
err2: free(s);
err1: free(buf);
err0: return 0;
}

static kripto_ae *eax_recreate
(
	kripto_ae *s,
	unsigned int rounds,
	const void *key,
	unsigned int key_len,
	const void *iv,
	unsigned int iv_len,
	unsigned int tag_len
)
{
	uint8_t *buf;

	(void)tag_len;

	buf = (uint8_t *)malloc(s->len);
	if(!buf) goto err0;

	/* OMAC IV (nonce) */
	s->omac = kripto_mac_recreate(s->omac, rounds, key, key_len, s->len);
	if(!s->omac) goto err1;
	memset(buf, 0, s->len);
	kripto_mac_input(s->omac, buf, s->len);
	kripto_mac_input(s->omac, iv, iv_len);
	kripto_mac_tag(s->omac, s->iv, iv_len);

	/* recreate OMAC for encryption/decryption */
	s->omac = kripto_mac_recreate(s->omac, rounds, key, key_len, s->len);
	if(!s->omac) goto err1;
	buf[s->len - 1] = 2;
	kripto_mac_input(s->omac, buf, s->len);

	/* recreate CTR */
	s->ctr = kripto_stream_recreate(s->ctr, rounds, key, key_len, s->iv, iv_len);
	if(!s->ctr) goto err2;

	/* recreate OMAC for header */
	s->header = kripto_mac_recreate(s->header, rounds, key, key_len, s->len);
	if(!s->header) goto err3;
	buf[s->len - 1] = 1;
	kripto_mac_input(s->header, buf, s->len);

	free(buf);

	return s;

err3: kripto_stream_destroy(s->ctr);
err2: kripto_mac_destroy(s->omac);
err1: free(buf);
err0:
	free(s->ctr_desc);
	free(s->omac_desc);
	kripto_memory_wipe(s->iv, s->len);
	free(s);
	return 0;
}

kripto_ae_desc *kripto_ae_eax(const kripto_block_desc *block)
{
	struct ext *s = (struct ext *)malloc(sizeof(struct ext));
	if(!s) return 0;

	s->block = block;

	s->desc.create = &eax_create;
	s->desc.recreate = &eax_recreate;
	s->desc.encrypt = &eax_encrypt;
	s->desc.decrypt = &eax_decrypt;
	s->desc.header = &eax_header;
	s->desc.tag = &eax_tag;
	s->desc.destroy = &eax_destroy;
	s->desc.maxkey = kripto_block_maxkey(block);
	s->desc.maxiv = kripto_block_size(block);
	s->desc.maxtag = s->desc.maxiv;

	return (kripto_ae_desc *)s;
}
