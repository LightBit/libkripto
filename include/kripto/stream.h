#ifndef KRIPTO_STREAM_H
#define KRIPTO_STREAM_H

#include <stddef.h>

typedef struct kripto_desc_stream kripto_desc_stream;
typedef struct kripto_stream kripto_stream;

extern kripto_stream *kripto_stream_create
(
	const kripto_desc_stream *desc,
	unsigned int rounds,
	const void *key,
	unsigned int key_len,
	const void *iv,
	unsigned int iv_len
);

extern kripto_stream *kripto_stream_recreate
(
	kripto_stream *s,
	unsigned int rounds,
	const void *key,
	unsigned int key_len,
	const void *iv,
	unsigned int iv_len
);

extern void kripto_stream_encrypt
(
	kripto_stream *s,
	const void *pt,
	void *ct,
	size_t len
);

extern void kripto_stream_decrypt
(
	kripto_stream *s,
	const void *ct,
	void *pt,
	size_t len
);

extern void kripto_stream_prng
(
	kripto_stream *s,
	void *out,
	size_t len
);

extern void kripto_stream_destroy(kripto_stream *s);

extern unsigned int kripto_stream_multof(const kripto_stream *s);

extern const kripto_desc_stream *kripto_stream_getdesc(const kripto_stream *s);

extern unsigned int kripto_stream_maxkey(const kripto_desc_stream *desc);

extern unsigned int kripto_stream_maxiv(const kripto_desc_stream *desc);

#endif
