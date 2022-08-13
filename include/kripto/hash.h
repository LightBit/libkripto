#ifndef KRIPTO_HASH_H
#define KRIPTO_HASH_H

#include <stddef.h>

typedef struct kripto_desc_hash kripto_desc_hash;
typedef struct kripto_hash kripto_hash;

extern kripto_hash *kripto_hash_create
(
	const kripto_desc_hash *desc,
	unsigned int rounds,
	const void *salt,
	unsigned int salt_len,
	unsigned int out_len
);

extern kripto_hash *kripto_hash_recreate
(
	kripto_hash *s,
	unsigned int rounds,
	const void *salt,
	unsigned int salt_len,
	unsigned int out_len
);

extern void kripto_hash_input
(
	kripto_hash *s,
	const void *in,
	size_t len
);

extern void kripto_hash_output
(
	kripto_hash *s,
	void *out,
	size_t len
);

extern void kripto_hash_destroy(kripto_hash *s);

extern int kripto_hash_all
(
	const kripto_desc_hash *desc,
	unsigned int rounds,
	const void *salt,
	unsigned int salt_len,
	const void *in,
	size_t in_len,
	void *out,
	size_t out_len
);

extern const kripto_desc_hash *kripto_hash_getdesc(const kripto_hash *s);

extern unsigned int kripto_hash_maxout(const kripto_desc_hash *desc);

extern unsigned int kripto_hash_maxsalt(const kripto_desc_hash *desc);

extern unsigned int kripto_hash_blocksize(const kripto_desc_hash *desc);

#endif
