#ifndef KRIPTO_BLOCK_H
#define KRIPTO_BLOCK_H

typedef struct kripto_desc_block kripto_desc_block;
typedef struct kripto_block kripto_block;

extern kripto_block *kripto_block_create
(
	const kripto_desc_block *desc,
	unsigned int rounds,
	const void *key,
	unsigned int key_len
);

extern kripto_block *kripto_block_recreate
(
	kripto_block *s,
	unsigned int rounds,
	const void *key,
	unsigned int key_len
);

extern void kripto_block_tweak
(
	kripto_block *s,
	const void *tweak,
	unsigned int len
);

extern void kripto_block_encrypt
(
	const kripto_block *s,
	const void *pt,
	void *ct
);

extern void kripto_block_decrypt
(
	const kripto_block *s,
	const void *ct,
	void *pt
);

extern void kripto_block_destroy(kripto_block *s);

extern const kripto_desc_block *kripto_block_getdesc(const kripto_block *s);

extern unsigned int kripto_block_size(const kripto_desc_block *desc);

extern unsigned int kripto_block_maxkey(const kripto_desc_block *desc);

extern unsigned int kripto_block_maxtweak(const kripto_desc_block *desc);

#endif
