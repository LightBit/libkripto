#ifndef KRIPTO_BLOCK_DESC_H
#define KRIPTO_BLOCK_DESC_H

struct kripto_desc_block
{
	kripto_block *(*create)
	(
		const kripto_desc_block *const desc,
		unsigned int,
		const void *,
		unsigned int
	);

	kripto_block *(*recreate)
	(
		kripto_block *,
		unsigned int,
		const void *,
		unsigned int
	);

	void (*tweak)
	(
		kripto_block *,
		const void *,
		unsigned int
	);

	void (*encrypt)(const kripto_block *, const void *, void *);

	void (*decrypt)(const kripto_block *, const void *, void *);

	void (*destroy)(kripto_block *);

	unsigned int blocksize;
	unsigned int maxkey;
	unsigned int maxtweak;
};

#endif
