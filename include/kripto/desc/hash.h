#ifndef KRIPTO_HASH_DESC_H
#define KRIPTO_HASH_DESC_H

struct kripto_desc_hash
{
	kripto_hash *(*create)
	(
		const kripto_desc_hash *,
		unsigned int,
		const void *,
		unsigned int,
		unsigned int
	);

	kripto_hash *(*recreate)
	(
		kripto_hash *,
		unsigned int,
		const void *,
		unsigned int,
		unsigned int
	);

	void (*input)(kripto_hash *, const void *, size_t);

	void (*output)(kripto_hash *, void *, size_t);

	void (*destroy)(kripto_hash *);

	int (*hash_all)
	(
		const kripto_desc_hash *,
		const unsigned int,
		const void *,
		unsigned int,
		const void *,
		size_t,
		void *,
		size_t
	);

	unsigned int maxout;
	unsigned int blocksize;
	unsigned int maxsalt;
};

#endif
