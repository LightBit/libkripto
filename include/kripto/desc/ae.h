#ifndef KRIPTO_AE_DESC_H
#define KRIPTO_AE_DESC_H

#include <stddef.h>

struct kripto_desc_ae
{
	kripto_ae *(*create)
	(
		const kripto_desc_ae *,
		unsigned int,
		const void *,
		unsigned int,
		const void *,
		unsigned int,
		unsigned int
	);

	kripto_ae *(*recreate)
	(
		kripto_ae *,
		unsigned int,
		const void *,
		unsigned int,
		const void *,
		unsigned int,
		unsigned int
	);

	void (*encrypt)
	(
		kripto_ae *,
		const void *,
		void *,
		size_t
	);

	void (*decrypt)
	(
		kripto_ae *,
		const void *,
		void *,
		size_t
	);

	void (*header)(kripto_ae *, const void *, size_t);

	void (*tag)(kripto_ae *, void *, unsigned int);

	void (*destroy)(kripto_ae *);

	unsigned int maxkey;
	unsigned int maxiv;
	unsigned int maxtag;
};

#endif
