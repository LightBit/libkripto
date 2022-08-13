#ifndef KRIPTO_MAC_DESC_H
#define KRIPTO_MAC_DESC_H

struct kripto_desc_mac
{
	kripto_mac *(*create)
	(
		const kripto_desc_mac *,
		unsigned int,
		const void *,
		unsigned int,
		unsigned int
	);

	kripto_mac *(*recreate)
	(
		kripto_mac *,
		unsigned int,
		const void *,
		unsigned int,
		unsigned int
	);

	void (*input)(kripto_mac *, const void *, size_t);

	void (*tag)(kripto_mac *, void *, unsigned int);

	void (*destroy)(kripto_mac *);

	unsigned int maxtag;
	unsigned int maxkey;
};

#endif
