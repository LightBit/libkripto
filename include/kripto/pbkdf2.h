#ifndef KRIPTO_PBKDF2_H
#define KRIPTO_PBKDF2_H

extern int kripto_pbkdf2
(
	const kripto_desc_mac *mac,
	unsigned int mac_rounds,
	unsigned int iter,
	const void *pass,
	unsigned int pass_len,
	const void *salt,
	unsigned int salt_len,
	void *out,
	size_t out_len
);

#endif
