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
#include <stddef.h>
#include <stdlib.h>
#include <assert.h>

#include <kripto/cast.h>
#include <kripto/loadstore.h>
#include <kripto/rotate.h>
#include <kripto/memory.h>
#include <kripto/hash.h>
#include <kripto/desc/hash.h>

#include <kripto/hash/sha2_512.h>

struct kripto_hash
{
	const kripto_desc_hash *desc;
	uint64_t h[8];
	uint64_t len[2];
	uint8_t buf[128];
	unsigned int r;
	unsigned int i;
	int o;
};

static const uint64_t RC[160] =
{
	0x428A2F98D728AE22, 0x7137449123EF65CD,
	0xB5C0FBCFEC4D3B2F, 0xE9B5DBA58189DBBC,
	0x3956C25BF348B538, 0x59F111F1B605D019,
	0x923F82A4AF194F9B, 0xAB1C5ED5DA6D8118,
	0xD807AA98A3030242, 0x12835B0145706FBE,
	0x243185BE4EE4B28C, 0x550C7DC3D5FFB4E2,
	0x72BE5D74F27B896F, 0x80DEB1FE3B1696B1,
	0x9BDC06A725C71235, 0xC19BF174CF692694,
	0xE49B69C19EF14AD2, 0xEFBE4786384F25E3,
	0x0FC19DC68B8CD5B5, 0x240CA1CC77AC9C65,
	0x2DE92C6F592B0275, 0x4A7484AA6EA6E483,
	0x5CB0A9DCBD41FBD4, 0x76F988DA831153B5,
	0x983E5152EE66DFAB, 0xA831C66D2DB43210,
	0xB00327C898FB213F, 0xBF597FC7BEEF0EE4,
	0xC6E00BF33DA88FC2, 0xD5A79147930AA725,
	0x06CA6351E003826F, 0x142929670A0E6E70,
	0x27B70A8546D22FFC, 0x2E1B21385C26C926,
	0x4D2C6DFC5AC42AED, 0x53380D139D95B3DF,
	0x650A73548BAF63DE, 0x766A0ABB3C77B2A8,
	0x81C2C92E47EDAEE6, 0x92722C851482353B,
	0xA2BFE8A14CF10364, 0xA81A664BBC423001,
	0xC24B8B70D0F89791, 0xC76C51A30654BE30,
	0xD192E819D6EF5218, 0xD69906245565A910,
	0xF40E35855771202A, 0x106AA07032BBD1B8,
	0x19A4C116B8D2D0C8, 0x1E376C085141AB53,
	0x2748774CDF8EEB99, 0x34B0BCB5E19B48A8,
	0x391C0CB3C5C95A63, 0x4ED8AA4AE3418ACB,
	0x5B9CCA4F7763E373, 0x682E6FF3D6B2B8A3,
	0x748F82EE5DEFB2FC, 0x78A5636F43172F60,
	0x84C87814A1F0AB72, 0x8CC702081A6439EC,
	0x90BEFFFA23631E28, 0xA4506CEBDE82BDE9,
	0xBEF9A3F7B2C67915, 0xC67178F2E372532B,
	0xCA273ECEEA26619C, 0xD186B8C721C0C207,
	0xEADA7DD6CDE0EB1E, 0xF57D4F7FEE6ED178,
	0x06F067AA72176FBA, 0x0A637DC5A2C898A6,
	0x113F9804BEF90DAE, 0x1B710B35131C471B,
	0x28DB77F523047D84, 0x32CAAB7B40C72493,
	0x3C9EBE0A15C9BEBC, 0x431D67C49C100D4C,
	0x4CC5D4BECB3E42B6, 0x597F299CFC657E2A,
	0x5FCB6FAB3AD6FAEC, 0x6C44198C4A475817,
	0x7BA0EA2D98160007, 0x7EABF2D0C21F964A,
	0x8DBE8D038B409545, 0x90BB1721582E8285,
	0x99A2AD45936D4E61, 0x9F86E289FE03E739,
	0xA84C4472FAA9A82F, 0xB3DF34FCE89E0532,
	0xB99BB8D7B173534F, 0xBC76CBAB1AEA1F9C,
	0xC226A69A780F3CC3, 0xD304F19AA233957D,
	0xDE1BE20A212129DD, 0xE39BB43755141950,
	0xEE84927CEA48DDD2, 0xF3EDD2773C523B67,
	0xFBFDFE53A8D32F2A, 0x0BEE2C7AB77E9E25,
	0x0E90181CF1B09E56, 0x25F57204C725BED8,
	0x2DA45582CD598B32, 0x3A52C34C203BFCF3,
	0x41DC0172CD1991C1, 0x495796FCB33CC1C0,
	0x4BD31FC693F9F16E, 0x533CDE2115F5A9A0,
	0x5F7ABFE36E99C1D3, 0x66C206B310A57E6F,
	0x6DFCC6BC39603F61, 0x7062F20F86FD1052,
	0x778D51277ADEC865, 0x7EABA3CC25DA7048,
	0x8363ECCC37A5BE05, 0x85BE1C253BEBA54E,
	0x93C04028F348BBC5, 0x9F4A205FD05B2148,
	0xA19535651CA6D2DE, 0xA627BB0FBF027BC7,
	0xACFA80891DA2F06B, 0xB3C29B23031A7F9D,
	0xB602F6FAC7D3D74D, 0xC36CEE0A10C7BA49,
	0xC7DC81EEA9EBAD4F, 0xCE7B8471B0F809DF,
	0xD740288C84DF269C, 0xE21DBA7AC2290607,
	0xEABBFF66BE175964, 0xF56A9E60F62CEA92,
	0xFDE41D729D126EAB, 0x0434D0970E42E781,
	0x0A7CB752A3F1CD86, 0x0EA7D22D6BCD7382,
	0x16F2987F9495A5EE, 0x1D20CDCD45B8DE1E,
	0x213AF85A39B0C320, 0x2964505C52A2F35B,
	0x2D738E114181E082, 0x3B8CEA0E71C58AAF,
	0x4584E6AE9F54016E, 0x515F4356903DCCC2,
	0x5356112DDFD5A8E9, 0x5D1BC3EDBE2C897A,
	0x5F0DA9F8ED53548B, 0x62EF0BE4D5492E78,
	0x64DE896EACE0BE7F, 0x6E801BA3078AE05F,
	0x7BDB3595CDADF50A, 0x7FA5377856834C98,
	0x818916BAD3D008A8, 0x854E959F834021A7,
	0x926A82C27137E2C6, 0x9622C7BA7D179197,
	0x97FDD5929D59CE21, 0x9BB1CB7470162D7E,
	0xAE0B55609FFEA9D5, 0xB1AE88AB4ECA7239,
	0xB8ECC9F6468460A1, 0xC1EB8968A81A3124,
	0xC911DD821BB6B418, 0xCCA11FE32D0C58D0
};

static kripto_hash *sha2_512_recreate
(
	kripto_hash *s,
	unsigned int r,
	const void *salt,
	unsigned int salt_len,
	unsigned int out_len
)
{
	(void)salt;
	(void)salt_len;
	s->len[1] = s->len[0] = s->o = s->i = 0;

	s->r = r;
	if(!s->r) s->r = 80;

	if(out_len > 48)
	{
		/* 512 */
		s->h[0] = 0x6A09E667F3BCC908;
		s->h[1] = 0xBB67AE8584CAA73B;
		s->h[2] = 0x3C6EF372FE94F82B;
		s->h[3] = 0xA54FF53A5F1D36F1;
		s->h[4] = 0x510E527FADE682D1;
		s->h[5] = 0x9B05688C2B3E6C1F;
		s->h[6] = 0x1F83D9ABFB41BD6B;
		s->h[7] = 0x5BE0CD19137E2179;
	}
	else
	{
		/* 384 */
		s->h[0] = 0xCBBB9D5DC1059ED8;
		s->h[1] = 0x629A292A367CD507;
		s->h[2] = 0x9159015A3070DD17;
		s->h[3] = 0x152FECD8F70E5939;
		s->h[4] = 0x67332667FFC00B31;
		s->h[5] = 0x8EB44A8768581511;
		s->h[6] = 0xDB0C2E0D64F98FA7;
		s->h[7] = 0x47B5481DBEFA4FA4;
	}

	return s;
}

#define CH(X0, X1, X2) (X2 ^ (X0 & (X1 ^ X2)))
#define MAJ(X0, X1, X2) ((X0 & X1) | (X2 & (X0 | X1)))

#define S0(X) (ROR64_01(X) ^ ROR64_08(X) ^ ((X) >> 7))
#define S1(X) (ROR64_19(X) ^ ROR64_61(X) ^ ((X) >> 6))

#define E0(X) (ROR64_28(X) ^ ROR64_34(X) ^ ROR64_39(X))
#define E1(X) (ROR64_14(X) ^ ROR64_18(X) ^ ROR64_41(X))

#define ROUND(A, B, C, D, E, F, G, H, RC, RK)	\
{ 						\
	H += E1(E) + CH(E, F, G) + RC + RK;	\
	D += H;					\
	H += E0(A) + MAJ(A, B, C);		\
}

#define KI(K, I)				\
(						\
	K[I & 15] += S0(K[(I + 1) & 15])	\
		+ K[(I + 9) & 15]		\
		+ S1(K[(I + 14) & 15])		\
)

static void sha2_512_process(kripto_hash *s, const uint8_t *data)
{
	uint64_t a = s->h[0];
	uint64_t b = s->h[1];
	uint64_t c = s->h[2];
	uint64_t d = s->h[3];
	uint64_t e = s->h[4];
	uint64_t f = s->h[5];
	uint64_t g = s->h[6];
	uint64_t h = s->h[7];
	uint64_t k[16];

	k[ 0] = LOAD64B(data      );
	k[ 1] = LOAD64B(data +   8);
	k[ 2] = LOAD64B(data +  16);
	k[ 3] = LOAD64B(data +  24);
	k[ 4] = LOAD64B(data +  32);
	k[ 5] = LOAD64B(data +  40);
	k[ 6] = LOAD64B(data +  48);
	k[ 7] = LOAD64B(data +  56);
	k[ 8] = LOAD64B(data +  64);
	k[ 9] = LOAD64B(data +  72);
	k[10] = LOAD64B(data +  80);
	k[11] = LOAD64B(data +  88);
	k[12] = LOAD64B(data +  96);
	k[13] = LOAD64B(data + 104);
	k[14] = LOAD64B(data + 112);
	k[15] = LOAD64B(data + 120);

	ROUND(a, b, c, d, e, f, g, h, RC[ 0], k[ 0]);
	ROUND(h, a, b, c, d, e, f, g, RC[ 1], k[ 1]);
	ROUND(g, h, a, b, c, d, e, f, RC[ 2], k[ 2]);
	ROUND(f, g, h, a, b, c, d, e, RC[ 3], k[ 3]);
	ROUND(e, f, g, h, a, b, c, d, RC[ 4], k[ 4]);
	ROUND(d, e, f, g, h, a, b, c, RC[ 5], k[ 5]);
	ROUND(c, d, e, f, g, h, a, b, RC[ 6], k[ 6]);
	ROUND(b, c, d, e, f, g, h, a, RC[ 7], k[ 7]);
	
	ROUND(a, b, c, d, e, f, g, h, RC[ 8], k[ 8]);
	ROUND(h, a, b, c, d, e, f, g, RC[ 9], k[ 9]);
	ROUND(g, h, a, b, c, d, e, f, RC[10], k[10]);
	ROUND(f, g, h, a, b, c, d, e, RC[11], k[11]);
	ROUND(e, f, g, h, a, b, c, d, RC[12], k[12]);
	ROUND(d, e, f, g, h, a, b, c, RC[13], k[13]);
	ROUND(c, d, e, f, g, h, a, b, RC[14], k[14]);
	ROUND(b, c, d, e, f, g, h, a, RC[15], k[15]);

	for(unsigned int i = 16; i < s->r;)
	{
		ROUND(a, b, c, d, e, f, g, h, RC[i], KI(k, i)); i++;
		ROUND(h, a, b, c, d, e, f, g, RC[i], KI(k, i)); i++;
		ROUND(g, h, a, b, c, d, e, f, RC[i], KI(k, i)); i++;
		ROUND(f, g, h, a, b, c, d, e, RC[i], KI(k, i)); i++;
		ROUND(e, f, g, h, a, b, c, d, RC[i], KI(k, i)); i++;
		ROUND(d, e, f, g, h, a, b, c, RC[i], KI(k, i)); i++;
		ROUND(c, d, e, f, g, h, a, b, RC[i], KI(k, i)); i++;
		ROUND(b, c, d, e, f, g, h, a, RC[i], KI(k, i)); i++;
	}

	kripto_memory_wipe(k, 128);

	s->h[0] += a;
	s->h[1] += b;
	s->h[2] += c;
	s->h[3] += d;
	s->h[4] += e;
	s->h[5] += f;
	s->h[6] += g;
	s->h[7] += h;
}

static void sha2_512_input
(
	kripto_hash *s,
	const void *in,
	size_t len
) 
{
	for(size_t i = 0; i < len; i++)
	{
		s->buf[s->i++] = CU8(in)[i];

		if(s->i == 128)
		{
			s->len[0] += 1024;
			if(s->len[0] < 1024)
			{
				s->len[1]++;
				assert(s->len[1]);
			}

			sha2_512_process(s, s->buf);
			s->i = 0;
		}
	}
}

static void sha2_512_finish(kripto_hash *s)
{
	s->len[0] += s->i << 3;
	if(s->len[0] < (s->i << 3))
	{
		s->len[1]++;
		assert(s->len[1]);
	}

	s->buf[s->i++] = 0x80; /* pad */

	if(s->i > 112) /* not enough space for length */
	{
		while(s->i < 128) s->buf[s->i++] = 0;
		sha2_512_process(s, s->buf);
		s->i = 0;
	}
	while(s->i < 112) s->buf[s->i++] = 0;

	/* add length */
	STORE64B(s->len[1], s->buf + 112);
	STORE64B(s->len[0], s->buf + 120);

	sha2_512_process(s, s->buf);

	s->i = 0;
	s->o = -1;
}

static void sha2_512_output(kripto_hash *s, void *out, size_t len)
{
	if(!s->o) sha2_512_finish(s);

	assert(s->i + len <= 64);
	STORE64B_ARRAY(s->h, s->i, out, len);
	s->i += len;
}

static kripto_hash *sha2_512_create
(
	const kripto_desc_hash *desc,
	unsigned int r,
	const void *salt,
	unsigned int salt_len,
	unsigned int out_len
)
{
	kripto_hash *s = (kripto_hash *)malloc(sizeof(kripto_hash));
	if(!s) return 0;

	s->desc = desc;

	return sha2_512_recreate(s, r, salt, salt_len, out_len);
}

static void sha2_512_destroy(kripto_hash *s)
{
	kripto_memory_wipe(s, sizeof(kripto_hash));
	free(s);
}

static int sha2_512_hash
(
	const kripto_desc_hash *desc,
	unsigned int r,
	const void *salt,
	unsigned int salt_len,
	const void *in,
	size_t in_len,
	void *out,
	size_t out_len
)
{
	kripto_hash s;
	(void)desc;

	(void)sha2_512_recreate(&s, r, salt, salt_len, out_len);
	sha2_512_input(&s, in, in_len);
	sha2_512_output(&s, out, out_len);

	kripto_memory_wipe(&s, sizeof(kripto_hash));

	return 0;
}

static const kripto_desc_hash sha2_512 =
{
	&sha2_512_create,
	&sha2_512_recreate,
	&sha2_512_input,
	&sha2_512_output,
	&sha2_512_destroy,
	&sha2_512_hash,
	64, /* max output */
	128, /* block_size */
	0 /* max salt */
};

const kripto_desc_hash *const kripto_hash_sha2_512 = &sha2_512;
