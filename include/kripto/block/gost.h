#ifndef KRIPTO_BLOCK_GOST_H
#define KRIPTO_BLOCK_GOST_H

extern kripto_desc_block *kripto_block_gost(const unsigned char (*sboxes)[16]);
extern kripto_desc_block *kripto_block_gost_cbr(void);
extern kripto_desc_block *kripto_block_gost_r34_12_2015(void);

#endif
