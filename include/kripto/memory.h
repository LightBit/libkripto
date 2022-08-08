#ifndef KRIPTO_MEMORY_H
#define KRIPTO_MEMORY_H

#include <stddef.h>

extern void kripto_memory_wipe(void *, size_t);

extern unsigned char kripto_memory_equals(const void *, const void *, size_t);

#endif
