#ifndef KRIPTO_ASSERT_H
#define KRIPTO_ASSERT_H

#include <stdlib.h>

#define kripto_assert(expr) { if(!(expr)) abort(); }

#endif
