#!/bin/sh

CFLAGS="lib/libkripto.a -std=c99 -pedantic -Wall -Wextra -Wcast-align -Wstrict-prototypes -Wmissing-prototypes -Wcast-qual -Wbad-function-cast -Wshadow -Wc++-compat -fstack-protector-all -I include/ -fPIC -D_ANSI_SOURCE -D_ISOC99_SOURCE -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64 $CFLAGS"

find test/ -name "*.c" -exec cc {} $CFLAGS -o t \; -exec ./t \; -exec rm t \;
#find test/ -name "*.c" -print -exec cc {} $CFLAGS -DVERBOSE -o t \; -exec valgrind -q ./t \; -exec rm t \;
