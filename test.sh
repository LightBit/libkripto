#!/bin/sh

CFLAGS="lib/libkripto.a -std=c99 -pedantic -Wall -Wextra -Wcast-align -Wstrict-prototypes -Wmissing-prototypes -Wcast-qual -Wbad-function-cast -Wshadow -Wc++-compat -fstack-protector-all -I include/ -fPIC -D_ANSI_SOURCE -D_ISOC99_SOURCE -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64 $CFLAGS"

find test/ -name "*.c" -exec cc {} $CFLAGS -o t \; -exec ./t \;
#find test/block/ -name "*.c" -exec cc {} $CFLAGS -o t \; -exec valgrind -q ./t \;

#cc test/authstream/keccak1600.c $CFLAGS -o t
#./t

#cc test/mac/omac.c $CFLAGS -o t
#./t

#cc test/mac/hmac.c $CFLAGS -o t
#./t

#cc test/scrypt.c $CFLAGS -o t
#./t

#cc test/block/rijndael256.c $CFLAGS -o t
#./t

#cc test/block/khazad.c $CFLAGS -o t
#./t

#cc test/block/xtea.c $CFLAGS -o t
#./t

#cc test/block/blowfish.c $CFLAGS -o t
#./t

#cc test/block/serpent.c $CFLAGS -o t
#./t

#cc test/block/mars.c $CFLAGS -o t
#./t

#cc test/block/threefish256.c -DVERBOSE $CFLAGS -o t
#./t

#echo $?

#cc test/hash/skein256.c $CFLAGS -o t
#./t

#cc test/hash/md5.c $CFLAGS -o t
#./t

#cc test/hash/blake256.c $CFLAGS -o t
#./t

#cc test/hash/blake2b.c $CFLAGS -o t
#./t

#cc test/hash/keccak1600.c test/test.c -DVERBOSE $CFLAGS -o t
#./t

#cc test/stream/chacha.c $CFLAGS -o t
#./t

#cc test/stream/salsa20.c $CFLAGS -o t
#./t

#cc test/mode/ctr.c $CFLAGS -o t
#./t

rm t
