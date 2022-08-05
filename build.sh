#!/bin/sh

# Copyright (C) 2011 by Gregor Pintar <grpintar@gmail.com>
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

CWD=$(pwd)
CC=${CC:-"cc"}
AR=${AR:-"ar"}
STRIP=${STRIP:-"strip"}
CFLAGS="-std=c99 -pedantic -Wall -Wextra -Wstrict-prototypes -Wmissing-prototypes -Wcast-qual -Wbad-function-cast -Wshadow -I $CWD/include/ -fPIC -D_ANSI_SOURCE -D_ISOC99_SOURCE -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64 $CFLAGS"
# -fstack-protector-all -fno-strict-aliasing -Werror  Wc++-compat -Wcast-align -DNDEBUG -fwhole-program -ffunction-sections -fdata-sections
OPTIM="-O2 -s -D_FORTIFY_SOURCE=2 -DNDEBUG $OPTIM"
# -flto -march=i686
LDFLAGS="-Wall $LDFLAGS"

#SRC="lib/version.c lib/authstream.c lib/authstream/eax.c lib/mac.c lib/mac/hmac.c lib/mac/omac.c lib/stream/salsa20.c lib/hash/md5.c  lib/hash/skein256.c lib/hash/blake256.c lib/hash/blake512.c lib/hash/blake2s.c lib/hash/blake2b.c lib/hash/whirlpool.c lib/hash/keccak1600.c lib/hash/keccak800.c lib/block/xtea.c lib/block/safer.c lib/block/simon128.c lib/block/simon64.c lib/block/simon32.c lib/block/speck128.c lib/block/speck64.c lib/block/speck32.c lib/block/threefish256.c lib/block/threefish512.c lib/block/threefish1024.c lib/stream/ecb.c lib/stream/ctr.c lib/stream/cbc.c lib/stream/ofb.c lib/stream/rc4.c lib/stream/chacha.c lib/block/rijndael.c lib/block/serpent.c lib/block/rc5.c lib/block/rc6.c lib/block/twofish.c lib/block/blowfish.c lib/block/anubis.c lib/block/noekeon.c lib/block/aria.c lib/block/seed.c lib/block/camellia.c lib/block/gost.c lib/hash.c lib/hash/sha1.c lib/hash/sha2_256.c lib/hash/sha2_512.c lib/memwipe.c lib/random.c lib/pkcs7.c lib/block.c lib/stream.c lib/pbkdf2.c lib/scrypt.c lib/stream/cfb.c"
#OBJ="version.o authstream.o eax.o mac.o hmac.o omac.o salsa20.o md5.o skein256.o blake256.o blake512.o blake2s.o blake2b.o whirlpool.o keccak1600.o keccak800.o xtea.o safer.o simon128.o simon64.o simon32.o speck128.o speck64.o speck32.o threefish256.o threefish512.o threefish1024.o ecb.o ctr.o cbc.o ofb.o rc4.o chacha.o rijndael.o serpent.o rc5.o rc6.o twofish.o blowfish.o anubis.o noekeon.o aria.o seed.o camellia.o gost.o hash.o sha1.o sha2_256.o sha2_512.o memwipe.o random.o pkcs7.o block.o stream.o pbkdf2.o scrypt.o cfb.o"

i=1
while [ $i -le $# ]; do

	eval param=\$$i;

	case $param in
	"-g")
		debug=1
		;;
	"-shared")
		shared=1
		;;
	"-os=unix")
		os=1
		CFLAGS="$CFLAGS -DKRIPTO_UNIX"
		;;
	"-os=windows")
		os=2
		CFLAGS="$CFLAGS -DKRIPTO_WINDOWS"
		LDFLAGS="$LDFLAGS -Wl,--subsystem,windows"
		;;
	"-h" | "--help")
		echo "-g		 		Debug build"
		echo "-shared		 		Build shared library"
		echo "-os=[unix|windows]		Target operating system"
		exit 1
		;;
	*)
		CFLAGS="$CFLAGS $param"
		;;
	esac

	i=$(($i+1))
done

# if OS not defined assume UNIX
if [ -z $os ]; then
	CFLAGS="$CFLAGS -DKRIPTO_UNIX"
fi

if [ -z $debug ]; then
	CFLAGS="$CFLAGS $OPTIM"
	LDFLAGS="$LDFLAGS $OPTIM"
else
	CFLAGS="$CFLAGS -g -fstack-protector-all"
fi

# compile
#$PREFIX$CC -c $SRC $CFLAGS
cd lib
$PREFIX$CC -c *.c $CFLAGS
cd block
$PREFIX$CC -c *.c $CFLAGS
cd ../hash
$PREFIX$CC -c *.c $CFLAGS
cd ../mac
$PREFIX$CC -c *.c $CFLAGS
cd ../stream
$PREFIX$CC -c *.c $CFLAGS
cd ../ae
$PREFIX$CC -c *.c $CFLAGS
cd ../

# build static
#$PREFIX$AR rcs libkripto.a $OBJ
$PREFIX$AR rcs libkripto.a *.o block/*.o hash/*.o mac/*.o stream/*.o ae/*.o

# build shared
if [ ! -z $shared ]; then
	#$PREFIX$CC -shared $LDFLAGS -Wl,-soname,libkripto.so.0 -o libkripto.so.0.1.0 $OBJ -lc
	#$PREFIX$CC -shared $LDFLAGS -Wl,-soname,libkripto.so.0 -o libkripto.so.0.1.0 *.o block/*.o hash/*.o mac/*.o stream/*.o ae/*.o -lc
	$PREFIX$CC -shared $LDFLAGS -o libkripto.so *.o block/*.o hash/*.o mac/*.o stream/*.o ae/*.o

	# strip
	if [ -z $debug ]; then
		$PREFIX$STRIP -S libkripto.so
	fi
fi

# clean
rm -f *.o block/*.o hash/*.o mac/*.o stream/*.o ae/*.o
