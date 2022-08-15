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
CFLAGS="-std=c99 -pedantic -Wall -Wextra -Wcast-align -Wstrict-prototypes -Wmissing-prototypes -Wcast-qual -Wbad-function-cast -Wshadow -Wc++-compat -fstack-protector-all -I $CWD/include/ -fPIC -D_ANSI_SOURCE -D_ISOC99_SOURCE -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64 $CFLAGS"
# -DNDEBUG -D_FORTIFY_SOURCE=2
OPTIM="-O2 $OPTIM"
LDFLAGS="-Wall $LDFLAGS"

i=1
while [ $i -le $# ]; do

	eval param=\$$i;

	case $param in
	"-g")
		debug=1
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
		echo "-os=[unix|windows]		Target operating system"
		exit 1
		;;
	*)
		CFLAGS="$CFLAGS $param"
		;;
	esac

	i=$(($i+1))
done

#endian=$(printf '\1' | od -An -t xS)
#if [ "$endian" = " 0001" ]; then
#	CFLAGS="$CFLAGS -DKRIPTO_LITTLE_ENDIAN"
#elif [ "$endian" = " 0100" ]; then
#	CFLAGS="$CFLAGS -DKRIPTO_BIG_ENDIAN"
#fi

# if OS not defined assume UNIX
if [ -z $os ]; then
	CFLAGS="$CFLAGS -DKRIPTO_UNIX"
fi

if [ -z $debug ]; then
	CFLAGS="$CFLAGS $OPTIM"
	LDFLAGS="$LDFLAGS $OPTIM"
else
	CFLAGS="$CFLAGS -g"
fi

# compile
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
$PREFIX$AR rcs libkripto.a *.o block/*.o hash/*.o mac/*.o stream/*.o ae/*.o

# build shared
#$PREFIX$CC -shared $LDFLAGS -Wl,-soname,libkripto.so.0 -o libkripto.so.0.1.0 *.o block/*.o hash/*.o mac/*.o stream/*.o ae/*.o -lc
$PREFIX$CC -shared $LDFLAGS -o libkripto.so *.o block/*.o hash/*.o mac/*.o stream/*.o ae/*.o

# strip
if [ -z $debug ]; then
	$PREFIX$STRIP -S libkripto.so
fi

# run tests
cd ../
find test/ -name "*.c" -exec $CC {} lib/libkripto.a $CFLAGS -o t \; -exec ./t \; -exec rm t \;
#find test/ -name "*.c" -exec $CC {} lib/libkripto.a $CFLAGS -DVERBOSE -o t \; -exec valgrind -q ./t \; -exec rm t \;
