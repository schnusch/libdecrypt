#!/bin/sh
set -e
[ -d "build" ] || mkdir "build"
cd "build"
find .. -type f -name "*.c" | grep -Fxv "../demo/demo.c" | sort -R | C_INCLUDE_PATH="/usr/include/libxml2" xargs -rd '\n' \
		gcc -Wall -Wextra -pedantic -std=c99 -O2 -shared -fPIC -lcrypto -lcurl -lxml2 -o "libdecrypt.so"
gcc -Wall -Wextra -pedantic -std=c99 -O2 -L. -ldecrypt -o "demo" "../demo/demo.c"
cp -t . "../demo/test."{rsdf,ccf,dlc}
LD_LIBRARY_PATH="`readlink -f .`" ./demo
