#!/bin/sh
set -e
[ -d "build" ] || mkdir "build"
cd "build"
find .. -type f -name "*.c" | grep -Fxv "../example.c" | sort -R | C_INCLUDE_PATH="/usr/include/libxml2" xargs -rd '\n' \
		gcc -Wall -Wextra -pedantic -std=c99 -O2 -shared -fPIC -lcrypto -lcurl -lxml2 -o "libdecrypt.so"
