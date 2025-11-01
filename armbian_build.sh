#!/bin/bash

#export CC=aarch64-linux-gnu-gcc
export CC=arm-linux-gnueabihf-gcc
export LIBCURL_DIR=$HOME/curl/build-linux-arm64-static
export ZLIB_DIR=$HOME/zlib-aarch64

$CC \
  -static \
  -I. \
  -I$LIBCURL_DIR/include \
  -I$ZLIB_DIR/include \
  beacon.c aes.c cJSON.c \
  $LIBCURL_DIR/lib/libcurl.a \
  $ZLIB_DIR/lib/libz.a \
  -ldl \
  -o beacon_linux

