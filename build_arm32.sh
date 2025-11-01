export CC=arm-linux-gnueabihf-gcc
export LIBCURL_DIR=/home/grisun0/curl/build-linux-armhf-static
export ZLIB_DIR=/home/grisun0/zlib-armhf
$CC \
  -static \
  -I. \
  -I$LIBCURL_DIR/include \
  -I$ZLIB_DIR/include \
  beacon.c aes.c cJSON.c \
  $LIBCURL_DIR/lib/libcurl.a \
  $ZLIB_DIR/lib/libz.a \
  -ldl \
  -o beacon_arm32
