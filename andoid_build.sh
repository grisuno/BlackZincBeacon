}export CLANG=$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android24-clang ;
$CLANG \
  -static \
  -I. \
  -I$HOME/curl/include \
  beacon.c aes.c cJSON.c \
  $HOME/curl/build-android-arm64/lib/.libs/libcurl.a \
  -ldl -lz \
  -o beacon_android


