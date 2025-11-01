#!/bin/bash
arm-linux-gnueabihf-gcc -I. -I/home/grisun0/curl-arm32/include -I/home/grisun0/openssl-armhf/include -I/home/grisun0/zlib-armhf/include beacon.c aes.c cJSON.c -L/home/grisun0/curl-arm32/lib -L/home/grisun0/openssl-armhf/lib -L/home/grisun0/zlib-armhf/lib -lcurl -lssl -lcrypto -lz -ldl -lpthread -o beacon

