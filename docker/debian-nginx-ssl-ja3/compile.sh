#!/bin/bash

cd nginx
ASAN_OPTIONS=symbolize=1 ./auto/configure --add-module=/build/nginx-ssl-ja3 --with-http_ssl_module --with-stream_ssl_module --with-debug --with-stream --with-cc-opt="-fsanitize=address -O -fno-omit-frame-pointer" --with-ld-opt="-L/usr/local/lib -Wl,-E -lasan"
make install
cd -
