#!/bin/bash
set -euo pipefail

MODULE=/build/nginx-ssl-ja3
NGINX_BUILD=/build/nginx
NGINX_BIN=/usr/local/nginx/sbin/nginx

export LD_LIBRARY_PATH=/usr/local/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}
export PATH=/usr/local/bin:/usr/local/nginx/sbin:$PATH

# ─── 1. Build nginx with the module ─────────────────────────────────────────

echo "━━━ Building nginx with module ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
cd "$NGINX_BUILD"

./auto/configure \
    --add-module="$MODULE" \
    --with-http_ssl_module \
    --with-stream_ssl_module \
    --with-stream \
    --with-debug \
    --with-cc-opt="-I/usr/local/include" \
    --with-ld-opt="-L/usr/local/lib -Wl,-rpath,/usr/local/lib"

make -j"$(nproc)" install
echo "nginx binary: $NGINX_BIN"
"$NGINX_BIN" -v

# ─── 2. C unit tests (standalone, no nginx required) ────────────────────────

echo ""
echo "━━━ C unit tests ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
make -C "$MODULE/t/unit" clean all

# ─── 3. Perl integration tests (Test::Nginx) ────────────────────────────────

echo ""
echo "━━━ Perl integration tests ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
export TEST_NGINX_BINARY="$NGINX_BIN"
cd "$MODULE"
prove -v t/http_ssl_ja3.t t/stream_ssl_ja3.t

echo ""
echo "━━━ All tests passed ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
