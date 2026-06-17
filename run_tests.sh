#!/bin/bash
set -euo pipefail

MODULE=/build/nginx-ssl-ja3
NGINX_BUILD=/build/nginx
NGINX_BIN=/usr/local/nginx/sbin/nginx

# Support both the lean test image (system OpenSSL) and the full dev image
# (custom OpenSSL built to /usr/local/lib).
if [ -f /usr/local/lib/libssl.so ] || [ -f /usr/local/lib/libssl.a ]; then
    export LD_LIBRARY_PATH=/usr/local/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}
    OPENSSL_CC="-I/usr/local/include"
    OPENSSL_LD="-L/usr/local/lib -Wl,-rpath,/usr/local/lib"
else
    OPENSSL_CC=""
    OPENSSL_LD=""
fi

export PATH=/usr/local/bin:/usr/local/nginx/sbin:$PATH

# ─── 1. Build nginx with the module ──────────────────────────────────────────

echo "━━━ Building nginx with module ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
cd "$NGINX_BUILD"

./auto/configure \
    --add-module="$MODULE" \
    --with-http_ssl_module \
    --with-stream_ssl_module \
    --with-stream \
    --with-debug \
    ${OPENSSL_CC:+--with-cc-opt="$OPENSSL_CC"} \
    ${OPENSSL_LD:+--with-ld-opt="$OPENSSL_LD"}

make -j"$(nproc)" install
echo "nginx: $("$NGINX_BIN" -v 2>&1)"

# ─── 2. C unit tests + coverage ──────────────────────────────────────────────

echo ""
echo "━━━ C unit tests + coverage ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
make -C "$MODULE/t/unit" coverage

# ─── 3. Perl integration tests (Test::Nginx) ─────────────────────────────────

echo ""
echo "━━━ Perl integration tests ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
export TEST_NGINX_BINARY="$NGINX_BIN"

# The tests use `use lib 'lib'` after chdir($FindBin::Bin), so they look for
# Test::Nginx in t/lib/.  Link that to the nginx-tests framework if available.
NGINX_TESTS_LIB=/build/nginx-tests/lib
if [ -d "$NGINX_TESTS_LIB" ] && [ ! -e "$MODULE/t/lib" ]; then
    ln -s "$NGINX_TESTS_LIB" "$MODULE/t/lib"
fi

cd "$MODULE"
prove -v t/http_ssl_ja3.t t/stream_ssl_ja3.t t/http_ssl_ja4.t t/stream_ssl_ja4.t

echo ""
echo "━━━ All tests passed ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
