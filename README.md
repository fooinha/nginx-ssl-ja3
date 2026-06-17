# nginx-ssl-ja3

**Release:** v0.0.2 (stable) · [v0.1.0-alpha](https://github.com/fooinha/nginx-ssl-ja3/tree/feat/ja4) (JA4/JA4S experimental — see below)

nginx module for SSL/TLS JA3 fingerprinting.

## Description

This module adds nginx variables that expose the [JA3](https://github.com/salesforce/ja3)
TLS client fingerprint and its MD5 hash. JA3 fingerprints the TLS ClientHello by combining
the TLS version, cipher suites, extensions, elliptic curves, and elliptic curve point formats
into a string that is then MD5-hashed.

> **Note:** Chrome 110+ and recent Firefox builds randomise the order of TLS ClientHello
> extensions, which makes standard JA3 unstable across requests from the same browser.
> Compile with `--with-cc-opt='-DJA3_SORT_EXT'` to sort extensions before fingerprinting
> (produces a non-standard but stable fingerprint).

---

## Variables

### HTTP

| Variable | Description |
|---|---|
| `$http_ssl_ja3` | JA3 fingerprint string for an HTTP/HTTPS connection |
| `$http_ssl_ja3_hash` | MD5 hash of `$http_ssl_ja3` |

```nginx
http {
    server {
        listen              127.0.0.1:443 ssl;
        ssl_certificate     cert.pem;
        ssl_certificate_key rsa.key;
        return 200          "$http_ssl_ja3\n$http_ssl_ja3_hash\n";
    }
}
```

Example fingerprint string:
```
771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53-10,0-23-65281-10-11-35-16-5-13-18-51-45-43-21,0-29-23-24,0
```

### Stream

| Variable | Description |
|---|---|
| `$stream_ssl_ja3` | JA3 fingerprint string for a TCP stream SSL connection |
| `$stream_ssl_ja3_hash` | MD5 hash of `$stream_ssl_ja3` |

```nginx
stream {
    server {
        listen              127.0.0.1:12345 ssl;
        ssl_certificate     cert.pem;
        ssl_certificate_key rsa.key;
        return              "$stream_ssl_ja3\n$stream_ssl_ja3_hash\n";
    }
}
```

---

## Build

### Requirements

- **nginx** ≥ 1.11.2 (stream support) with `--with-http_ssl_module --with-stream_ssl_module`
- **OpenSSL** ≥ 1.1.1 (for `SSL_CTX_set_client_hello_cb`) — OpenSSL 3.x recommended

The module uses the nginx ClientHello early callback to capture cipher suites and extensions
before the handshake completes, which requires a small patch to nginx source.
No patch to OpenSSL itself is needed when using a system OpenSSL ≥ 1.1.1.

### Nginx patches

| Patch file | nginx version |
|---|---|
| [`patches/nginx.1.27.2.ssl.extensions.patch`](patches/nginx.1.27.2.ssl.extensions.patch) | nginx 1.27.2 |
| [`patches/nginx.1.29.8.ssl.extensions.patch`](patches/nginx.1.29.8.ssl.extensions.patch) | nginx 1.29.x / 1.30.x / 1.31.x |
| [`patches/nginx.1.23.1.ssl.extensions.patch`](patches/nginx.1.23.1.ssl.extensions.patch) | nginx 1.23.1 |

### Build steps

```bash
# Clone nginx (pinned to the version matching your patch)
git clone --depth 1 --branch release-1.27.2 https://github.com/nginx/nginx.git
cd nginx

# Apply the nginx patch
patch -p1 < /path/to/nginx-ssl-ja3/patches/nginx.1.27.2.ssl.extensions.patch

# Configure with the module
./configure \
    --add-module=/path/to/nginx-ssl-ja3 \
    --with-http_ssl_module \
    --with-stream_ssl_module \
    --with-stream \
    --with-debug

# Build and install
make && make install
```

> When using a custom OpenSSL build via `--with-openssl=/path`, nginx compiles OpenSSL
> as part of its own build. The module's compile-time feature detection skips the
> link test automatically in that case.

---

## Tests

### Docker (recommended — runs everything)

```bash
docker compose -f docker/docker-compose.yml run --rm nginx-test
```

This builds a lean Debian bookworm image with system OpenSSL 3, patches and builds
nginx 1.27.2, runs 71 C unit tests with lcov coverage, and runs 25 Perl integration
tests (HTTP + stream).

### C unit tests only

```bash
make -C t/unit all       # build and run
make -C t/unit coverage  # run + print lcov coverage table
```

### Perl integration tests

```bash
# nginx must already be installed and TEST_NGINX_BINARY set
export TEST_NGINX_BINARY=/usr/local/nginx/sbin/nginx
prove -v t/http_ssl_ja3.t t/stream_ssl_ja3.t
```

---

## Docker

A dev image (with a from-source OpenSSL build) and a lean test image are available:

```bash
# Full dev environment
docker compose -f docker/docker-compose.yml up --build nginx-dev

# Lean test runner (CI-style)
docker compose -f docker/docker-compose.yml run --rm nginx-test
```

---

## Experimental: JA4 / JA4S fingerprinting

Branch [`feat/ja4`](https://github.com/fooinha/nginx-ssl-ja3/tree/feat/ja4) (tagged [`v0.1.0-alpha`](https://github.com/fooinha/nginx-ssl-ja3/releases/tag/v0.1.0-alpha))
adds support for [JA4+](https://github.com/FoxIO-LLC/ja4) TLS fingerprinting alongside the existing JA3 variables:

| Variable | Description |
|---|---|
| `$http_ssl_ja4` | JA4 client fingerprint for HTTP/HTTPS connections (36 chars) |
| `$stream_ssl_ja4` | JA4 client fingerprint for stream SSL connections |
| `$stream_ssl_ja4s` | JA4S **server** fingerprint — only populated in TLS proxy mode |

JA4 format: `t{ver}{sni}{nc:02d}{ne:02d}{alpn}_{cipher_hash}_{ext_hash}`

Example: `t13d0306h2_55b375c5d22e_a56c5b993250`

JA4S format: `t{ver}{ne:02d}{alpn}_{cipher}_{ext_hash}`

Example: `t130200_1301_a56c5b993250`

> **Status:** experimental — not ready for production use. The branch passes
> 198 tests (148 C unit tests + 50 Perl integration tests) but the JA4S golden-dataset
> Docker containers and full proxy-mode integration tests are still in progress.

To try it:

```bash
git checkout feat/ja4
docker compose -f docker/docker-compose.yml run --rm nginx-test
```

---

## Contributors

- [@fooinha](https://github.com/fooinha) — author and maintainer
- [@Sessa93](https://github.com/Sessa93) — OpenSSL 1.1.1-pre9 support
- [@bartebor](https://github.com/bartebor) — fix SSL session leak
- [@catap](https://github.com/catap) — C99 mode fix; skip OpenSSL feature test for custom builds
- [@tiandrey](https://github.com/tiandrey) — nginx 1.14.0 and OpenSSL patch updates
- [@k1k](https://github.com/k1k) — allow building without stream module
- [@gbilic](https://github.com/gbilic) — JA3_SORT_EXT extension sorting feature
- [@oowl](https://github.com/oowl) — static-link build fix (`NGX_LIBDL`/`NGX_LIBPTHREAD`)
- [@kamyabzad](https://github.com/kamyabzad) — fix segfault in ClientHello callback
- [@climagabriel](https://github.com/climagabriel) — replace deprecated `SSL_get0_raw_cipherlist` with `SSL_client_hello_get0_ciphers`
- [@vobloeb](https://github.com/vobloeb) — nginx 1.29.x / 1.30.x / 1.31.x patch
- [@rc5hack](https://github.com/rc5hack) — compiler flag and git clone improvements

---

## Fair Warning

**THIS IS NOT PRODUCTION READY.**

No guarantee of stability. It will most probably blow up in real-life scenarios.
