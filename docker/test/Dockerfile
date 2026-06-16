FROM debian:bookworm-slim

# ─── System packages ──────────────────────────────────────────────────────────
# No valgrind/vim/devscripts — only what's needed to build nginx + run tests.
# OpenSSL 3.x in bookworm already exposes SSL_client_hello_get1_extensions_present
# so no from-source OpenSSL build is required.
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        cpanminus \
        git \
        lcov \
        libpcre2-dev \
        libperl-dev \
        libssl-dev \
        perl \
        zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

# ─── Perl test dependencies ───────────────────────────────────────────────────
# Test::Nginx from CPAN is the OpenResty variant; nginx module tests use the
# framework bundled in the nginx-tests repo instead. Install only the
# non-bundled deps from cpanm.
RUN cpanm --notest IO::Socket::SSL Digest::MD5

# ─── nginx source (pinned to the tag that both patches target) ───────────────
WORKDIR /build
RUN git clone --depth 1 --branch release-1.27.2 https://github.com/nginx/nginx.git nginx

# ─── Module source is mounted at runtime; patches are COPY'd at build time ───
COPY patches/nginx.1.27.2.ssl.extensions.patch /build/nginx/
WORKDIR /build/nginx
RUN patch -p1 < nginx.1.27.2.ssl.extensions.patch

# ─── nginx Test::Nginx framework ─────────────────────────────────────────────
# Use the nginx project's own Test::Nginx (not the CPAN/OpenResty variant).
WORKDIR /build
RUN git clone --depth 1 https://github.com/nginx/nginx-tests.git

# ─── Build nginx with the module ─────────────────────────────────────────────
# Module source is expected at /build/nginx-ssl-ja3 (mounted volume).
# We defer the configure+make to run_tests.sh so a source-only rebuild doesn't
# require a full image rebuild.

WORKDIR /build
