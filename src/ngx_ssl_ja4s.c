/*
 * Copyright (C) 2017-2026 Paulo Pacheco
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "ngx_ssl_ja4s.h"

#include <openssl/evp.h>

#ifndef NGX_SSL_IS_GREASE
#define NGX_SSL_IS_GREASE(v) \
    (((v) & 0x0f0f) == 0x0a0a && ((v) & 0xff) == (((v) >> 8) & 0xff))
#endif

static void
ngx_ssl_ja4s_version_str(unsigned short ver, char out[2])
{
    switch (ver) {
    case 0x0304: out[0] = '1'; out[1] = '3'; return;
    case 0x0303: out[0] = '1'; out[1] = '2'; return;
    case 0x0302: out[0] = '1'; out[1] = '1'; return;
    case 0x0301: out[0] = '1'; out[1] = '0'; return;
    case 0x0300: out[0] = 's'; out[1] = '3'; return;
    case 0x0002: out[0] = 's'; out[1] = '2'; return;
    default:     out[0] = '0'; out[1] = '0'; return;
    }
}

static const char ngx_ssl_ja4s_hex[] = "0123456789abcdef";

static u_char *
ngx_ssl_ja4s_write4hex(u_char *p, unsigned short v)
{
    p[0] = (u_char) ngx_ssl_ja4s_hex[(v >> 12) & 0xf];
    p[1] = (u_char) ngx_ssl_ja4s_hex[(v >>  8) & 0xf];
    p[2] = (u_char) ngx_ssl_ja4s_hex[(v >>  4) & 0xf];
    p[3] = (u_char) ngx_ssl_ja4s_hex[(v >>  0) & 0xf];
    return p + 4;
}

/* SHA-256 of buf[len], first 12 lowercase hex chars written to out[12]. */
static int
ngx_ssl_ja4s_sha256_12(const u_char *buf, size_t len, u_char out[12])
{
    EVP_MD_CTX    *ctx;
    unsigned char  hash[EVP_MAX_MD_SIZE];
    unsigned int   hash_len = 0;
    int            i;

    ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        return -1;
    }

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1
        || EVP_DigestUpdate(ctx, buf, len) != 1
        || EVP_DigestFinal_ex(ctx, hash, &hash_len) != 1
        || hash_len < 6)
    {
        EVP_MD_CTX_free(ctx);
        return -1;
    }

    for (i = 0; i < 6; i++) {
        out[i * 2]     = (u_char) ngx_ssl_ja4s_hex[(hash[i] >> 4) & 0xf];
        out[i * 2 + 1] = (u_char) ngx_ssl_ja4s_hex[hash[i] & 0xf];
    }

    EVP_MD_CTX_free(ctx);
    return 0;
}

/* Server extensions in wire order as comma-sep 4-hex, SHA-256[:12]. */
static int
ngx_ssl_ja4s_ext_hash(ngx_pool_t *pool, ngx_ssl_ja4s_t *ja4s, u_char out[12])
{
    u_char  *buf;
    u_char  *p;
    size_t   i;

    if (ja4s->extensions_sz == 0) {
        ngx_memcpy(out, "000000000000", 12);
        return 0;
    }

    buf = ngx_pnalloc(pool, ja4s->extensions_sz * 5);
    if (buf == NULL) {
        return -1;
    }

    p = buf;
    for (i = 0; i < ja4s->extensions_sz; i++) {
        if (i > 0) {
            *p++ = ',';
        }
        p = ngx_ssl_ja4s_write4hex(p, ja4s->extensions[i]);
    }

    return ngx_ssl_ja4s_sha256_12(buf, p - buf, out);
}


void
ngx_ssl_ja4s_fp(ngx_pool_t *pool, ngx_ssl_ja4s_t *ja4s, ngx_str_t *out)
{
    u_char  *p;
    char     ver[2];
    u_char   ext_hash[12];
    size_t   ne;

    if (pool == NULL || ja4s == NULL || out == NULL) {
        return;
    }

    out->data = ngx_pnalloc(pool, NGX_SSL_JA4S_FP_LEN);
    if (out->data == NULL) {
        out->len = 0;
        return;
    }
    out->len = NGX_SSL_JA4S_FP_LEN;

    ngx_ssl_ja4s_version_str(ja4s->version, ver);

    if (ngx_ssl_ja4s_ext_hash(pool, ja4s, ext_hash) != 0) {
        ngx_memcpy(ext_hash, "000000000000", 12);
    }

    ne = ja4s->extensions_sz < 99 ? ja4s->extensions_sz : 99;

    p = out->data;
    *p++ = 't';
    *p++ = (u_char) ver[0];
    *p++ = (u_char) ver[1];
    *p++ = (u_char) ('0' + ne / 10);
    *p++ = (u_char) ('0' + ne % 10);
    *p++ = (u_char) (ja4s->alpn[0] ? ja4s->alpn[0] : '0');
    *p++ = (u_char) (ja4s->alpn[1] ? ja4s->alpn[1] : '0');
    *p++ = '_';
    p = ngx_ssl_ja4s_write4hex(p, ja4s->cipher);
    *p++ = '_';
    ngx_memcpy(p, ext_hash, 12);
}


int
ngx_ssl_ja4s(ngx_connection_t *c, ngx_pool_t *pool, ngx_ssl_ja4s_t *ja4s)
{
    (void) pool;
    if (c == NULL || c->ssl == NULL) {
        return NGX_DECLINED;
    }

    if (!c->ssl->handshaked) {
        return NGX_DECLINED;
    }

    /* ja4s_version is zero if no ServerHello was captured (not a proxy conn) */
    if (c->ssl->ja4s_version == 0 && c->ssl->ja4s_cipher == 0) {
        return NGX_DECLINED;
    }

    ngx_memzero(ja4s, sizeof(ngx_ssl_ja4s_t));

    ja4s->version      = c->ssl->ja4s_version;
    ja4s->alpn[0]      = c->ssl->ja4s_alpn[0];
    ja4s->alpn[1]      = c->ssl->ja4s_alpn[1];
    ja4s->cipher       = c->ssl->ja4s_cipher;
    ja4s->extensions   = c->ssl->ja4s_extensions;
    ja4s->extensions_sz = c->ssl->ja4s_extensions_sz;

    return NGX_OK;
}
