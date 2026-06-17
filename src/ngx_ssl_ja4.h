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
#ifndef __NGX_SSL_JA4__
#define __NGX_SSL_JA4__

#include <ngx_core.h>

/*
 * JA4 TLS client fingerprint.
 *
 * Format: {proto}{ver}{sni}{nciphers:02d}{nexts:02d}{alpn}_{cipher_hash}_{ext_sigalg_hash}
 *
 * Example: t13d1516h2_acb2b30fb7d1_1bf25040e8ef
 *
 *   proto          - 't' (TLS)
 *   ver            - 2-char version: 13/12/11/10/s3/s2
 *   sni            - 'd' (SNI present) or 'i' (absent)
 *   nciphers       - non-GREASE cipher count, zero-padded to 2 digits
 *   nexts          - non-GREASE extension count, zero-padded to 2 digits
 *   alpn           - first+last char of first ALPN, or "00" if absent
 *   cipher_hash    - sorted non-GREASE ciphers as 4-hex, SHA-256[:12]
 *   ext_sigalg_hash - sorted non-GREASE exts (excl SNI/ALPN) + sigalgs,
 *                     SHA-256[:12]
 */

/* JA4_FP_LEN: 10 header chars + '_' + 12 cipher hash + '_' + 12 ext hash */
#define NGX_SSL_JA4_FP_LEN    36

typedef struct ngx_ssl_ja4_s {
    /* raw fields populated from ngx_ssl_ja4() */
    unsigned short  version;        /* highest TLS version (host byte order) */
    unsigned char   sni;            /* 'd' or 'i' */
    unsigned char   alpn[2];        /* first+last char, or {0,0} */

    size_t          ciphers_sz;
    unsigned short *ciphers;        /* non-GREASE ciphers (host byte order) */

    size_t          extensions_sz;
    unsigned short *extensions;     /* non-GREASE extension types */

    size_t          sig_algs_sz;
    unsigned short *sig_algs;       /* signature algorithms (wire order) */
} ngx_ssl_ja4_t;


/* Populate ja4 from the connection's captured ClientHello fields.
 * Returns NGX_OK on success, NGX_DECLINED if the connection is not ready. */
int ngx_ssl_ja4(ngx_connection_t *c, ngx_pool_t *pool, ngx_ssl_ja4_t *ja4);

/* Build the JA4 fingerprint string into out (must point to >= NGX_SSL_JA4_FP_LEN bytes).
 * Sets out->len = 0 on error. */
void ngx_ssl_ja4_fp(ngx_pool_t *pool, ngx_ssl_ja4_t *ja4, ngx_str_t *out);

#endif /* __NGX_SSL_JA4__ */
