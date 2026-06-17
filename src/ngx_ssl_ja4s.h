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
#ifndef __NGX_SSL_JA4S__
#define __NGX_SSL_JA4S__

#include <ngx_core.h>

/*
 * JA4S TLS server fingerprint (upstream/proxy connections only).
 *
 * Captures the server's TLS ServerHello and EncryptedExtensions.
 * Only available when nginx acts as a TLS proxy (connecting to an upstream).
 *
 * Format: {proto}{ver}{nexts:02d}{alpn}_{cipher_4hex}_{ext_hash}
 *
 * Example: t130200_1301_a56c5b993250
 *
 *   proto       - 't' (TLS)
 *   ver         - 2-char version: 13/12/11/10/s3/s2
 *   nexts       - non-GREASE extension count, zero-padded to 2 digits
 *   alpn        - first+last char of chosen ALPN protocol, or "00" if absent
 *   cipher_4hex - 4-char lowercase hex of server-chosen cipher suite
 *   ext_hash    - extensions in wire order as comma-sep 4-hex, SHA-256[:12]
 */

/* NGX_SSL_JA4S_FP_LEN: 1+2+2+2+'_'+4+'_'+12 = 25 chars */
#define NGX_SSL_JA4S_FP_LEN   25

typedef struct ngx_ssl_ja4s_s {
    unsigned short  version;
    unsigned char   alpn[2];        /* first+last char of chosen ALPN, or {0,0} */
    unsigned short  cipher;         /* server-chosen cipher suite */

    size_t          extensions_sz;
    unsigned short *extensions;     /* non-GREASE server extensions (wire order) */
} ngx_ssl_ja4s_t;


/* Populate ja4s from the connection's captured upstream ServerHello fields.
 * Returns NGX_OK on success, NGX_DECLINED if data is not available
 * (e.g., not a proxy connection or handshake not completed). */
int ngx_ssl_ja4s(ngx_connection_t *c, ngx_pool_t *pool, ngx_ssl_ja4s_t *ja4s);

/* Build the JA4S fingerprint string into out.
 * Sets out->len = 0 on error. */
void ngx_ssl_ja4s_fp(ngx_pool_t *pool, ngx_ssl_ja4s_t *ja4s, ngx_str_t *out);

#endif /* __NGX_SSL_JA4S__ */
