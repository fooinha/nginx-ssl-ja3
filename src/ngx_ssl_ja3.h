/*
 * Copyright (C) 2017-2019 Paulo Pacheco
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
#ifndef __NGX_SSL_JA3__
#define __NGX_SSL_JA3__

#include <ngx_core.h>

typedef struct ngx_ssl_ja3_s {
    int             version;

    size_t          ciphers_sz;
    unsigned short *ciphers;

    size_t          extensions_sz;
    unsigned short *extensions;

    size_t          curves_sz;
    unsigned short  *curves;

    size_t          point_formats_sz;
    unsigned char  *point_formats;

} ngx_ssl_ja3_t;


int ngx_ssl_ja3(ngx_connection_t *c, ngx_pool_t *pool, ngx_ssl_ja3_t *ja3);
void ngx_ssl_ja3_fp(ngx_pool_t *pool, ngx_ssl_ja3_t *ja3, ngx_str_t *out);

#endif //__NGX_SSL_JA3__
