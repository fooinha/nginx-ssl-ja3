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
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>
#include <ngx_log.h>

#include "ngx_ssl_ja4.h"

static ngx_int_t ngx_stream_ssl_ja4_preread_init(ngx_conf_t *cf);

static ngx_stream_module_t ngx_stream_ssl_ja4_preread_module_ctx = {
    NULL,                                        /* preconfiguration */
    ngx_stream_ssl_ja4_preread_init,             /* postconfiguration */
    NULL,                                        /* create main configuration */
    NULL,                                        /* init main configuration */
    NULL,                                        /* create server configuration */
    NULL                                         /* merge server configuration */
};

ngx_module_t ngx_stream_ssl_ja4_preread_module = {
    NGX_MODULE_V1,
    &ngx_stream_ssl_ja4_preread_module_ctx,      /* module context */
    NULL,                                        /* module directives */
    NGX_STREAM_MODULE,                           /* module type */
    NULL,                                        /* init master */
    NULL,                                        /* init module */
    NULL,                                        /* init process */
    NULL,                                        /* init thread */
    NULL,                                        /* exit thread */
    NULL,                                        /* exit process */
    NULL,                                        /* exit master */
    NGX_MODULE_V1_PADDING
};

static ngx_int_t
ngx_stream_ssl_ja4_var(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, uintptr_t data)
{
    ngx_ssl_ja4_t  ja4;
    ngx_str_t      fp = ngx_null_string;

    if (s->connection == NULL) {
        return NGX_OK;
    }

    if (ngx_ssl_ja4(s->connection, s->connection->pool, &ja4) == NGX_DECLINED) {
        v->not_found = 1;
        return NGX_OK;
    }

    ngx_ssl_ja4_fp(s->connection->pool, &ja4, &fp);
    if (fp.data == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->data         = fp.data;
    v->len          = fp.len;
    v->valid        = 1;
    v->no_cacheable = 1;
    v->not_found    = 0;

    return NGX_OK;
}

static ngx_stream_variable_t ngx_stream_ssl_ja4_variables_list[] = {

    {   ngx_string("stream_ssl_ja4"),
        NULL,
        ngx_stream_ssl_ja4_var,
        0, 0, 0
    },

};


static ngx_int_t
ngx_stream_ssl_ja4_preread_init(ngx_conf_t *cf)
{
    ngx_stream_variable_t  *v;
    size_t                  l;
    size_t                  vars_len;

    vars_len = sizeof(ngx_stream_ssl_ja4_variables_list)
               / sizeof(ngx_stream_ssl_ja4_variables_list[0]);

    for (l = 0; l < vars_len; l++) {
        v = ngx_stream_add_variable(cf,
                &ngx_stream_ssl_ja4_variables_list[l].name,
                ngx_stream_ssl_ja4_variables_list[l].flags);
        if (v == NULL) {
            continue;
        }
        *v = ngx_stream_ssl_ja4_variables_list[l];
    }

    return NGX_OK;
}
