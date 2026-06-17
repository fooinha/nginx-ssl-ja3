/*
 * Minimal nginx type and function stubs for unit testing ngx_ssl_ja3/ja4.c
 * without a full nginx build.
 */
#ifndef NGX_CORE_STUB_H
#define NGX_CORE_STUB_H

#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <openssl/obj_mac.h>
#include <openssl/ssl.h>

typedef unsigned char   u_char;
typedef intptr_t        ngx_int_t;
typedef uintptr_t       ngx_uint_t;

typedef struct {
    size_t   len;
    u_char  *data;
} ngx_str_t;

#define ngx_null_string  { 0, NULL }

typedef struct ngx_log_s  ngx_log_t;
typedef struct ngx_pool_s ngx_pool_t;

struct ngx_log_s  { ngx_uint_t log_level; };
struct ngx_pool_s { ngx_log_t *log; };

/* Minimal ngx_ssl_connection_t with JA3 and JA4/JA4S patched fields */
typedef struct {
    SSL            *connection;   /* underlying OpenSSL object */
    unsigned        handshaked:1;

    /* JA3 fields added by the nginx patch */
    size_t          ciphers_sz;
    unsigned short *ciphers;

    size_t          extensions_size;
    int            *extensions;

    size_t          curves_sz;
    unsigned short *curves;

    size_t          point_formats_sz;
    unsigned char  *point_formats;

    /* JA4 fields */
    unsigned short  ja4_version;
    unsigned char   ja4_sni;
    unsigned char   ja4_alpn[2];
    size_t          ja4_sig_algs_sz;
    unsigned short *ja4_sig_algs;

    /* JA4S fields */
    unsigned short  ja4s_version;
    unsigned char   ja4s_alpn[2];
    unsigned short  ja4s_cipher;
    size_t          ja4s_extensions_sz;
    unsigned short *ja4s_extensions;
} ngx_ssl_connection_t;

typedef struct ngx_connection_s ngx_connection_t;
struct ngx_connection_s {
    ngx_pool_t          *pool;
    ngx_ssl_connection_t *ssl;
};

#define NGX_OK        0
#define NGX_ERROR    -1
#define NGX_DECLINED -5

/* No-op log macros */
#define NGX_LOG_DEBUG_EVENT 0
#define ngx_log_debug0(level, log, err, fmt)
#define ngx_log_debug1(level, log, err, fmt, a1)
#define ngx_log_debug2(level, log, err, fmt, a1, a2)

/* Standard memory helpers */
#define ngx_memcpy(dst, src, n)     memcpy(dst, src, n)
#define ngx_memzero(buf, n)         memset(buf, 0, n)
#define ngx_qsort                   qsort

/*
 * Set to 1 before a call to make the next ngx_pnalloc/ngx_palloc return NULL.
 * Resets automatically after triggering once.
 */
static int ngx_pnalloc_fail_next = 0;

static inline void *
ngx_pnalloc(ngx_pool_t *pool, size_t size)
{
    (void)pool;
    if (ngx_pnalloc_fail_next) {
        ngx_pnalloc_fail_next = 0;
        return NULL;
    }
    return malloc(size);
}

static inline void *
ngx_palloc(ngx_pool_t *pool, size_t size)
{
    return ngx_pnalloc(pool, size);
}

/*
 * nginx ngx_snprintf writes at most `max` bytes to buf, NO null terminator.
 * Returns pointer past last written byte.
 */
static inline u_char *
ngx_snprintf(u_char *buf, size_t max, const char *fmt, ...)
{
    if (max == 0) {
        return buf;
    }

    char    tmp[4096];
    va_list args;
    va_start(args, fmt);
    int n = vsnprintf(tmp, sizeof(tmp), fmt, args);
    va_end(args);

    size_t copy = (n > 0 && (size_t)n <= max) ? (size_t)n : max;
    memcpy(buf, tmp, copy);
    return buf + copy;
}

#endif /* NGX_CORE_STUB_H */
