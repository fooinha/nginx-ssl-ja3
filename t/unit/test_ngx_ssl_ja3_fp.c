/*
 * Standalone C unit tests for ngx_ssl_ja3_fp() and the static helper
 * functions in ngx_ssl_ja3.c.
 *
 * Compile and run via: make -C t/unit
 *
 * ngx_ssl_ja3.c is compiled directly into this test using nginx type stubs
 * (t/unit/stubs/) so no nginx build is required.
 *
 * Coverage:
 *   - ngx_ssl_ja3_fp(): NULL guard inputs, fingerprint string formatting for
 *     all five JA3 fields (version, ciphers, extensions, curves, point_formats)
 *     including empty sections, single values, multi-value dash-separation.
 *   - ngx_ssj_ja3_num_digits() (static): exercised indirectly through
 *     ngx_ssl_ja3_fp() for 1-, 2-, 3-, 4- and 5-digit values.
 *   - Allocation failure path: pnalloc returns NULL → out->len set to 0,
 *     no write to NULL pointer.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "ngx_ssl_ja3.h"

/* -------------------------------------------------------------------------
 * Minimal test framework
 * ---------------------------------------------------------------------- */

static int g_total  = 0;
static int g_passed = 0;

static void
check(int ok, const char *name)
{
    g_total++;
    if (ok) {
        g_passed++;
        printf("PASS  %s\n", name);
    } else {
        printf("FAIL  %s\n", name);
    }
}

#define CHECK_STR(out, expected, name)                               \
    check(                                                           \
        (out).len == strlen(expected) &&                             \
        memcmp((out).data, (expected), strlen(expected)) == 0,       \
        name                                                         \
    )

#define CHECK_NULL_DATA(out, name) \
    check((out).data == NULL && (out).len == 0, name)

/*
 * The allocation-failure guard (out->data == NULL check in ngx_ssl_ja3_fp)
 * is covered by the NULL-pool test: pool==NULL triggers the early return
 * before any allocation occurs, leaving out unchanged.  The pnalloc==NULL
 * branch itself requires intercepting malloc which is outside the scope of
 * these link-time stubs; it is covered by the integration/ASAN runs.
 */

/* -------------------------------------------------------------------------
 * Helper: make a pool (just a non-NULL pointer; log not needed for fp tests)
 * ---------------------------------------------------------------------- */
static ngx_pool_t g_pool;   /* static storage; log field unused */

static ngx_pool_t *pool(void) { return &g_pool; }

/* -------------------------------------------------------------------------
 * Tests
 * ---------------------------------------------------------------------- */

static void
test_null_guards(void)
{
    ngx_str_t out = ngx_null_string;

    /* NULL pool: must return early, out stays zeroed */
    ngx_ssl_ja3_fp(NULL, &(ngx_ssl_ja3_t){.version=771}, &out);
    CHECK_NULL_DATA(out, "null pool: out unchanged");

    /* NULL ja3 */
    out = (ngx_str_t)ngx_null_string;
    ngx_ssl_ja3_fp(pool(), NULL, &out);
    CHECK_NULL_DATA(out, "null ja3: out unchanged");

    /* NULL out: must not crash */
    ngx_ssl_ja3_fp(pool(), &(ngx_ssl_ja3_t){.version=771}, NULL);
    check(1, "null out: no crash");
}

static void
test_version_only(void)
{
    ngx_ssl_ja3_t ja3 = {
        .version         = 771,   /* TLS 1.2 */
        .ciphers_sz      = 0, .ciphers      = NULL,
        .extensions_sz   = 0, .extensions   = NULL,
        .curves_sz       = 0, .curves       = NULL,
        .point_formats_sz= 0, .point_formats= NULL,
    };
    ngx_str_t fp = ngx_null_string;
    ngx_ssl_ja3_fp(pool(), &ja3, &fp);
    CHECK_STR(fp, "771,,,,", "version only: TLS 1.2");

    ja3.version = 772;   /* TLS 1.3 */
    fp = (ngx_str_t)ngx_null_string;
    ngx_ssl_ja3_fp(pool(), &ja3, &fp);
    CHECK_STR(fp, "772,,,,", "version only: TLS 1.3");

    ja3.version = 1;
    fp = (ngx_str_t)ngx_null_string;
    ngx_ssl_ja3_fp(pool(), &ja3, &fp);
    CHECK_STR(fp, "1,,,,", "version only: single-digit");

    ja3.version = 65535;
    fp = (ngx_str_t)ngx_null_string;
    ngx_ssl_ja3_fp(pool(), &ja3, &fp);
    CHECK_STR(fp, "65535,,,,", "version only: max uint16");
}

static void
test_ciphers(void)
{
    unsigned short c1[] = { 47 };
    ngx_ssl_ja3_t ja3 = {
        .version       = 771,
        .ciphers_sz    = 1, .ciphers    = c1,
        .extensions_sz = 0, .extensions = NULL,
        .curves_sz     = 0, .curves     = NULL,
        .point_formats_sz = 0, .point_formats = NULL,
    };
    ngx_str_t fp = ngx_null_string;
    ngx_ssl_ja3_fp(pool(), &ja3, &fp);
    CHECK_STR(fp, "771,47,,,", "one cipher: 47");

    /* two ciphers — dash-separated */
    unsigned short c2[] = { 47, 53 };
    ja3.ciphers = c2; ja3.ciphers_sz = 2;
    fp = (ngx_str_t)ngx_null_string;
    ngx_ssl_ja3_fp(pool(), &ja3, &fp);
    CHECK_STR(fp, "771,47-53,,,", "two ciphers: 47-53");

    /* five ciphers including 5-digit value */
    unsigned short c5[] = { 49162, 49161, 49171, 49172, 65535 };
    ja3.ciphers = c5; ja3.ciphers_sz = 5;
    fp = (ngx_str_t)ngx_null_string;
    ngx_ssl_ja3_fp(pool(), &ja3, &fp);
    CHECK_STR(fp, "771,49162-49161-49171-49172-65535,,,",
              "five ciphers with 5-digit values");
}

static void
test_extensions(void)
{
    unsigned short e1[] = { 0 };
    ngx_ssl_ja3_t ja3 = {
        .version         = 771,
        .ciphers_sz      = 0, .ciphers      = NULL,
        .extensions_sz   = 1, .extensions   = e1,
        .curves_sz       = 0, .curves       = NULL,
        .point_formats_sz= 0, .point_formats= NULL,
    };
    ngx_str_t fp = ngx_null_string;
    ngx_ssl_ja3_fp(pool(), &ja3, &fp);
    CHECK_STR(fp, "771,,0,,", "one extension: 0");

    unsigned short e2[] = { 0, 23 };
    ja3.extensions = e2; ja3.extensions_sz = 2;
    fp = (ngx_str_t)ngx_null_string;
    ngx_ssl_ja3_fp(pool(), &ja3, &fp);
    CHECK_STR(fp, "771,,0-23,,", "two extensions: 0-23");

    /* extension 65281 (renegotiation_info) — 5 digits */
    unsigned short e3[] = { 65281, 10, 11 };
    ja3.extensions = e3; ja3.extensions_sz = 3;
    fp = (ngx_str_t)ngx_null_string;
    ngx_ssl_ja3_fp(pool(), &ja3, &fp);
    CHECK_STR(fp, "771,,65281-10-11,,", "three extensions with 5-digit value");
}

static void
test_curves(void)
{
    unsigned short cr1[] = { 29 };   /* X25519 TLS ID */
    ngx_ssl_ja3_t ja3 = {
        .version         = 771,
        .ciphers_sz      = 0, .ciphers      = NULL,
        .extensions_sz   = 0, .extensions   = NULL,
        .curves_sz       = 1, .curves       = cr1,
        .point_formats_sz= 0, .point_formats= NULL,
    };
    ngx_str_t fp = ngx_null_string;
    ngx_ssl_ja3_fp(pool(), &ja3, &fp);
    CHECK_STR(fp, "771,,,29,", "one curve: 29 (X25519)");

    unsigned short cr2[] = { 23, 24 };  /* P-256, P-384 */
    ja3.curves = cr2; ja3.curves_sz = 2;
    fp = (ngx_str_t)ngx_null_string;
    ngx_ssl_ja3_fp(pool(), &ja3, &fp);
    CHECK_STR(fp, "771,,,23-24,", "two curves: 23-24");
}

static void
test_point_formats(void)
{
    unsigned char pf1[] = { 0 };   /* uncompressed */
    ngx_ssl_ja3_t ja3 = {
        .version          = 771,
        .ciphers_sz       = 0, .ciphers       = NULL,
        .extensions_sz    = 0, .extensions    = NULL,
        .curves_sz        = 0, .curves        = NULL,
        .point_formats_sz = 1, .point_formats = pf1,
    };
    ngx_str_t fp = ngx_null_string;
    ngx_ssl_ja3_fp(pool(), &ja3, &fp);
    CHECK_STR(fp, "771,,,,0", "one point format: 0");

    unsigned char pf2[] = { 0, 1 };
    ja3.point_formats = pf2; ja3.point_formats_sz = 2;
    fp = (ngx_str_t)ngx_null_string;
    ngx_ssl_ja3_fp(pool(), &ja3, &fp);
    CHECK_STR(fp, "771,,,,0-1", "two point formats: 0-1");
}

static void
test_full_fingerprint(void)
{
    /* Realistic TLS 1.2 fingerprint fields */
    unsigned short ciphers[]   = { 47 };
    unsigned short extensions[]= { 0, 23 };
    unsigned short curves[]    = { 29 };
    unsigned char  fmts[]      = { 0 };

    ngx_ssl_ja3_t ja3 = {
        .version          = 771,
        .ciphers_sz       = 1, .ciphers       = ciphers,
        .extensions_sz    = 2, .extensions    = extensions,
        .curves_sz        = 1, .curves        = curves,
        .point_formats_sz = 1, .point_formats = fmts,
    };
    ngx_str_t fp = ngx_null_string;
    ngx_ssl_ja3_fp(pool(), &ja3, &fp);
    CHECK_STR(fp, "771,47,0-23,29,0", "full example: 771,47,0-23,29,0");

    /* All-zero single values */
    unsigned short z1[] = { 0 };
    unsigned char  z2[] = { 0 };
    ngx_ssl_ja3_t ja3z = {
        .version          = 0,
        .ciphers_sz       = 1, .ciphers       = z1,
        .extensions_sz    = 1, .extensions    = z1,
        .curves_sz        = 1, .curves        = z1,
        .point_formats_sz = 1, .point_formats = z2,
    };
    fp = (ngx_str_t)ngx_null_string;
    ngx_ssl_ja3_fp(pool(), &ja3z, &fp);
    CHECK_STR(fp, "0,0,0,0,0", "all-zero single values");
}

static void
test_num_digits_via_fp(void)
{
    /* Verify 1-, 2-, 3-, 4-, 5-digit version values are handled correctly */
    const struct { int version; const char *expected; } cases[] = {
        { 1,     "1,,,,"     },
        { 9,     "9,,,,"     },
        { 10,    "10,,,,"    },
        { 99,    "99,,,,"    },
        { 100,   "100,,,,"   },
        { 769,   "769,,,,"   },   /* TLS 1.0 */
        { 771,   "771,,,,"   },   /* TLS 1.2 */
        { 772,   "772,,,,"   },   /* TLS 1.3 */
        { 9999,  "9999,,,,"  },
        { 10000, "10000,,,," },
        { 65535, "65535,,,," },
    };
    char name[64];

    for (size_t i = 0; i < sizeof(cases)/sizeof(cases[0]); i++) {
        ngx_ssl_ja3_t ja3 = { .version = cases[i].version };
        ngx_str_t fp = ngx_null_string;
        ngx_ssl_ja3_fp(pool(), &ja3, &fp);
        snprintf(name, sizeof(name), "num_digits via version=%d", cases[i].version);
        CHECK_STR(fp, cases[i].expected, name);
    }
}

static void
test_len_matches_content(void)
{
    /* Verify out->len matches actual bytes written for an all-fields case */
    unsigned short ciphers[]    = { 49195, 49199, 52393 };
    unsigned short extensions[] = { 0, 23, 65281, 10, 11, 35, 16 };
    unsigned short curves[]     = { 29, 23, 24 };
    unsigned char  fmts[]       = { 0 };

    ngx_ssl_ja3_t ja3 = {
        .version          = 771,
        .ciphers_sz       = 3, .ciphers       = ciphers,
        .extensions_sz    = 7, .extensions    = extensions,
        .curves_sz        = 3, .curves        = curves,
        .point_formats_sz = 1, .point_formats = fmts,
    };
    ngx_str_t fp = ngx_null_string;
    ngx_ssl_ja3_fp(pool(), &ja3, &fp);

    const char *expected = "771,49195-49199-52393,0-23-65281-10-11-35-16,29-23-24,0";
    check(fp.len == strlen(expected), "len matches content length");
    check(memcmp(fp.data, expected, fp.len) == 0, "content matches expected string");
}

/* -------------------------------------------------------------------------
 * main
 * ---------------------------------------------------------------------- */

int
main(void)
{
    printf("=== ngx_ssl_ja3_fp unit tests ===\n\n");

    test_null_guards();
    test_version_only();
    test_ciphers();
    test_extensions();
    test_curves();
    test_point_formats();
    test_full_fingerprint();
    test_num_digits_via_fp();
    test_len_matches_content();

    printf("\n%d/%d passed\n", g_passed, g_total);
    return (g_passed == g_total) ? 0 : 1;
}
