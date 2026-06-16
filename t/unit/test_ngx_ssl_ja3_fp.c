/*
 * Standalone C unit tests for ngx_ssl_ja3.c static helpers and public API.
 *
 * Compile and run via: make -C t/unit
 *
 * ngx_ssl_ja3.c is #include'd directly (not compiled as a separate TU) so
 * that static symbols are visible to the tests.
 *
 * Coverage:
 *   ngx_ssl_ja3_fp()         — NULL guards, all five JA3 fields, single /
 *                               multi values, dash-separation, OOM path.
 *   ngx_ssj_ja3_num_digits() — exercised indirectly via ngx_ssl_ja3_fp()
 *                               for 1- through 5-digit values.
 *   ngx_ssl_ja3_is_ext_greased() — all 16 GREASE constants + non-GREASE.
 *   ngx_ssl_ja3_nid_to_cid() — NID→wire-ID table hits (OpenSSL 1.x path),
 *                               ffdhe range (0x100-0x104), pass-through.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/*
 * Pull in the implementation as part of this TU so static functions are
 * accessible.  The Makefile must NOT list ngx_ssl_ja3.c in SRCS.
 */
#include "../../src/ngx_ssl_ja3.c"

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

/* -------------------------------------------------------------------------
 * Helper: stable pool pointer (log field unused by fp tests)
 * ---------------------------------------------------------------------- */
static ngx_pool_t g_pool;
static ngx_pool_t *pool(void) { return &g_pool; }

/* -------------------------------------------------------------------------
 * ngx_ssl_ja3_fp — NULL guards
 * ---------------------------------------------------------------------- */

static void
test_null_guards(void)
{
    ngx_str_t out = ngx_null_string;

    ngx_ssl_ja3_fp(NULL, &(ngx_ssl_ja3_t){.version=771}, &out);
    CHECK_NULL_DATA(out, "null pool: out unchanged");

    out = (ngx_str_t)ngx_null_string;
    ngx_ssl_ja3_fp(pool(), NULL, &out);
    CHECK_NULL_DATA(out, "null ja3: out unchanged");

    ngx_ssl_ja3_fp(pool(), &(ngx_ssl_ja3_t){.version=771}, NULL);
    check(1, "null out: no crash");
}

/* -------------------------------------------------------------------------
 * ngx_ssl_ja3_fp — OOM (ngx_pnalloc returns NULL)
 * ---------------------------------------------------------------------- */

static void
test_alloc_failure(void)
{
    ngx_ssl_ja3_t ja3 = { .version = 771 };
    ngx_str_t fp = ngx_null_string;

    ngx_pnalloc_fail_next = 1;
    ngx_ssl_ja3_fp(pool(), &ja3, &fp);
    check(fp.len == 0,    "OOM: out->len set to 0");
    check(fp.data == NULL, "OOM: out->data is NULL");
}

/* -------------------------------------------------------------------------
 * ngx_ssl_ja3_fp — version field
 * ---------------------------------------------------------------------- */

static void
test_version_only(void)
{
    ngx_ssl_ja3_t ja3 = {
        .version         = 771,
        .ciphers_sz      = 0, .ciphers      = NULL,
        .extensions_sz   = 0, .extensions   = NULL,
        .curves_sz       = 0, .curves       = NULL,
        .point_formats_sz= 0, .point_formats= NULL,
    };
    ngx_str_t fp = ngx_null_string;
    ngx_ssl_ja3_fp(pool(), &ja3, &fp);
    CHECK_STR(fp, "771,,,,", "version only: TLS 1.2");

    ja3.version = 772;
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

/* -------------------------------------------------------------------------
 * ngx_ssl_ja3_fp — cipher field
 * ---------------------------------------------------------------------- */

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

    unsigned short c2[] = { 47, 53 };
    ja3.ciphers = c2; ja3.ciphers_sz = 2;
    fp = (ngx_str_t)ngx_null_string;
    ngx_ssl_ja3_fp(pool(), &ja3, &fp);
    CHECK_STR(fp, "771,47-53,,,", "two ciphers: 47-53");

    unsigned short c5[] = { 49162, 49161, 49171, 49172, 65535 };
    ja3.ciphers = c5; ja3.ciphers_sz = 5;
    fp = (ngx_str_t)ngx_null_string;
    ngx_ssl_ja3_fp(pool(), &ja3, &fp);
    CHECK_STR(fp, "771,49162-49161-49171-49172-65535,,,",
              "five ciphers with 5-digit values");
}

/* -------------------------------------------------------------------------
 * ngx_ssl_ja3_fp — extensions field
 * ---------------------------------------------------------------------- */

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

    unsigned short e3[] = { 65281, 10, 11 };
    ja3.extensions = e3; ja3.extensions_sz = 3;
    fp = (ngx_str_t)ngx_null_string;
    ngx_ssl_ja3_fp(pool(), &ja3, &fp);
    CHECK_STR(fp, "771,,65281-10-11,,", "three extensions with 5-digit value");
}

/* -------------------------------------------------------------------------
 * ngx_ssl_ja3_fp — curves field
 * ---------------------------------------------------------------------- */

static void
test_curves(void)
{
    unsigned short cr1[] = { 29 };
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

    unsigned short cr2[] = { 23, 24 };
    ja3.curves = cr2; ja3.curves_sz = 2;
    fp = (ngx_str_t)ngx_null_string;
    ngx_ssl_ja3_fp(pool(), &ja3, &fp);
    CHECK_STR(fp, "771,,,23-24,", "two curves: 23-24");
}

/* -------------------------------------------------------------------------
 * ngx_ssl_ja3_fp — point_formats field
 * ---------------------------------------------------------------------- */

static void
test_point_formats(void)
{
    unsigned char pf1[] = { 0 };
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

/* -------------------------------------------------------------------------
 * ngx_ssl_ja3_fp — full fingerprint
 * ---------------------------------------------------------------------- */

static void
test_full_fingerprint(void)
{
    unsigned short ciphers[]    = { 47 };
    unsigned short extensions[] = { 0, 23 };
    unsigned short curves[]     = { 29 };
    unsigned char  fmts[]       = { 0 };

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

/* -------------------------------------------------------------------------
 * ngx_ssj_ja3_num_digits — exercised indirectly via version field
 * ---------------------------------------------------------------------- */

static void
test_num_digits_via_fp(void)
{
    const struct { int version; const char *expected; } cases[] = {
        { 1,     "1,,,,"     },
        { 9,     "9,,,,"     },
        { 10,    "10,,,,"    },
        { 99,    "99,,,,"    },
        { 100,   "100,,,,"   },
        { 769,   "769,,,,"   },
        { 771,   "771,,,,"   },
        { 772,   "772,,,,"   },
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

/* -------------------------------------------------------------------------
 * ngx_ssl_ja3_fp — out->len matches bytes written
 * ---------------------------------------------------------------------- */

static void
test_len_matches_content(void)
{
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
 * ngx_ssl_ja3_is_ext_greased — all 16 GREASE values + non-GREASE
 * ---------------------------------------------------------------------- */

static void
test_is_ext_greased(void)
{
    static const unsigned short grease[] = {
        0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
        0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa,
    };
    char name[48];

    for (size_t i = 0; i < sizeof(grease)/sizeof(grease[0]); i++) {
        snprintf(name, sizeof(name), "grease: 0x%04x is GREASE", grease[i]);
        check(ngx_ssl_ja3_is_ext_greased(grease[i]) == 1, name);
    }

    static const int non_grease[] = { 0, 1, 23, 47, 771, 0x1000, 65535 };
    for (size_t i = 0; i < sizeof(non_grease)/sizeof(non_grease[0]); i++) {
        snprintf(name, sizeof(name), "grease: 0x%04x is not GREASE", non_grease[i]);
        check(ngx_ssl_ja3_is_ext_greased(non_grease[i]) == 0, name);
    }
}

/* -------------------------------------------------------------------------
 * ngx_ssl_ja3_nid_to_cid — NID table hits, ffdhe range, pass-through
 * ---------------------------------------------------------------------- */

static void
test_nid_to_cid(void)
{
    /* TLS wire values pass through unchanged (OpenSSL 3 SSL_get1_curves path) */
    check(ngx_ssl_ja3_nid_to_cid(0)  == 0,  "nid_to_cid: wire 0 passes through");
    check(ngx_ssl_ja3_nid_to_cid(23) == 23, "nid_to_cid: wire 23 (secp256r1) passes through");
    check(ngx_ssl_ja3_nid_to_cid(29) == 29, "nid_to_cid: wire 29 (X25519) passes through");

    /* ffdhe finite-field DH groups */
    check(ngx_ssl_ja3_nid_to_cid(NID_ffdhe2048) == 0x100, "nid_to_cid: NID_ffdhe2048 -> 0x100");
    check(ngx_ssl_ja3_nid_to_cid(NID_ffdhe3072) == 0x101, "nid_to_cid: NID_ffdhe3072 -> 0x101");
    check(ngx_ssl_ja3_nid_to_cid(NID_ffdhe4096) == 0x102, "nid_to_cid: NID_ffdhe4096 -> 0x102");
    check(ngx_ssl_ja3_nid_to_cid(NID_ffdhe6144) == 0x103, "nid_to_cid: NID_ffdhe6144 -> 0x103");
    check(ngx_ssl_ja3_nid_to_cid(NID_ffdhe8192) == 0x104, "nid_to_cid: NID_ffdhe8192 -> 0x104");

    /* NID table lookup (OpenSSL 1.x SSL_get1_curves returned NIDs) */
    check(ngx_ssl_ja3_nid_to_cid(NID_sect163k1)        ==  1, "nid_to_cid: NID_sect163k1 -> 1");
    check(ngx_ssl_ja3_nid_to_cid(NID_X9_62_prime256v1) == 23, "nid_to_cid: NID_secp256r1 -> 23");
    check(ngx_ssl_ja3_nid_to_cid(NID_secp384r1)        == 24, "nid_to_cid: NID_secp384r1 -> 24");
    check(ngx_ssl_ja3_nid_to_cid(NID_secp521r1)        == 25, "nid_to_cid: NID_secp521r1 -> 25");
    check(ngx_ssl_ja3_nid_to_cid(NID_X25519)           == 29, "nid_to_cid: NID_X25519 -> 29");
    check(ngx_ssl_ja3_nid_to_cid(NID_X448)             == 30, "nid_to_cid: NID_X448 -> 30");
}

/* -------------------------------------------------------------------------
 * main
 * ---------------------------------------------------------------------- */

int
main(void)
{
    printf("=== ngx_ssl_ja3_fp unit tests ===\n\n");

    test_null_guards();
    test_alloc_failure();
    test_version_only();
    test_ciphers();
    test_extensions();
    test_curves();
    test_point_formats();
    test_full_fingerprint();
    test_num_digits_via_fp();
    test_len_matches_content();
    test_is_ext_greased();
    test_nid_to_cid();

    printf("\n%d/%d passed\n", g_passed, g_total);
    return (g_passed == g_total) ? 0 : 1;
}
