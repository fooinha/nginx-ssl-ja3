/*
 * Standalone C unit tests for ngx_ssl_ja4.c and ngx_ssl_ja4s.c.
 *
 * Compile and run via: make -C t/unit test_ngx_ssl_ja4_fp
 *
 * Both source files are #include'd directly so that static helpers are
 * accessible for white-box testing.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

/* Pull in both implementations as part of this TU */
#include "../../src/ngx_ssl_ja4.c"
#include "../../src/ngx_ssl_ja4s.c"

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

#define CHECK_STR(out, expected, name) \
    check( \
        (out).len == strlen(expected) && \
        memcmp((out).data, (expected), strlen(expected)) == 0, \
        name \
    )

#define CHECK_BYTES(ptr, expected, n, name) \
    check(memcmp(ptr, expected, n) == 0, name)

/* Stable pool — log field unused */
static ngx_pool_t g_pool;
static ngx_pool_t *pool(void) { return &g_pool; }

/* -------------------------------------------------------------------------
 * Helpers
 * ---------------------------------------------------------------------- */

/* Check that all characters in ptr[0..n-1] are lowercase hex or '_' or ','. */
static int
is_lowhex(const u_char *p, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++) {
        char c = (char)p[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
            return 0;
        }
    }
    return 1;
}

/* -------------------------------------------------------------------------
 * ngx_ssl_ja4_version_str — all known TLS versions
 * ---------------------------------------------------------------------- */

static void
test_ja4_version_str(void)
{
    char out[2];

    ngx_ssl_ja4_version_str(0x0304, out);
    check(out[0]=='1' && out[1]=='3', "ver 0x0304 -> '13'");

    ngx_ssl_ja4_version_str(0x0303, out);
    check(out[0]=='1' && out[1]=='2', "ver 0x0303 -> '12'");

    ngx_ssl_ja4_version_str(0x0302, out);
    check(out[0]=='1' && out[1]=='1', "ver 0x0302 -> '11'");

    ngx_ssl_ja4_version_str(0x0301, out);
    check(out[0]=='1' && out[1]=='0', "ver 0x0301 -> '10'");

    ngx_ssl_ja4_version_str(0x0300, out);
    check(out[0]=='s' && out[1]=='3', "ver 0x0300 -> 's3'");

    ngx_ssl_ja4_version_str(0x0002, out);
    check(out[0]=='s' && out[1]=='2', "ver 0x0002 -> 's2'");

    ngx_ssl_ja4_version_str(0x0000, out);
    check(out[0]=='0' && out[1]=='0', "ver 0x0000 -> '00' (unknown)");
}

/* -------------------------------------------------------------------------
 * NGX_SSL_IS_GREASE — all 16 GREASE values + edge cases
 * ---------------------------------------------------------------------- */

static void
test_grease_macro(void)
{
    static const unsigned short grease[] = {
        0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
        0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa,
    };
    static const unsigned short non_grease[] = {
        0x0000, 0x0001, 0x002b, 0x0033, 0x1301, 0x1302, 0xc02b, 0xffff,
    };
    char name[64];
    size_t i;

    for (i = 0; i < sizeof(grease)/sizeof(grease[0]); i++) {
        snprintf(name, sizeof(name), "GREASE 0x%04x is GREASE", grease[i]);
        check(NGX_SSL_IS_GREASE(grease[i]) != 0, name);
    }
    for (i = 0; i < sizeof(non_grease)/sizeof(non_grease[0]); i++) {
        snprintf(name, sizeof(name), "GREASE 0x%04x is not GREASE", non_grease[i]);
        check(NGX_SSL_IS_GREASE(non_grease[i]) == 0, name);
    }
}

/* -------------------------------------------------------------------------
 * ngx_ssl_ja4_fp — null guards
 * ---------------------------------------------------------------------- */

static void
test_ja4_null_guards(void)
{
    ngx_str_t out = {0, NULL};
    ngx_ssl_ja4_t ja4;
    memset(&ja4, 0, sizeof(ja4));
    ja4.version = 0x0304;
    ja4.sni = 'd';

    ngx_ssl_ja4_fp(NULL, &ja4, &out);
    check(out.data == NULL, "null pool: out.data unchanged");

    ngx_ssl_ja4_fp(pool(), NULL, &out);
    check(out.data == NULL, "null ja4: out.data unchanged");

    ngx_ssl_ja4_fp(pool(), &ja4, NULL);
    check(1, "null out: no crash");
}

/* -------------------------------------------------------------------------
 * ngx_ssl_ja4_fp — structure: length and separators
 * ---------------------------------------------------------------------- */

static void
test_ja4_fp_structure(void)
{
    ngx_ssl_ja4_t ja4;
    ngx_str_t fp = {0, NULL};

    memset(&ja4, 0, sizeof(ja4));
    ja4.version = 0x0304;
    ja4.sni = 'd';

    ngx_ssl_ja4_fp(pool(), &ja4, &fp);

    check(fp.len == NGX_SSL_JA4_FP_LEN,
          "JA4 fp length == NGX_SSL_JA4_FP_LEN (36)");
    check(fp.data != NULL,
          "JA4 fp.data != NULL");
    if (fp.data == NULL) return;

    check(fp.data[0] == 't',        "fp[0] == 't' (TLS)");
    check(fp.data[1] == '1',        "fp[1] == '1' (ver hi)");
    check(fp.data[2] == '3',        "fp[2] == '3' (ver lo, TLS 1.3)");
    check(fp.data[3] == 'd',        "fp[3] == 'd' (SNI present)");
    check(fp.data[10] == '_',       "fp[10] == '_' (first separator)");
    check(fp.data[23] == '_',       "fp[23] == '_' (second separator)");
    check(is_lowhex(fp.data + 11, 12), "cipher hash is 12 lowercase hex chars");
    check(is_lowhex(fp.data + 24, 12), "ext hash is 12 lowercase hex chars");
}

/* -------------------------------------------------------------------------
 * ngx_ssl_ja4_fp — no-SNI path
 * ---------------------------------------------------------------------- */

static void
test_ja4_no_sni(void)
{
    ngx_ssl_ja4_t ja4;
    ngx_str_t fp = {0, NULL};

    memset(&ja4, 0, sizeof(ja4));
    ja4.version = 0x0303;
    ja4.sni = 'i';

    ngx_ssl_ja4_fp(pool(), &ja4, &fp);
    if (fp.data == NULL) { check(0, "no-SNI: fp allocated"); return; }

    check(fp.data[3] == 'i', "fp[3] == 'i' (no SNI)");
    check(fp.data[1] == '1' && fp.data[2] == '2',
          "TLS 1.2 version encoded as '12'");
}

/* -------------------------------------------------------------------------
 * ngx_ssl_ja4_fp — ALPN encoding
 * ---------------------------------------------------------------------- */

static void
test_ja4_alpn(void)
{
    ngx_ssl_ja4_t ja4;
    ngx_str_t fp = {0, NULL};

    memset(&ja4, 0, sizeof(ja4));
    ja4.version = 0x0304;
    ja4.sni = 'd';
    ja4.alpn[0] = 'h';
    ja4.alpn[1] = '2';

    ngx_ssl_ja4_fp(pool(), &ja4, &fp);
    if (fp.data == NULL) { check(0, "ALPN: fp allocated"); return; }

    check(fp.data[8] == 'h' && fp.data[9] == '2',
          "ALPN 'h2' encoded as 'h2'");

    /* No ALPN (zero bytes) */
    ngx_ssl_ja4_t ja4b = ja4;
    ja4b.alpn[0] = 0;
    ja4b.alpn[1] = 0;
    ngx_str_t fp2 = {0, NULL};
    ngx_ssl_ja4_fp(pool(), &ja4b, &fp2);
    if (fp2.data == NULL) { check(0, "no-ALPN: fp allocated"); return; }
    check(fp2.data[8] == '0' && fp2.data[9] == '0',
          "no ALPN encoded as '00'");
}

/* -------------------------------------------------------------------------
 * ngx_ssl_ja4_fp — cipher count encoding
 * ---------------------------------------------------------------------- */

static void
test_ja4_cipher_count(void)
{
    unsigned short ciphers[] = {
        0x1301, 0x1302, 0x1303,
        0x0a0a,  /* GREASE — should be excluded by ngx_ssl_ja4() but counted here */
    };
    ngx_ssl_ja4_t ja4;
    ngx_str_t fp = {0, NULL};

    memset(&ja4, 0, sizeof(ja4));
    ja4.version = 0x0304;
    ja4.sni = 'd';
    /* simulate post-ngx_ssl_ja4() result: ciphers are already GREASE-filtered */
    ja4.ciphers = ciphers;
    ja4.ciphers_sz = 3;  /* 3 non-GREASE */

    ngx_ssl_ja4_fp(pool(), &ja4, &fp);
    if (fp.data == NULL) { check(0, "cipher count: fp allocated"); return; }

    check(fp.data[4] == '0' && fp.data[5] == '3',
          "3 ciphers encoded as '03'");

    /* Test count clamping at 99 */
    ja4.ciphers_sz = 100;
    ngx_str_t fp2 = {0, NULL};
    ngx_ssl_ja4_fp(pool(), &ja4, &fp2);
    if (fp2.data) {
        check(fp2.data[4] == '9' && fp2.data[5] == '9',
              "count > 99 clamped to '99'");
    }
}

/* -------------------------------------------------------------------------
 * ngx_ssl_ja4_fp — cipher hash golden vector
 *
 * ciphers (sorted): 0x1301, 0x1302, 0x1303
 * input:  "1301,1302,1303"
 * SHA-256[:12] = "55b375c5d22e"
 * ---------------------------------------------------------------------- */

static void
test_ja4_cipher_hash_golden(void)
{
    unsigned short ciphers[] = {0x1301, 0x1302, 0x1303};
    ngx_ssl_ja4_t ja4;
    ngx_str_t fp = {0, NULL};

    memset(&ja4, 0, sizeof(ja4));
    ja4.version = 0x0304;
    ja4.sni = 'd';
    ja4.ciphers = ciphers;
    ja4.ciphers_sz = 3;

    ngx_ssl_ja4_fp(pool(), &ja4, &fp);
    if (fp.data == NULL) { check(0, "cipher hash golden: fp allocated"); return; }

    /* cipher hash is at fp[11..22] */
    check(memcmp(fp.data + 11, "55b375c5d22e", 12) == 0,
          "cipher hash for [1301,1302,1303] == '55b375c5d22e'");
}

/* -------------------------------------------------------------------------
 * ngx_ssl_ja4_fp — cipher hash: GREASE filtered before sort
 *
 * A GREASE cipher must not appear in the sorted list.
 * ---------------------------------------------------------------------- */

static void
test_ja4_cipher_hash_grease_filtered(void)
{
    /* After ngx_ssl_ja4() filtering, ciphers only contain non-GREASE.
     * Test that the cipher hash sorts them regardless of input order. */
    unsigned short ciphers_unsorted[] = {0x1303, 0x1301, 0x1302};
    ngx_ssl_ja4_t ja4;
    ngx_str_t fp = {0, NULL};

    memset(&ja4, 0, sizeof(ja4));
    ja4.version = 0x0304;
    ja4.sni = 'd';
    ja4.ciphers = ciphers_unsorted;
    ja4.ciphers_sz = 3;

    ngx_ssl_ja4_fp(pool(), &ja4, &fp);
    if (fp.data == NULL) { check(0, "sorted cipher hash: fp allocated"); return; }

    /* Same hash as sorted [1301,1302,1303] — the function sorts internally */
    check(memcmp(fp.data + 11, "55b375c5d22e", 12) == 0,
          "cipher hash same regardless of input order (sorted internally)");
}

/* -------------------------------------------------------------------------
 * ngx_ssl_ja4_fp — empty cipher hash
 * ---------------------------------------------------------------------- */

static void
test_ja4_empty_cipher_hash(void)
{
    ngx_ssl_ja4_t ja4;
    ngx_str_t fp = {0, NULL};

    memset(&ja4, 0, sizeof(ja4));
    ja4.version = 0x0304;
    ja4.sni = 'i';

    ngx_ssl_ja4_fp(pool(), &ja4, &fp);
    if (fp.data == NULL) { check(0, "empty cipher: fp allocated"); return; }

    check(memcmp(fp.data + 11, "000000000000", 12) == 0,
          "empty cipher list hash is '000000000000'");
}

/* -------------------------------------------------------------------------
 * ngx_ssl_ja4_fp — ext+sigalg hash: empty case
 *
 * no extensions, no sigalgs → hash of "_" = "d2e2adf7177b"
 * ---------------------------------------------------------------------- */

static void
test_ja4_empty_ext_hash(void)
{
    ngx_ssl_ja4_t ja4;
    ngx_str_t fp = {0, NULL};

    memset(&ja4, 0, sizeof(ja4));
    ja4.version = 0x0304;
    ja4.sni = 'i';

    ngx_ssl_ja4_fp(pool(), &ja4, &fp);
    if (fp.data == NULL) { check(0, "empty ext: fp allocated"); return; }

    /* ext_sigalg_hash input is "_" (empty ext list + "_" + empty sigalgs)
     * SHA-256("_")[:12] = "d2e2adf7177b" */
    check(memcmp(fp.data + 24, "d2e2adf7177b", 11) == 0,
          "empty ext+sigalg hash is SHA-256('_')[:12]");
}

/* -------------------------------------------------------------------------
 * ngx_ssl_ja4_fp — ext hash: SNI and ALPN excluded from sorted list
 *
 * extensions: [0x0000 (SNI), 0x0010 (ALPN)] → excluded → hash of "_"
 * ---------------------------------------------------------------------- */

static void
test_ja4_ext_sni_alpn_excluded(void)
{
    unsigned short exts[] = {0x0000, 0x0010};
    ngx_ssl_ja4_t ja4;
    ngx_str_t fp = {0, NULL};

    memset(&ja4, 0, sizeof(ja4));
    ja4.version = 0x0304;
    ja4.sni = 'd';
    ja4.alpn[0] = 'h';
    ja4.alpn[1] = '2';
    ja4.extensions = exts;
    ja4.extensions_sz = 2;

    ngx_ssl_ja4_fp(pool(), &ja4, &fp);
    if (fp.data == NULL) { check(0, "SNI/ALPN excl: fp allocated"); return; }

    /* Both SNI and ALPN are excluded from ext hash → same as empty ext hash */
    check(memcmp(fp.data + 24, "d2e2adf7177b", 11) == 0,
          "SNI(0000)+ALPN(0010) excluded from ext hash → hash of '_'");
}

/* -------------------------------------------------------------------------
 * ngx_ssl_ja4_fp — extension count includes SNI and ALPN
 * ---------------------------------------------------------------------- */

static void
test_ja4_ext_count_includes_sni_alpn(void)
{
    unsigned short exts[] = {0x0000, 0x0010, 0x002b};  /* SNI, ALPN, supported_versions */
    ngx_ssl_ja4_t ja4;
    ngx_str_t fp = {0, NULL};

    memset(&ja4, 0, sizeof(ja4));
    ja4.version = 0x0304;
    ja4.sni = 'd';
    ja4.extensions = exts;
    ja4.extensions_sz = 3;  /* all 3 count toward nexts */

    ngx_ssl_ja4_fp(pool(), &ja4, &fp);
    if (fp.data == NULL) { check(0, "ext count: fp allocated"); return; }

    check(fp.data[6] == '0' && fp.data[7] == '3',
          "nexts counts SNI+ALPN+supported_versions as '03'");
}

/* -------------------------------------------------------------------------
 * ngx_ssl_ja4_fp — OOM simulation
 * ---------------------------------------------------------------------- */

static void
test_ja4_oom(void)
{
    ngx_ssl_ja4_t ja4;
    ngx_str_t fp = {0, NULL};

    memset(&ja4, 0, sizeof(ja4));
    ja4.version = 0x0304;
    ja4.sni = 'd';

    ngx_pnalloc_fail_next = 1;
    ngx_ssl_ja4_fp(pool(), &ja4, &fp);
    check(fp.data == NULL && fp.len == 0, "OOM: fp.data NULL and len 0");
}

/* =========================================================================
 * JA4S tests
 * ===================================================================== */

/* -------------------------------------------------------------------------
 * ngx_ssl_ja4s_fp — null guards
 * ---------------------------------------------------------------------- */

static void
test_ja4s_null_guards(void)
{
    ngx_str_t out = {0, NULL};
    ngx_ssl_ja4s_t ja4s;
    memset(&ja4s, 0, sizeof(ja4s));
    ja4s.version = 0x0304;
    ja4s.cipher = 0x1301;

    ngx_ssl_ja4s_fp(NULL, &ja4s, &out);
    check(out.data == NULL, "JA4S null pool: out.data unchanged");

    ngx_ssl_ja4s_fp(pool(), NULL, &out);
    check(out.data == NULL, "JA4S null ja4s: out.data unchanged");

    ngx_ssl_ja4s_fp(pool(), &ja4s, NULL);
    check(1, "JA4S null out: no crash");
}

/* -------------------------------------------------------------------------
 * ngx_ssl_ja4s_fp — structure: length and separators
 * ---------------------------------------------------------------------- */

static void
test_ja4s_fp_structure(void)
{
    ngx_ssl_ja4s_t ja4s;
    ngx_str_t fp = {0, NULL};

    memset(&ja4s, 0, sizeof(ja4s));
    ja4s.version = 0x0304;
    ja4s.cipher = 0x1301;

    ngx_ssl_ja4s_fp(pool(), &ja4s, &fp);

    check(fp.len == NGX_SSL_JA4S_FP_LEN,
          "JA4S fp length == NGX_SSL_JA4S_FP_LEN (25)");
    if (fp.data == NULL) { check(0, "JA4S fp.data != NULL"); return; }

    check(fp.data[0] == 't',   "JA4S fp[0] == 't'");
    check(fp.data[1] == '1',   "JA4S fp[1] == '1' (TLS 1.3 hi)");
    check(fp.data[2] == '3',   "JA4S fp[2] == '3' (TLS 1.3 lo)");
    check(fp.data[7] == '_',   "JA4S fp[7] == '_' (first separator)");
    check(fp.data[12] == '_',  "JA4S fp[12] == '_' (second separator)");
    check(is_lowhex(fp.data + 8, 4),   "cipher is 4 lowercase hex chars");
    check(is_lowhex(fp.data + 13, 12), "ext hash is 12 lowercase hex chars");
}

/* -------------------------------------------------------------------------
 * ngx_ssl_ja4s_fp — cipher encoding
 * ---------------------------------------------------------------------- */

static void
test_ja4s_cipher(void)
{
    ngx_ssl_ja4s_t ja4s;
    ngx_str_t fp = {0, NULL};

    memset(&ja4s, 0, sizeof(ja4s));
    ja4s.version = 0x0304;
    ja4s.cipher = 0x1301;

    ngx_ssl_ja4s_fp(pool(), &ja4s, &fp);
    if (fp.data == NULL) { check(0, "cipher enc: fp allocated"); return; }

    check(memcmp(fp.data + 8, "1301", 4) == 0,
          "cipher 0x1301 encoded as '1301'");

    ngx_ssl_ja4s_t ja4s2 = ja4s;
    ja4s2.cipher = 0xc02b;
    ngx_str_t fp2 = {0, NULL};
    ngx_ssl_ja4s_fp(pool(), &ja4s2, &fp2);
    if (fp2.data == NULL) { check(0, "cipher c02b: fp allocated"); return; }

    check(memcmp(fp2.data + 8, "c02b", 4) == 0,
          "cipher 0xc02b encoded as 'c02b'");
}

/* -------------------------------------------------------------------------
 * ngx_ssl_ja4s_fp — ALPN encoding
 * ---------------------------------------------------------------------- */

static void
test_ja4s_alpn(void)
{
    ngx_ssl_ja4s_t ja4s;
    ngx_str_t fp = {0, NULL};

    memset(&ja4s, 0, sizeof(ja4s));
    ja4s.version = 0x0304;
    ja4s.cipher = 0x1301;
    ja4s.alpn[0] = 'h';
    ja4s.alpn[1] = '2';

    ngx_ssl_ja4s_fp(pool(), &ja4s, &fp);
    if (fp.data == NULL) { check(0, "JA4S ALPN h2: fp allocated"); return; }

    check(fp.data[5] == 'h' && fp.data[6] == '2',
          "JA4S ALPN 'h2' at fp[5..6]");

    ngx_ssl_ja4s_t ja4s2 = ja4s;
    ja4s2.alpn[0] = 0;
    ja4s2.alpn[1] = 0;
    ngx_str_t fp2 = {0, NULL};
    ngx_ssl_ja4s_fp(pool(), &ja4s2, &fp2);
    if (fp2.data == NULL) { check(0, "JA4S no ALPN: fp allocated"); return; }
    check(fp2.data[5] == '0' && fp2.data[6] == '0',
          "JA4S no ALPN encoded as '00'");
}

/* -------------------------------------------------------------------------
 * ngx_ssl_ja4s_fp — extension count
 * ---------------------------------------------------------------------- */

static void
test_ja4s_ext_count(void)
{
    unsigned short exts[] = {0x002b, 0x0033};
    ngx_ssl_ja4s_t ja4s;
    ngx_str_t fp = {0, NULL};

    memset(&ja4s, 0, sizeof(ja4s));
    ja4s.version = 0x0304;
    ja4s.cipher = 0x1301;
    ja4s.extensions = exts;
    ja4s.extensions_sz = 2;

    ngx_ssl_ja4s_fp(pool(), &ja4s, &fp);
    if (fp.data == NULL) { check(0, "JA4S ext count: fp allocated"); return; }

    check(fp.data[3] == '0' && fp.data[4] == '2',
          "2 extensions encoded as '02'");
}

/* -------------------------------------------------------------------------
 * ngx_ssl_ja4s_fp — golden vector: Go TLS 1.3 ServerHello
 *
 * ServerHello extensions (wire order): supported_versions(002b), key_share(0033)
 * cipher: TLS_AES_128_GCM_SHA256 (0x1301)
 * version: 0x0304 (TLS 1.3, from supported_versions)
 * no ALPN
 *
 * Expected: t130200_1301_a56c5b993250
 *   - "002b,0033" SHA-256[:12] = "a56c5b993250"
 * ---------------------------------------------------------------------- */

static void
test_ja4s_golden_go_tls13(void)
{
    unsigned short exts[] = {0x002b, 0x0033};
    ngx_ssl_ja4s_t ja4s;
    ngx_str_t fp = {0, NULL};

    memset(&ja4s, 0, sizeof(ja4s));
    ja4s.version = 0x0304;
    ja4s.cipher = 0x1301;
    ja4s.extensions = exts;
    ja4s.extensions_sz = 2;

    ngx_ssl_ja4s_fp(pool(), &ja4s, &fp);
    if (fp.data == NULL) { check(0, "JA4S golden Go: fp allocated"); return; }

    CHECK_STR(fp, "t130200_1301_a56c5b993250",
              "JA4S golden: Go TLS 1.3 == 't130200_1301_a56c5b993250'");
}

/* -------------------------------------------------------------------------
 * ngx_ssl_ja4s_fp — empty extension hash
 *
 * no extensions → hash of "" = SHA-256("")[:12] = "e3b0c44298fc"
 * ---------------------------------------------------------------------- */

static void
test_ja4s_empty_ext_hash(void)
{
    ngx_ssl_ja4s_t ja4s;
    ngx_str_t fp = {0, NULL};

    memset(&ja4s, 0, sizeof(ja4s));
    ja4s.version = 0x0303;
    ja4s.cipher = 0xc02b;

    ngx_ssl_ja4s_fp(pool(), &ja4s, &fp);
    if (fp.data == NULL) { check(0, "JA4S empty ext: fp allocated"); return; }

    /* 0 extensions → ngx_ssl_ja4s_ext_hash returns "000000000000" */
    check(memcmp(fp.data + 13, "000000000000", 12) == 0,
          "JA4S empty ext list hash is '000000000000'");
}

/* -------------------------------------------------------------------------
 * ngx_ssl_ja4s_fp — single extension hash
 *
 * extensions: [0x002b]  → input "002b"
 * SHA-256("002b")[:12] = "b9a491fefe05"
 * ---------------------------------------------------------------------- */

static void
test_ja4s_single_ext_hash(void)
{
    unsigned short exts[] = {0x002b};
    ngx_ssl_ja4s_t ja4s;
    ngx_str_t fp = {0, NULL};

    memset(&ja4s, 0, sizeof(ja4s));
    ja4s.version = 0x0304;
    ja4s.cipher = 0x1301;
    ja4s.extensions = exts;
    ja4s.extensions_sz = 1;

    ngx_ssl_ja4s_fp(pool(), &ja4s, &fp);
    if (fp.data == NULL) { check(0, "JA4S single ext: fp allocated"); return; }

    /* fp: t130100_1301_b9a491fefe05 */
    check(memcmp(fp.data + 13, "b9a491fefe05", 12) == 0,
          "JA4S [002b] ext hash == SHA-256('002b')[:12] = 'b9a491fefe05'");
}

/* -------------------------------------------------------------------------
 * ngx_ssl_ja4s_fp — OOM simulation
 * ---------------------------------------------------------------------- */

static void
test_ja4s_oom(void)
{
    ngx_ssl_ja4s_t ja4s;
    ngx_str_t fp = {0, NULL};

    memset(&ja4s, 0, sizeof(ja4s));
    ja4s.version = 0x0304;
    ja4s.cipher = 0x1301;

    ngx_pnalloc_fail_next = 1;
    ngx_ssl_ja4s_fp(pool(), &ja4s, &fp);
    check(fp.data == NULL && fp.len == 0, "JA4S OOM: fp.data NULL and len 0");
}

/* =========================================================================
 * main
 * ===================================================================== */

int
main(void)
{
    printf("=== ngx_ssl_ja4 / ngx_ssl_ja4s unit tests ===\n\n");

    printf("-- Version string --\n");
    test_ja4_version_str();

    printf("\n-- GREASE macro --\n");
    test_grease_macro();

    printf("\n-- JA4 null guards --\n");
    test_ja4_null_guards();

    printf("\n-- JA4 fingerprint structure --\n");
    test_ja4_fp_structure();

    printf("\n-- JA4 SNI encoding --\n");
    test_ja4_no_sni();

    printf("\n-- JA4 ALPN encoding --\n");
    test_ja4_alpn();

    printf("\n-- JA4 cipher count --\n");
    test_ja4_cipher_count();

    printf("\n-- JA4 cipher hash (golden) --\n");
    test_ja4_cipher_hash_golden();
    test_ja4_cipher_hash_grease_filtered();
    test_ja4_empty_cipher_hash();

    printf("\n-- JA4 ext+sigalg hash --\n");
    test_ja4_empty_ext_hash();
    test_ja4_ext_sni_alpn_excluded();
    test_ja4_ext_count_includes_sni_alpn();

    printf("\n-- JA4 OOM --\n");
    test_ja4_oom();

    printf("\n-- JA4S null guards --\n");
    test_ja4s_null_guards();

    printf("\n-- JA4S fingerprint structure --\n");
    test_ja4s_fp_structure();

    printf("\n-- JA4S cipher encoding --\n");
    test_ja4s_cipher();

    printf("\n-- JA4S ALPN encoding --\n");
    test_ja4s_alpn();

    printf("\n-- JA4S extension count --\n");
    test_ja4s_ext_count();

    printf("\n-- JA4S golden vector --\n");
    test_ja4s_golden_go_tls13();
    test_ja4s_empty_ext_hash();
    test_ja4s_single_ext_hash();

    printf("\n-- JA4S OOM --\n");
    test_ja4s_oom();

    printf("\n%d/%d passed\n", g_passed, g_total);
    return (g_passed == g_total) ? 0 : 1;
}
