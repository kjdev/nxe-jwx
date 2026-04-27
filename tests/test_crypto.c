/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 *
 * test_crypto.c - cryptographic fixture helpers for nxe-jwx tests.
 */

#include <ngx_config.h>
#include <ngx_core.h>

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/bio.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/core_names.h>
#endif

#include "test_crypto.h"


/* === base64url encoder === */

static const char b64url_alphabet[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";


ngx_str_t
test_b64url(const u_char *src, size_t len, ngx_pool_t *pool)
{
    ngx_str_t r = { 0, NULL };
    size_t out_cap, i, o;
    u_char *out;

    out_cap = ((len + 2) / 3) * 4;
    if (out_cap == 0) {
        out_cap = 1;
    }
    out = ngx_pnalloc(pool, out_cap);
    if (out == NULL) {
        return r;
    }

    i = o = 0;
    while (i + 3 <= len) {
        u_char a = src[i];
        u_char b = src[i + 1];
        u_char c = src[i + 2];
        out[o++] = (u_char) b64url_alphabet[a >> 2];
        out[o++] = (u_char) b64url_alphabet[((a & 0x3) << 4) | (b >> 4)];
        out[o++] = (u_char) b64url_alphabet[((b & 0xf) << 2) | (c >> 6)];
        out[o++] = (u_char) b64url_alphabet[c & 0x3f];
        i += 3;
    }
    if (i < len) {
        u_char a = src[i];
        out[o++] = (u_char) b64url_alphabet[a >> 2];
        if (i + 1 < len) {
            u_char b = src[i + 1];
            out[o++] = (u_char) b64url_alphabet[((a & 0x3) << 4) | (b >> 4)];
            out[o++] = (u_char) b64url_alphabet[(b & 0xf) << 2];
        } else {
            out[o++] = (u_char) b64url_alphabet[(a & 0x3) << 4];
        }
    }

    r.data = out;
    r.len = o;
    return r;
}


/* === pool-backed printf === */

static ngx_str_t
test_pmprintf(ngx_pool_t *pool, const char *fmt, ...)
{
    ngx_str_t r = { 0, NULL };
    va_list ap, ap2;
    int n;
    char *buf;

    va_start(ap, fmt);
    va_copy(ap2, ap);
    n = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);

    if (n < 0) {
        va_end(ap2);
        return r;
    }

    buf = ngx_pnalloc(pool, (size_t) n + 1);
    if (buf == NULL) {
        va_end(ap2);
        return r;
    }
    vsnprintf(buf, (size_t) n + 1, fmt, ap2);
    va_end(ap2);

    r.data = (u_char *) buf;
    r.len = (size_t) n;
    return r;
}


/* === JWT build helpers === */

ngx_str_t
test_jwt_build(const char *header_json, const char *payload_json,
    const u_char *sig, size_t sig_len, ngx_pool_t *pool)
{
    ngx_str_t header_b64, payload_b64, sig_b64, out;
    u_char *p;

    header_b64 = test_b64url((const u_char *) header_json,
                             strlen(header_json), pool);
    payload_b64 = test_b64url((const u_char *) payload_json,
                              strlen(payload_json), pool);
    sig_b64 = test_b64url(sig, sig_len, pool);

    out.len = header_b64.len + 1 + payload_b64.len + 1 + sig_b64.len;
    out.data = ngx_pnalloc(pool, out.len);
    if (out.data == NULL) {
        ngx_str_t empty = { 0, NULL };
        return empty;
    }

    p = out.data;
    memcpy(p, header_b64.data, header_b64.len); p += header_b64.len;
    *p++ = '.';
    memcpy(p, payload_b64.data, payload_b64.len); p += payload_b64.len;
    *p++ = '.';
    memcpy(p, sig_b64.data, sig_b64.len);
    return out;
}


ngx_str_t
test_signing_input(const char *header_json, const char *payload_json,
    ngx_pool_t *pool)
{
    ngx_str_t header_b64, payload_b64, out;
    u_char *p;

    header_b64 = test_b64url((const u_char *) header_json,
                             strlen(header_json), pool);
    payload_b64 = test_b64url((const u_char *) payload_json,
                              strlen(payload_json), pool);

    out.len = header_b64.len + 1 + payload_b64.len;
    out.data = ngx_pnalloc(pool, out.len);
    if (out.data == NULL) {
        ngx_str_t empty = { 0, NULL };
        return empty;
    }

    p = out.data;
    memcpy(p, header_b64.data, header_b64.len); p += header_b64.len;
    *p++ = '.';
    memcpy(p, payload_b64.data, payload_b64.len);
    return out;
}


/* === keygen === */

EVP_PKEY *
test_gen_rsa(int bits)
{
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx;

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (ctx == NULL) {
        return NULL;
    }
    if (EVP_PKEY_keygen_init(ctx) <= 0
        || EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0
        || EVP_PKEY_keygen(ctx, &pkey) <= 0)
    {
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}


EVP_PKEY *
test_gen_ec(int nid)
{
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx;

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (ctx == NULL) {
        return NULL;
    }
    if (EVP_PKEY_keygen_init(ctx) <= 0
        || EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, nid) <= 0
        || EVP_PKEY_keygen(ctx, &pkey) <= 0)
    {
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}


EVP_PKEY *
test_gen_ed25519(void)
{
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx;

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
    if (ctx == NULL) {
        return NULL;
    }
    if (EVP_PKEY_keygen_init(ctx) <= 0
        || EVP_PKEY_keygen(ctx, &pkey) <= 0)
    {
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}


/* === JWK builders === */

static ngx_str_t
extract_bn_b64url(const BIGNUM *bn, ngx_pool_t *pool)
{
    int n;
    u_char *raw;
    ngx_str_t empty = { 0, NULL };

    n = BN_num_bytes(bn);
    if (n <= 0) {
        return empty;
    }
    raw = ngx_pnalloc(pool, (size_t) n);
    if (raw == NULL) {
        return empty;
    }
    BN_bn2bin(bn, raw);
    return test_b64url(raw, (size_t) n, pool);
}


ngx_str_t
test_jwk_rsa(EVP_PKEY *pkey, const char *kid, const char *alg,
    ngx_pool_t *pool)
{
    ngx_str_t empty = { 0, NULL };
    ngx_str_t n_b64 = { 0, NULL };
    ngx_str_t e_b64 = { 0, NULL };
    BIGNUM *n_bn = NULL, *e_bn = NULL;
    int owned = 0;

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_N, &n_bn) <= 0
        || EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_E, &e_bn) <= 0)
    {
        BN_free(n_bn);
        BN_free(e_bn);
        return empty;
    }
    owned = 1;
#else
    {
        const RSA *rsa = EVP_PKEY_get0_RSA(pkey);
        const BIGNUM *nc = NULL, *ec = NULL;
        if (rsa == NULL) {
            return empty;
        }
        RSA_get0_key(rsa, &nc, &ec, NULL);
        n_bn = (BIGNUM *) nc;
        e_bn = (BIGNUM *) ec;
    }
#endif

    n_b64 = extract_bn_b64url(n_bn, pool);
    e_b64 = extract_bn_b64url(e_bn, pool);
    if (owned) {
        BN_free(n_bn);
        BN_free(e_bn);
    }
    if (n_b64.len == 0 || e_b64.len == 0) {
        return empty;
    }

    return test_pmprintf(pool,
                         "{\"kty\":\"RSA\""
                         "%s%s%s"
                         "%s%s%s"
                         ",\"n\":\"%.*s\",\"e\":\"%.*s\"}",
                         kid ? ",\"kid\":\"" : "", kid ? kid : "",
                         kid ? "\"" : "",
                         alg ? ",\"alg\":\"" : "", alg ? alg : "",
                         alg ? "\"" : "",
                         (int) n_b64.len, n_b64.data,
                         (int) e_b64.len, e_b64.data);
}


static int
ec_pub_xy(EVP_PKEY *pkey, size_t coord_len, u_char *x_out, u_char *y_out)
{
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    BIGNUM *x = NULL, *y = NULL;
    int n;

    if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_EC_PUB_X, &x) <= 0
        || EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_EC_PUB_Y, &y) <= 0)
    {
        BN_free(x);
        BN_free(y);
        return -1;
    }
    memset(x_out, 0, coord_len);
    memset(y_out, 0, coord_len);
    n = BN_num_bytes(x);
    if (n > 0 && (size_t) n <= coord_len) {
        BN_bn2bin(x, x_out + (coord_len - (size_t) n));
    }
    n = BN_num_bytes(y);
    if (n > 0 && (size_t) n <= coord_len) {
        BN_bn2bin(y, y_out + (coord_len - (size_t) n));
    }
    BN_free(x);
    BN_free(y);
    return 0;
#else
    const EC_KEY *ec = EVP_PKEY_get0_EC_KEY(pkey);
    const EC_POINT *pt;
    const EC_GROUP *grp;
    BIGNUM *x = NULL, *y = NULL;
    int rc = -1;
    int n;

    if (ec == NULL) {
        return -1;
    }
    pt = EC_KEY_get0_public_key(ec);
    grp = EC_KEY_get0_group(ec);
    if (pt == NULL || grp == NULL) {
        return -1;
    }
    x = BN_new();
    y = BN_new();
    if (x == NULL || y == NULL) {
        goto out;
    }
    if (EC_POINT_get_affine_coordinates(grp, pt, x, y, NULL) != 1) {
        goto out;
    }
    memset(x_out, 0, coord_len);
    memset(y_out, 0, coord_len);
    n = BN_num_bytes(x);
    if (n > 0 && (size_t) n <= coord_len) {
        BN_bn2bin(x, x_out + (coord_len - (size_t) n));
    }
    n = BN_num_bytes(y);
    if (n > 0 && (size_t) n <= coord_len) {
        BN_bn2bin(y, y_out + (coord_len - (size_t) n));
    }
    rc = 0;
out:
    BN_free(x);
    BN_free(y);
    return rc;
#endif
}


ngx_str_t
test_jwk_ec(EVP_PKEY *pkey, const char *crv, size_t coord_len,
    const char *kid, const char *alg, ngx_pool_t *pool)
{
    ngx_str_t empty = { 0, NULL };
    u_char *x = ngx_pnalloc(pool, coord_len);
    u_char *y = ngx_pnalloc(pool, coord_len);
    ngx_str_t x_b64, y_b64;

    if (x == NULL || y == NULL || ec_pub_xy(pkey, coord_len, x, y) != 0) {
        return empty;
    }
    x_b64 = test_b64url(x, coord_len, pool);
    y_b64 = test_b64url(y, coord_len, pool);
    if (x_b64.len == 0 || y_b64.len == 0) {
        return empty;
    }

    return test_pmprintf(pool,
                         "{\"kty\":\"EC\",\"crv\":\"%s\""
                         "%s%s%s"
                         "%s%s%s"
                         ",\"x\":\"%.*s\",\"y\":\"%.*s\"}",
                         crv,
                         kid ? ",\"kid\":\"" : "", kid ? kid : "",
                         kid ? "\"" : "",
                         alg ? ",\"alg\":\"" : "", alg ? alg : "",
                         alg ? "\"" : "",
                         (int) x_b64.len, x_b64.data,
                         (int) y_b64.len, y_b64.data);
}


ngx_str_t
test_jwk_okp(EVP_PKEY *pkey, const char *crv, size_t key_len,
    const char *kid, const char *alg, ngx_pool_t *pool)
{
    ngx_str_t empty = { 0, NULL };
    u_char *raw = ngx_pnalloc(pool, key_len);
    size_t got = key_len;
    ngx_str_t x_b64;

    if (raw == NULL) {
        return empty;
    }
    if (EVP_PKEY_get_raw_public_key(pkey, raw, &got) != 1
        || got != key_len)
    {
        return empty;
    }
    x_b64 = test_b64url(raw, key_len, pool);
    if (x_b64.len == 0) {
        return empty;
    }

    return test_pmprintf(pool,
                         "{\"kty\":\"OKP\",\"crv\":\"%s\""
                         "%s%s%s"
                         "%s%s%s"
                         ",\"x\":\"%.*s\"}",
                         crv,
                         kid ? ",\"kid\":\"" : "", kid ? kid : "",
                         kid ? "\"" : "",
                         alg ? ",\"alg\":\"" : "", alg ? alg : "",
                         alg ? "\"" : "",
                         (int) x_b64.len, x_b64.data);
}


ngx_str_t
test_jwk_oct(const u_char *secret, size_t len, const char *kid,
    const char *alg, ngx_pool_t *pool)
{
    ngx_str_t k_b64 = test_b64url(secret, len, pool);
    ngx_str_t empty = { 0, NULL };

    if (k_b64.len == 0 && len > 0) {
        return empty;
    }

    return test_pmprintf(pool,
                         "{\"kty\":\"oct\""
                         "%s%s%s"
                         "%s%s%s"
                         ",\"k\":\"%.*s\"}",
                         kid ? ",\"kid\":\"" : "", kid ? kid : "",
                         kid ? "\"" : "",
                         alg ? ",\"alg\":\"" : "", alg ? alg : "",
                         alg ? "\"" : "",
                         (int) k_b64.len, k_b64.data);
}


ngx_str_t
test_jwks_build(const ngx_str_t *jwks, size_t njwks, ngx_pool_t *pool)
{
    ngx_str_t out;
    size_t total, i;
    u_char *p;
    static const char prefix[] = "{\"keys\":[";
    static const char suffix[] = "]}";

    total = sizeof(prefix) - 1 + sizeof(suffix) - 1;
    for (i = 0; i < njwks; i++) {
        total += jwks[i].len;
        if (i + 1 < njwks) {
            total += 1;     /* ',' */
        }
    }

    out.data = ngx_pnalloc(pool, total);
    if (out.data == NULL) {
        ngx_str_t empty = { 0, NULL };
        return empty;
    }
    out.len = total;

    p = out.data;
    memcpy(p, prefix, sizeof(prefix) - 1); p += sizeof(prefix) - 1;
    for (i = 0; i < njwks; i++) {
        memcpy(p, jwks[i].data, jwks[i].len); p += jwks[i].len;
        if (i + 1 < njwks) {
            *p++ = ',';
        }
    }
    memcpy(p, suffix, sizeof(suffix) - 1);
    return out;
}


/* === signing === */

static int
ecdsa_der_to_raw(const u_char *der, size_t der_len, size_t coord_len,
    u_char *out)
{
    const u_char *p = der;
    ECDSA_SIG *sig;
    const BIGNUM *r, *s;
    int rl, sl;

    sig = d2i_ECDSA_SIG(NULL, &p, (long) der_len);
    if (sig == NULL) {
        return -1;
    }
    ECDSA_SIG_get0(sig, &r, &s);
    rl = BN_num_bytes(r);
    sl = BN_num_bytes(s);
    if (rl < 0 || (size_t) rl > coord_len
        || sl < 0 || (size_t) sl > coord_len)
    {
        ECDSA_SIG_free(sig);
        return -1;
    }
    memset(out, 0, coord_len * 2);
    BN_bn2bin(r, out + (coord_len - (size_t) rl));
    BN_bn2bin(s, out + coord_len + (coord_len - (size_t) sl));
    ECDSA_SIG_free(sig);
    return 0;
}


ngx_int_t
test_sign(EVP_PKEY *pkey, const char *digest, int pss, size_t ec_coord_len,
    const u_char *msg, size_t msg_len,
    u_char **out, size_t *out_len, ngx_pool_t *pool)
{
    EVP_MD_CTX *ctx;
    EVP_PKEY_CTX *pctx = NULL;
    const EVP_MD *md = NULL;
    u_char *sig = NULL;
    size_t sig_len = 0;
    ngx_int_t rc = NGX_ERROR;

    *out = NULL;
    *out_len = 0;

    if (digest != NULL) {
        md = EVP_get_digestbyname(digest);
        if (md == NULL) {
            return NGX_ERROR;
        }
    }

    ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    if (EVP_DigestSignInit(ctx, &pctx, md, NULL, pkey) != 1) {
        goto out;
    }

    if (pss) {
        if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) <= 0
            || EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, RSA_PSS_SALTLEN_DIGEST)
            <= 0
            || EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, md) <= 0)
        {
            goto out;
        }
    }

    if (EVP_DigestSign(ctx, NULL, &sig_len, msg, msg_len) != 1) {
        goto out;
    }
    sig = ngx_pnalloc(pool, sig_len);
    if (sig == NULL) {
        goto out;
    }
    if (EVP_DigestSign(ctx, sig, &sig_len, msg, msg_len) != 1) {
        goto out;
    }

    if (ec_coord_len > 0) {
        u_char *raw = ngx_pnalloc(pool, ec_coord_len * 2);
        if (raw == NULL) {
            goto out;
        }
        if (ecdsa_der_to_raw(sig, sig_len, ec_coord_len, raw) != 0) {
            goto out;
        }
        *out = raw;
        *out_len = ec_coord_len * 2;
    } else {
        *out = sig;
        *out_len = sig_len;
    }

    rc = NGX_OK;

out:
    EVP_MD_CTX_free(ctx);
    return rc;
}


ngx_int_t
test_hmac_sign(const u_char *key, size_t key_len, const char *digest,
    const u_char *msg, size_t msg_len,
    u_char **out, size_t *out_len, ngx_pool_t *pool)
{
    const EVP_MD *md;
    u_char tmp[EVP_MAX_MD_SIZE];
    unsigned int n = 0;
    u_char *buf;

    *out = NULL;
    *out_len = 0;

    md = EVP_get_digestbyname(digest);
    if (md == NULL) {
        return NGX_ERROR;
    }

    if (HMAC(md, key, (int) key_len, msg, msg_len, tmp, &n) == NULL) {
        return NGX_ERROR;
    }

    buf = ngx_pnalloc(pool, n);
    if (buf == NULL) {
        return NGX_ERROR;
    }
    memcpy(buf, tmp, n);
    *out = buf;
    *out_len = n;
    return NGX_OK;
}


ngx_str_t
test_pem_pubkey(EVP_PKEY *pkey, ngx_pool_t *pool)
{
    ngx_str_t empty = { 0, NULL };
    ngx_str_t out = { 0, NULL };
    BIO *bio;
    BUF_MEM *mem;
    u_char *buf;

    bio = BIO_new(BIO_s_mem());
    if (bio == NULL) {
        return empty;
    }
    if (PEM_write_bio_PUBKEY(bio, pkey) != 1) {
        BIO_free(bio);
        return empty;
    }
    BIO_get_mem_ptr(bio, &mem);
    buf = ngx_pnalloc(pool, mem->length);
    if (buf == NULL) {
        BIO_free(bio);
        return empty;
    }
    memcpy(buf, mem->data, mem->length);
    out.data = buf;
    out.len = mem->length;
    BIO_free(bio);
    return out;
}
