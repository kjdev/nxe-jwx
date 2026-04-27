/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 *
 * nxe_jwx_jwks.c - JWKS document parsing and EVP_PKEY construction
 *
 * Supports OpenSSL 1.1.x and 3.0+.  The version split lives entirely
 * inside the build_*_key helpers; the rest of the file is identical
 * for both branches.
 *
 *   - JWKS:    {"keys": [{...}, ...]}        nxe_jwx_jwks_parse
 *   - keyval:  {"kid": "PEM-or-raw", ...}    nxe_jwx_jwks_parse_keyval
 *
 * Each successfully decoded key produces an EVP_PKEY (or, with
 * NXE_JWX_HAVE_HMAC, a raw HMAC buffer) which is freed by a pool
 * cleanup handler.
 */

#include <ngx_config.h>
#include <ngx_core.h>

#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#endif

#include <nxe_json.h>

#include "nxe_jwx.h"
#include "nxe_jwx_internal.h"


/* === Internal types === */

/* `struct nxe_jwx_key_s` and `nxe_jwx_kty_t` are defined in
 * nxe_jwx_internal.h so that nxe_jwx_jws.c can introspect keys
 * without exposing them through the public API. */

struct nxe_jwx_jwks_s {
    struct nxe_jwx_key_s *keys;     /* allocated on pool */
    ngx_uint_t            nkeys;
};


/* === Curve table (EC keys) === */

typedef struct {
    const char *jwk_crv;            /* JWK "crv" */
    const char *ossl_name;          /* OpenSSL group name */
    size_t      coord_len;          /* expected length of x and y */
    int         nid;                /* OpenSSL NID (1.1.x path) */
} nxe_jwx_ec_curve_t;

static const nxe_jwx_ec_curve_t nxe_jwx_ec_curves[] = {
    { "P-256",     "prime256v1", 32, NID_X9_62_prime256v1 },
    { "P-384",     "secp384r1",  48, NID_secp384r1        },
    { "P-521",     "secp521r1",  66, NID_secp521r1        },
    { "secp256k1", "secp256k1",  32, NID_secp256k1        },
    { NULL, NULL, 0, 0 }
};


static const nxe_jwx_ec_curve_t *
nxe_jwx_lookup_ec_curve(const ngx_str_t *crv)
{
    const nxe_jwx_ec_curve_t *c;

    for (c = nxe_jwx_ec_curves; c->jwk_crv != NULL; c++) {
        size_t n = ngx_strlen(c->jwk_crv);
        if (crv->len == n
            && ngx_strncmp(crv->data, c->jwk_crv, n) == 0)
        {
            return c;
        }
    }
    return NULL;
}


/* === OKP curve table (Ed25519 / Ed448) === */

typedef struct {
    const char *jwk_crv;
    int         nid;
    size_t      key_len;            /* public-key octet length */
} nxe_jwx_okp_curve_t;

static const nxe_jwx_okp_curve_t nxe_jwx_okp_curves[] = {
    { "Ed25519", NID_ED25519, 32 },
    { "Ed448",   NID_ED448,   57 },
    { NULL, 0, 0 }
};


static const nxe_jwx_okp_curve_t *
nxe_jwx_lookup_okp_curve(const ngx_str_t *crv)
{
    const nxe_jwx_okp_curve_t *c;

    for (c = nxe_jwx_okp_curves; c->jwk_crv != NULL; c++) {
        size_t n = ngx_strlen(c->jwk_crv);
        if (crv->len == n
            && ngx_strncmp(crv->data, c->jwk_crv, n) == 0)
        {
            return c;
        }
    }
    return NULL;
}


/* === Common helpers === */

static ngx_int_t
nxe_jwx_b64url_field(nxe_json_t *parent, const char *name,
    ngx_str_t *out, ngx_pool_t *pool)
{
    nxe_json_t *node;
    ngx_str_t src;
    ngx_str_t src_mut;
    size_t decoded_max;

    out->data = NULL;
    out->len = 0;

    node = nxe_json_object_get(parent, name);
    if (node == NULL || nxe_json_type(node) != NXE_JSON_STRING) {
        return NGX_DECLINED;
    }

    if (nxe_json_string(node, &src) != NGX_OK || src.len == 0) {
        return NGX_DECLINED;
    }

    decoded_max = ngx_base64_decoded_length(src.len);
    out->data = ngx_pnalloc(pool, decoded_max);
    if (out->data == NULL) {
        return NGX_ERROR;
    }
    src_mut.data = src.data;
    src_mut.len = src.len;

    if (ngx_decode_base64url(out, &src_mut) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
nxe_jwx_string_field(nxe_json_t *parent, const char *name, ngx_str_t *out)
{
    nxe_json_t *node;

    out->data = NULL;
    out->len = 0;

    node = nxe_json_object_get(parent, name);
    if (node == NULL || nxe_json_type(node) != NXE_JSON_STRING) {
        return NGX_DECLINED;
    }
    return nxe_json_string(node, out);
}


/*
 * nxe_json_string returns a zero-copy view into the parsed JSON.
 * After we free the JWKS root document the underlying buffer goes
 * away; copy the bytes into the pool so the keyset can outlive the
 * JSON node.
 */
static ngx_int_t
nxe_jwx_dup_str_to_pool(ngx_str_t *str, ngx_pool_t *pool)
{
    u_char *p;

    if (str->len == 0 || str->data == NULL) {
        str->data = NULL;
        str->len = 0;
        return NGX_OK;
    }
    p = ngx_pnalloc(pool, str->len);
    if (p == NULL) {
        return NGX_ERROR;
    }
    ngx_memcpy(p, str->data, str->len);
    str->data = p;
    return NGX_OK;
}


/* === Cleanup === */

static void
nxe_jwx_jwks_cleanup(void *data)
{
    nxe_jwx_jwks_t *jwks = data;
    ngx_uint_t i;

    if (jwks == NULL) {
        return;
    }

    for (i = 0; i < jwks->nkeys; i++) {
        struct nxe_jwx_key_s *k = &jwks->keys[i];

        if (k->pkey != NULL) {
            EVP_PKEY_free(k->pkey);
            k->pkey = NULL;
        }
#if (NXE_JWX_HAVE_HMAC)
        if (k->hmac_secret.data != NULL && k->hmac_secret.len > 0) {
            OPENSSL_cleanse(k->hmac_secret.data, k->hmac_secret.len);
            k->hmac_secret.len = 0;
        }
#endif
    }
}


/* === Per-kty key construction === */

/*
 * Build an EVP_PKEY from RSA public components (n, e).
 *
 * Ownership contract: this helper does NOT take ownership of the
 * caller's BIGNUMs.  The 3.0+ path copies them into the OSSL_PARAM
 * structure; the 1.1.x path duplicates them via BN_dup before handing
 * the copies off to RSA_set0_key.  In both branches the caller is
 * responsible for freeing the original n_bn / e_bn after this returns.
 *
 * Returns NULL on failure.  Caller owns the returned EVP_PKEY.
 */
static EVP_PKEY *
nxe_jwx_build_rsa_key(const BIGNUM *n_bn, const BIGNUM *e_bn, ngx_log_t *log)
{
    EVP_PKEY *pkey = NULL;

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    EVP_PKEY_CTX *ctx = NULL;
    OSSL_PARAM_BLD *bld = NULL;
    OSSL_PARAM *params = NULL;

    bld = OSSL_PARAM_BLD_new();
    if (bld == NULL) {
        goto out;
    }
    if (!OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, n_bn)
        || !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, e_bn))
    {
        goto out;
    }
    params = OSSL_PARAM_BLD_to_param(bld);
    if (params == NULL) {
        goto out;
    }

    ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
    if (ctx == NULL) {
        goto out;
    }
    if (EVP_PKEY_fromdata_init(ctx) <= 0
        || EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) <= 0)
    {
        pkey = NULL;
        goto out;
    }

out:
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    EVP_PKEY_CTX_free(ctx);
    if (pkey == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "nxe_jwx: EVP_PKEY_fromdata(RSA) failed");
    }
    return pkey;
#else
    RSA *rsa = NULL;
    BIGNUM *n_dup = NULL;
    BIGNUM *e_dup = NULL;

    /*
     * Duplicate the inputs so the caller does not need to know which
     * branch of OpenSSL we hit -- ownership stays with the caller for
     * both 1.1.x and 3.0+.
     */
    n_dup = BN_dup(n_bn);
    e_dup = BN_dup(e_bn);
    if (n_dup == NULL || e_dup == NULL) {
        goto err;
    }

    rsa = RSA_new();
    if (rsa == NULL) {
        goto err;
    }
    /* RSA_set0_key takes ownership of the duplicated BNs on success. */
    if (RSA_set0_key(rsa, n_dup, e_dup, NULL) != 1) {
        goto err;
    }
    n_dup = NULL;
    e_dup = NULL;

    pkey = EVP_PKEY_new();
    if (pkey == NULL) {
        goto err;
    }
    if (EVP_PKEY_assign_RSA(pkey, rsa) != 1) {
        /*
         * EVP_PKEY_assign_RSA() does NOT take ownership of `rsa` on
         * failure, so we must free both pkey and rsa here.  The
         * subsequent goto-err path would only free pkey, leaving rsa
         * leaked.
         */
        EVP_PKEY_free(pkey);
        pkey = NULL;
        goto err;
    }
    /* On success the EVP_PKEY owns rsa; clear our local pointer. */
    rsa = NULL;
    return pkey;

err:
    if (pkey != NULL) {
        EVP_PKEY_free(pkey);
    }
    if (rsa != NULL) {
        RSA_free(rsa);
    }
    BN_free(n_dup);
    BN_free(e_dup);
    ngx_log_error(NGX_LOG_ERR, log, 0,
                  "nxe_jwx: failed to assemble RSA EVP_PKEY");
    return NULL;
#endif
}


/*
 * Build an EVP_PKEY from EC public-key components (crv, x, y).
 *
 * `point` is the SEC1 uncompressed point: 0x04 || X || Y.
 */
static EVP_PKEY *
nxe_jwx_build_ec_key(const nxe_jwx_ec_curve_t *curve,
    const u_char *point, size_t point_len, ngx_log_t *log)
{
    EVP_PKEY *pkey = NULL;

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    EVP_PKEY_CTX *ctx = NULL;
    OSSL_PARAM_BLD *bld = NULL;
    OSSL_PARAM *params = NULL;

    bld = OSSL_PARAM_BLD_new();
    if (bld == NULL) {
        goto out;
    }
    if (!OSSL_PARAM_BLD_push_utf8_string(bld,
                                         OSSL_PKEY_PARAM_GROUP_NAME,
                                         curve->ossl_name, 0))
    {
        goto out;
    }
    if (!OSSL_PARAM_BLD_push_octet_string(bld,
                                          OSSL_PKEY_PARAM_PUB_KEY, point,
                                          point_len))
    {
        goto out;
    }
    params = OSSL_PARAM_BLD_to_param(bld);
    if (params == NULL) {
        goto out;
    }

    ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    if (ctx == NULL) {
        goto out;
    }
    if (EVP_PKEY_fromdata_init(ctx) <= 0
        || EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) <= 0)
    {
        pkey = NULL;
        goto out;
    }

out:
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    EVP_PKEY_CTX_free(ctx);
    if (pkey == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "nxe_jwx: EVP_PKEY_fromdata(EC,%s) failed",
                      curve->ossl_name);
    }
    return pkey;
#else
    EC_KEY *ec = NULL;

    ec = EC_KEY_new_by_curve_name(curve->nid);
    if (ec == NULL) {
        goto err;
    }
    if (EC_KEY_oct2key(ec, point, point_len, NULL) != 1) {
        goto err;
    }

    pkey = EVP_PKEY_new();
    if (pkey == NULL) {
        goto err;
    }
    if (EVP_PKEY_assign_EC_KEY(pkey, ec) != 1) {
        /*
         * EVP_PKEY_assign_EC_KEY() does NOT take ownership of `ec` on
         * failure; free both pkey and ec here so the err path's single
         * cleanup branch does not leak the EC_KEY.
         */
        EVP_PKEY_free(pkey);
        pkey = NULL;
        goto err;
    }
    /* On success the EVP_PKEY owns ec; clear our local pointer. */
    ec = NULL;
    return pkey;

err:
    if (pkey != NULL) {
        EVP_PKEY_free(pkey);
    }
    if (ec != NULL) {
        EC_KEY_free(ec);
    }
    ngx_log_error(NGX_LOG_ERR, log, 0,
                  "nxe_jwx: failed to assemble EC EVP_PKEY (%s)",
                  curve->ossl_name);
    return NULL;
#endif
}


/*
 * Build an EVP_PKEY for an OKP (Ed25519 / Ed448) public key from raw
 * x bytes.  EVP_PKEY_new_raw_public_key() is supported on both 1.1.x
 * (>= 1.1.1) and 3.0+, so no version split is needed.
 */
static EVP_PKEY *
nxe_jwx_build_okp_key(const nxe_jwx_okp_curve_t *curve,
    const u_char *x, size_t x_len, ngx_log_t *log)
{
    EVP_PKEY *pkey;

    pkey = EVP_PKEY_new_raw_public_key(curve->nid, NULL, x, x_len);
    if (pkey == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "nxe_jwx: EVP_PKEY_new_raw_public_key(%s) failed",
                      curve->jwk_crv);
    }
    return pkey;
}


/* === Per-kty parse: returns NGX_OK on success, NGX_DECLINED on
 * "unsupported / invalid skip-this-key", NGX_ERROR on hard error. === */

static ngx_int_t
nxe_jwx_parse_rsa(struct nxe_jwx_key_s *k, nxe_json_t *jwk,
    ngx_pool_t *pool, ngx_log_t *log)
{
    ngx_str_t n_bytes, e_bytes;
    BIGNUM *n_bn = NULL, *e_bn = NULL;
    ngx_int_t rc;

    /*
     * nxe_jwx_b64url_field distinguishes "field absent / empty" (NGX_DECLINED)
     * from internal failures such as allocation or malformed base64
     * (NGX_ERROR).  Surface the latter as a hard error so the caller can
     * reject the entire JWKS instead of silently skipping the key.
     */
    rc = nxe_jwx_b64url_field(jwk, "n", &n_bytes, pool);
    if (rc == NGX_ERROR) {
        return NGX_ERROR;
    }
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "nxe_jwx: RSA jwk missing 'n'");
        return NGX_DECLINED;
    }
    rc = nxe_jwx_b64url_field(jwk, "e", &e_bytes, pool);
    if (rc == NGX_ERROR) {
        return NGX_ERROR;
    }
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "nxe_jwx: RSA jwk missing 'e'");
        return NGX_DECLINED;
    }

    if (n_bytes.len < (NXE_JWX_MIN_RSA_BITS / 8)) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "nxe_jwx: RSA modulus shorter than %ui bits",
                      (ngx_uint_t) NXE_JWX_MIN_RSA_BITS);
        return NGX_DECLINED;
    }

    n_bn = BN_bin2bn(n_bytes.data, (int) n_bytes.len, NULL);
    e_bn = BN_bin2bn(e_bytes.data, (int) e_bytes.len, NULL);
    if (n_bn == NULL || e_bn == NULL) {
        BN_free(n_bn);
        BN_free(e_bn);
        return NGX_ERROR;
    }

    /*
     * Build the EVP_PKEY without transferring ownership of n_bn / e_bn:
     * both 1.1.x and 3.0+ branches now copy the BNs internally so the
     * caller frees them unconditionally.
     */
    k->pkey = nxe_jwx_build_rsa_key(n_bn, e_bn, log);
    BN_free(n_bn);
    BN_free(e_bn);

    if (k->pkey == NULL) {
        return NGX_ERROR;
    }

    k->kty = NXE_JWX_KTY_RSA;
    return NGX_OK;
}


static ngx_int_t
nxe_jwx_parse_ec(struct nxe_jwx_key_s *k, nxe_json_t *jwk,
    ngx_pool_t *pool, ngx_log_t *log)
{
    const nxe_jwx_ec_curve_t *curve;
    ngx_str_t x_bytes, y_bytes;
    u_char *point;
    size_t point_len;
    ngx_int_t rc;

    if (k->crv.len == 0) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "nxe_jwx: EC jwk missing 'crv'");
        return NGX_DECLINED;
    }
    curve = nxe_jwx_lookup_ec_curve(&k->crv);
    if (curve == NULL) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "nxe_jwx: unsupported EC crv \"%V\"", &k->crv);
        return NGX_DECLINED;
    }

    rc = nxe_jwx_b64url_field(jwk, "x", &x_bytes, pool);
    if (rc == NGX_ERROR) {
        return NGX_ERROR;
    }
    if (rc != NGX_OK || x_bytes.len != curve->coord_len) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "nxe_jwx: EC jwk x has unexpected length");
        return NGX_DECLINED;
    }
    rc = nxe_jwx_b64url_field(jwk, "y", &y_bytes, pool);
    if (rc == NGX_ERROR) {
        return NGX_ERROR;
    }
    if (rc != NGX_OK || y_bytes.len != curve->coord_len) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "nxe_jwx: EC jwk y has unexpected length");
        return NGX_DECLINED;
    }

    point_len = 1 + curve->coord_len * 2;
    point = ngx_pnalloc(pool, point_len);
    if (point == NULL) {
        return NGX_ERROR;
    }
    point[0] = 0x04;            /* uncompressed */
    ngx_memcpy(point + 1, x_bytes.data, curve->coord_len);
    ngx_memcpy(point + 1 + curve->coord_len, y_bytes.data, curve->coord_len);

    k->pkey = nxe_jwx_build_ec_key(curve, point, point_len, log);
    if (k->pkey == NULL) {
        return NGX_ERROR;
    }

    k->kty = NXE_JWX_KTY_EC;
    return NGX_OK;
}


static ngx_int_t
nxe_jwx_parse_okp(struct nxe_jwx_key_s *k, nxe_json_t *jwk,
    ngx_pool_t *pool, ngx_log_t *log)
{
    const nxe_jwx_okp_curve_t *curve;
    ngx_str_t x_bytes;
    ngx_int_t rc;

    if (k->crv.len == 0) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "nxe_jwx: OKP jwk missing 'crv'");
        return NGX_DECLINED;
    }
    curve = nxe_jwx_lookup_okp_curve(&k->crv);
    if (curve == NULL) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "nxe_jwx: unsupported OKP crv \"%V\"", &k->crv);
        return NGX_DECLINED;
    }

    rc = nxe_jwx_b64url_field(jwk, "x", &x_bytes, pool);
    if (rc == NGX_ERROR) {
        return NGX_ERROR;
    }
    if (rc != NGX_OK || x_bytes.len != curve->key_len) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "nxe_jwx: OKP jwk x has unexpected length");
        return NGX_DECLINED;
    }

    k->pkey = nxe_jwx_build_okp_key(curve, x_bytes.data, x_bytes.len, log);
    if (k->pkey == NULL) {
        return NGX_ERROR;
    }

    k->kty = NXE_JWX_KTY_OKP;
    return NGX_OK;
}


#if (NXE_JWX_HAVE_HMAC)
static ngx_int_t
nxe_jwx_parse_oct(struct nxe_jwx_key_s *k, nxe_json_t *jwk,
    ngx_pool_t *pool, ngx_log_t *log)
{
    ngx_int_t rc;

    rc = nxe_jwx_b64url_field(jwk, "k", &k->hmac_secret, pool);
    if (rc == NGX_ERROR) {
        return NGX_ERROR;
    }
    if (rc != NGX_OK || k->hmac_secret.len == 0) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "nxe_jwx: oct jwk missing 'k'");
        return NGX_DECLINED;
    }

    k->kty = NXE_JWX_KTY_OCT;
    return NGX_OK;
}
#endif


/*
 * Parse a single JWK object into k.  On success k holds a usable
 * pkey/secret.  Returns NGX_DECLINED if the key should be skipped
 * (unknown kty, unsupported crv, missing fields).  NGX_ERROR is for
 * hard internal errors (allocation, OpenSSL).
 */
static ngx_int_t
nxe_jwx_parse_one_key(struct nxe_jwx_key_s *k, nxe_json_t *jwk,
    ngx_pool_t *pool, ngx_log_t *log)
{
    ngx_str_t kty;

    ngx_memzero(k, sizeof(*k));

    if (nxe_jwx_string_field(jwk, "kty", &kty) != NGX_OK) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "nxe_jwx: jwk missing 'kty'");
        return NGX_DECLINED;
    }

    /* Optional metadata. */
    (void) nxe_jwx_string_field(jwk, "kid", &k->kid);
    (void) nxe_jwx_string_field(jwk, "alg", &k->alg);
    (void) nxe_jwx_string_field(jwk, "crv", &k->crv);

    /*
     * The above accessors return zero-copy views into the JSON
     * document; copy them into the pool so the keyset survives the
     * eventual nxe_json_free(root).
     */
    if (nxe_jwx_dup_str_to_pool(&k->kid, pool) != NGX_OK
        || nxe_jwx_dup_str_to_pool(&k->alg, pool) != NGX_OK
        || nxe_jwx_dup_str_to_pool(&k->crv, pool) != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (kty.len == 3 && ngx_strncmp(kty.data, "RSA", 3) == 0) {
        return nxe_jwx_parse_rsa(k, jwk, pool, log);
    }
    if (kty.len == 2 && ngx_strncmp(kty.data, "EC", 2) == 0) {
        return nxe_jwx_parse_ec(k, jwk, pool, log);
    }
    if (kty.len == 3 && ngx_strncmp(kty.data, "OKP", 3) == 0) {
        return nxe_jwx_parse_okp(k, jwk, pool, log);
    }
#if (NXE_JWX_HAVE_HMAC)
    if (kty.len == 3 && ngx_strncmp(kty.data, "oct", 3) == 0) {
        return nxe_jwx_parse_oct(k, jwk, pool, log);
    }
#endif

    ngx_log_error(NGX_LOG_WARN, log, 0,
                  "nxe_jwx: unsupported kty \"%V\"", &kty);
    return NGX_DECLINED;
}


/* === Top-level parse functions === */

static nxe_jwx_jwks_t *
nxe_jwx_jwks_alloc(ngx_pool_t *pool, ngx_uint_t capacity)
{
    nxe_jwx_jwks_t *jwks;
    ngx_pool_cleanup_t *cln;

    jwks = ngx_pcalloc(pool, sizeof(*jwks));
    if (jwks == NULL) {
        return NULL;
    }
    jwks->keys = ngx_pcalloc(pool, sizeof(*jwks->keys) * capacity);
    if (jwks->keys == NULL) {
        return NULL;
    }
    jwks->nkeys = 0;

    cln = ngx_pool_cleanup_add(pool, 0);
    if (cln == NULL) {
        return NULL;
    }
    cln->handler = nxe_jwx_jwks_cleanup;
    cln->data = jwks;

    return jwks;
}


nxe_jwx_jwks_t *
nxe_jwx_jwks_parse(const ngx_str_t *jwks_json, ngx_pool_t *pool)
{
    nxe_jwx_jwks_t *jwks;
    nxe_json_t *root, *keys_node, *jwk;
    ngx_str_t input;
    ngx_log_t *log;
    size_t nkeys;
    ngx_uint_t i;

    if (pool == NULL || jwks_json == NULL || jwks_json->data == NULL) {
        return NULL;
    }
    log = nxe_jwx_log(pool);

    if (jwks_json->len == 0 || jwks_json->len > NXE_JWX_MAX_JWKS_SIZE) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "nxe_jwx: JWKS document size out of range");
        return NULL;
    }

    input.data = jwks_json->data;
    input.len = jwks_json->len;
    root = nxe_json_parse_untrusted(&input, pool);
    if (root == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "nxe_jwx: failed to parse JWKS as JSON");
        return NULL;
    }
    if (nxe_json_type(root) != NXE_JSON_OBJECT) {
        ngx_log_error(NGX_LOG_ERR, log, 0, "nxe_jwx: JWKS root is not object");
        nxe_json_free(root);
        return NULL;
    }

    keys_node = nxe_json_object_get(root, "keys");
    if (keys_node == NULL || nxe_json_type(keys_node) != NXE_JSON_ARRAY) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "nxe_jwx: JWKS missing 'keys' array");
        nxe_json_free(root);
        return NULL;
    }

    nkeys = nxe_json_array_size(keys_node);
    if (nkeys > NXE_JWX_MAX_JWKS_KEYS) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "nxe_jwx: JWKS contains more than %ui keys",
                      (ngx_uint_t) NXE_JWX_MAX_JWKS_KEYS);
        nxe_json_free(root);
        return NULL;
    }

    jwks = nxe_jwx_jwks_alloc(pool, nkeys ? (ngx_uint_t) nkeys : 1);
    if (jwks == NULL) {
        nxe_json_free(root);
        return NULL;
    }

    for (i = 0; i < nkeys; i++) {
        ngx_int_t rc;

        jwk = nxe_json_array_get(keys_node, i);
        if (jwk == NULL || nxe_json_type(jwk) != NXE_JSON_OBJECT) {
            ngx_log_error(NGX_LOG_WARN, log, 0,
                          "nxe_jwx: JWKS keys[%ui] is not an object", i);
            continue;
        }

        rc = nxe_jwx_parse_one_key(&jwks->keys[jwks->nkeys], jwk, pool, log);
        if (rc == NGX_OK) {
            jwks->nkeys++;
        } else if (rc == NGX_ERROR) {
            nxe_json_free(root);
            return NULL;
        }
        /* NGX_DECLINED: skip this key, keep going. */
    }

    nxe_json_free(root);

    if (jwks->nkeys == 0) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "nxe_jwx: JWKS produced zero usable keys");
        return NULL;
    }

    return jwks;
}


/*
 * Helper for nxe_jwx_jwks_parse_keyval: try to interpret a value as a
 * PEM public key.  Returns an EVP_PKEY on success, NULL otherwise (no
 * logging at info level; PEM-vs-raw is a normal try-and-fall-through).
 */
static EVP_PKEY *
nxe_jwx_load_pem_pubkey(const ngx_str_t *pem)
{
    BIO *bio;
    EVP_PKEY *pkey;

    bio = BIO_new_mem_buf(pem->data, (int) pem->len);
    if (bio == NULL) {
        return NULL;
    }
    pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    BIO_free(bio);
    return pkey;
}


/*
 * Map an EVP_PKEY's base id back into the nxe_jwx_kty_t enum so the
 * verifier's compatibility check accepts EC / OKP PEMs as well as RSA.
 * Returns NXE_JWX_KTY_UNKNOWN if the key type is not supported.
 */
static nxe_jwx_kty_t
nxe_jwx_kty_from_pkey(EVP_PKEY *pkey)
{
    switch (EVP_PKEY_base_id(pkey)) {
    case EVP_PKEY_RSA:
    case EVP_PKEY_RSA_PSS:
        return NXE_JWX_KTY_RSA;
    case EVP_PKEY_EC:
        return NXE_JWX_KTY_EC;
    case EVP_PKEY_ED25519:
    case EVP_PKEY_ED448:
        return NXE_JWX_KTY_OKP;
    default:
        return NXE_JWX_KTY_UNKNOWN;
    }
}


nxe_jwx_jwks_t *
nxe_jwx_jwks_parse_keyval(const ngx_str_t *keyval_json, ngx_pool_t *pool)
{
    nxe_jwx_jwks_t *jwks;
    nxe_json_t *root;
    ngx_str_t input;
    ngx_log_t *log;

    /* nxe-json does not (currently) expose object iteration, so we
     * implement keyval parsing here by delegating to nxe-json's
     * object_get for each kid the caller declared.  But operators
     * supply { "kid1": ..., "kid2": ... } as a JSON literal where
     * the kids are NOT known ahead of time, so we keep the design
     * symmetric with parse() above and require an explicit "keys"
     * array nested form in the future.
     *
     * For now we provide a minimal v1 that accepts a single-key
     * keyval payload {"kid": "<PEM>"} which is the dominant use
     * case in nginx-auth-jwt's auth_jwt_keyval directive.  Multi-key
     * support and (with NXE_JWX_HAVE_HMAC) raw secrets can be added
     * once nxe-json grows an object iterator without breaking the
     * public API.
     */

    if (pool == NULL || keyval_json == NULL || keyval_json->data == NULL) {
        return NULL;
    }
    log = nxe_jwx_log(pool);

    if (keyval_json->len == 0 || keyval_json->len > NXE_JWX_MAX_JWKS_SIZE) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "nxe_jwx: keyval document size out of range");
        return NULL;
    }

    input.data = keyval_json->data;
    input.len = keyval_json->len;
    root = nxe_json_parse_untrusted(&input, pool);
    if (root == NULL || nxe_json_type(root) != NXE_JSON_OBJECT) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "nxe_jwx: keyval root is not object");
        if (root != NULL) {
            nxe_json_free(root);
        }
        return NULL;
    }

    /*
     * Without nxe-json object iteration, expose only the
     * single-key shortcut: {"k": "<PEM>"}.  Operators that need
     * multi-key keyval should migrate to a JWKS document.
     */
    {
        ngx_str_t pem;
        EVP_PKEY *pkey;
        nxe_jwx_kty_t kty;

        if (nxe_jwx_string_field(root, "k", &pem) != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "nxe_jwx: keyval document does not expose a 'k' member;"
                          " multi-kid keyval support is pending nxe-json iteration");
            nxe_json_free(root);
            return NULL;
        }

        pkey = nxe_jwx_load_pem_pubkey(&pem);
        if (pkey == NULL) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "nxe_jwx: keyval 'k' is not a recognizable PEM public key");
            nxe_json_free(root);
            return NULL;
        }

        kty = nxe_jwx_kty_from_pkey(pkey);
        if (kty == NXE_JWX_KTY_UNKNOWN) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "nxe_jwx: keyval 'k' has unsupported key type");
            EVP_PKEY_free(pkey);
            nxe_json_free(root);
            return NULL;
        }

        jwks = nxe_jwx_jwks_alloc(pool, 1);
        if (jwks == NULL) {
            EVP_PKEY_free(pkey);
            nxe_json_free(root);
            return NULL;
        }
        jwks->keys[0].pkey = pkey;
        jwks->keys[0].kty = kty;
        jwks->nkeys = 1;
    }

    nxe_json_free(root);

    return jwks;
}


ngx_uint_t
nxe_jwx_jwks_count(const nxe_jwx_jwks_t *jwks)
{
    return jwks != NULL ? jwks->nkeys : 0;
}


/* Internal accessors used by nxe_jwx_jws.c. */

ngx_uint_t
nxe_jwx_jwks_size_internal(const nxe_jwx_jwks_t *jwks)
{
    return jwks != NULL ? jwks->nkeys : 0;
}


struct nxe_jwx_key_s *
nxe_jwx_jwks_key_at(const nxe_jwx_jwks_t *jwks, ngx_uint_t i)
{
    if (jwks == NULL || i >= jwks->nkeys) {
        return NULL;
    }
    return &jwks->keys[i];
}
