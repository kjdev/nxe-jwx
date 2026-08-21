/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 *
 * nxe_jwx_thumbprint.c - RFC 7638 JWK thumbprint computation.
 *
 * Supports OpenSSL 1.1.x and 3.0+; the version split is confined to
 * the per-kty coordinate extraction, matching the style of
 * nxe_jwx_jwks.c's build_*_key helpers.
 */

#include <ngx_config.h>
#include <ngx_core.h>

#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/core_names.h>
#endif

#include "nxe_jwx_internal.h"
#include "nxe_jwx_thumbprint.h"


/*
 * Encode a BIGNUM as a base64url big-endian octet string.  When
 * `pad_len` is 0 the minimal-length encoding is used (RSA n/e); when
 * `pad_len` is nonzero the value is zero-padded to that many octets
 * (EC x/y, which RFC 7518 requires at a fixed field width).
 */
static ngx_int_t
nxe_jwx_bn_to_b64url(const BIGNUM *bn, size_t pad_len, ngx_str_t *out,
    ngx_pool_t *pool)
{
    ngx_str_t raw;
    int len;

    len = pad_len > 0 ? (int) pad_len : BN_num_bytes(bn);
    if (len <= 0) {
        return NGX_ERROR;
    }

    raw.data = ngx_pnalloc(pool, len);
    if (raw.data == NULL) {
        return NGX_ERROR;
    }
    raw.len = len;

    if (pad_len > 0) {
        if (BN_bn2binpad(bn, raw.data, len) < 0) {
            return NGX_ERROR;
        }
    } else if (BN_bn2bin(bn, raw.data) != len) {
        return NGX_ERROR;
    }

    return nxe_jwx_encode_b64url(out, &raw, pool);
}


static ngx_int_t
nxe_jwx_thumbprint_rsa(struct nxe_jwx_key_s *k, ngx_pool_t *pool,
    ngx_str_t *json)
{
    ngx_str_t n_b64, e_b64;
    ngx_int_t rc;
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    BIGNUM *n = NULL, *e = NULL;

    if (!EVP_PKEY_get_bn_param(k->pkey, OSSL_PKEY_PARAM_RSA_N, &n)
        || !EVP_PKEY_get_bn_param(k->pkey, OSSL_PKEY_PARAM_RSA_E, &e))
    {
        BN_free(n);
        BN_free(e);
        return NGX_ERROR;
    }

    rc = nxe_jwx_bn_to_b64url(n, 0, &n_b64, pool);
    if (rc == NGX_OK) {
        rc = nxe_jwx_bn_to_b64url(e, 0, &e_b64, pool);
    }

    BN_free(n);
    BN_free(e);
#else
    const RSA *rsa;
    const BIGNUM *n, *e;

    rsa = EVP_PKEY_get0_RSA(k->pkey);
    if (rsa == NULL) {
        return NGX_ERROR;
    }

    RSA_get0_key(rsa, &n, &e, NULL);
    if (n == NULL || e == NULL) {
        return NGX_ERROR;
    }

    rc = nxe_jwx_bn_to_b64url(n, 0, &n_b64, pool);
    if (rc == NGX_OK) {
        rc = nxe_jwx_bn_to_b64url(e, 0, &e_b64, pool);
    }
#endif

    if (rc != NGX_OK) {
        return NGX_ERROR;
    }

    {
        static const char rsa_start[] = "{\"e\":\"";
        static const char rsa_mid[] = "\",\"kty\":\"RSA\",\"n\":\"";
        static const char rsa_end[] = "\"}";
        u_char *p;

        json->data = ngx_pnalloc(pool,
                                 sizeof(rsa_start) - 1 + e_b64.len +
                                 sizeof(rsa_mid) - 1
                                 + n_b64.len + sizeof(rsa_end) - 1);
        if (json->data == NULL) {
            return NGX_ERROR;
        }

        p = json->data;
        ngx_memcpy(p, rsa_start, sizeof(rsa_start) - 1);
        p += sizeof(rsa_start) - 1;
        ngx_memcpy(p, e_b64.data, e_b64.len);
        p += e_b64.len;
        ngx_memcpy(p, rsa_mid, sizeof(rsa_mid) - 1);
        p += sizeof(rsa_mid) - 1;
        ngx_memcpy(p, n_b64.data, n_b64.len);
        p += n_b64.len;
        ngx_memcpy(p, rsa_end, sizeof(rsa_end) - 1);
        p += sizeof(rsa_end) - 1;
        json->len = (size_t) (p - json->data);
    }

    return NGX_OK;
}


static ngx_int_t
nxe_jwx_thumbprint_ec(struct nxe_jwx_key_s *k, ngx_pool_t *pool,
    ngx_str_t *json)
{
    ngx_str_t x_b64, y_b64;
    ngx_int_t rc;
    size_t coord_len;
    int bits;
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    BIGNUM *x = NULL, *y = NULL;
#else
    const EC_KEY *ec;
    const EC_GROUP *group;
    const EC_POINT *pub;
    BIGNUM *x, *y;
#endif

    bits = EVP_PKEY_bits(k->pkey);
    if (bits <= 0) {
        return NGX_ERROR;
    }
    coord_len = (size_t) (bits + 7) / 8;

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    if (!EVP_PKEY_get_bn_param(k->pkey, OSSL_PKEY_PARAM_EC_PUB_X, &x)
        || !EVP_PKEY_get_bn_param(k->pkey, OSSL_PKEY_PARAM_EC_PUB_Y, &y))
    {
        BN_free(x);
        BN_free(y);
        return NGX_ERROR;
    }

    rc = nxe_jwx_bn_to_b64url(x, coord_len, &x_b64, pool);
    if (rc == NGX_OK) {
        rc = nxe_jwx_bn_to_b64url(y, coord_len, &y_b64, pool);
    }

    BN_free(x);
    BN_free(y);
#else
    ec = EVP_PKEY_get0_EC_KEY(k->pkey);
    if (ec == NULL) {
        return NGX_ERROR;
    }

    group = EC_KEY_get0_group(ec);
    pub = EC_KEY_get0_public_key(ec);
    if (group == NULL || pub == NULL) {
        return NGX_ERROR;
    }

    x = BN_new();
    y = BN_new();
    if (x == NULL || y == NULL) {
        BN_free(x);
        BN_free(y);
        return NGX_ERROR;
    }

    if (!EC_POINT_get_affine_coordinates(group, pub, x, y, NULL)) {
        BN_free(x);
        BN_free(y);
        return NGX_ERROR;
    }

    rc = nxe_jwx_bn_to_b64url(x, coord_len, &x_b64, pool);
    if (rc == NGX_OK) {
        rc = nxe_jwx_bn_to_b64url(y, coord_len, &y_b64, pool);
    }

    BN_free(x);
    BN_free(y);
#endif

    if (rc != NGX_OK) {
        return NGX_ERROR;
    }

    {
        static const char ec_start[] = "{\"crv\":\"";
        static const char ec_mid1[] = "\",\"kty\":\"EC\",\"x\":\"";
        static const char ec_mid2[] = "\",\"y\":\"";
        static const char ec_end[] = "\"}";
        u_char *p;

        json->data = ngx_pnalloc(pool,
                                 sizeof(ec_start) - 1 + k->crv.len +
                                 sizeof(ec_mid1) - 1
                                 + x_b64.len + sizeof(ec_mid2) - 1 + y_b64.len
                                 + sizeof(ec_end) - 1);
        if (json->data == NULL) {
            return NGX_ERROR;
        }

        p = json->data;
        ngx_memcpy(p, ec_start, sizeof(ec_start) - 1);
        p += sizeof(ec_start) - 1;
        ngx_memcpy(p, k->crv.data, k->crv.len);
        p += k->crv.len;
        ngx_memcpy(p, ec_mid1, sizeof(ec_mid1) - 1);
        p += sizeof(ec_mid1) - 1;
        ngx_memcpy(p, x_b64.data, x_b64.len);
        p += x_b64.len;
        ngx_memcpy(p, ec_mid2, sizeof(ec_mid2) - 1);
        p += sizeof(ec_mid2) - 1;
        ngx_memcpy(p, y_b64.data, y_b64.len);
        p += y_b64.len;
        ngx_memcpy(p, ec_end, sizeof(ec_end) - 1);
        p += sizeof(ec_end) - 1;
        json->len = (size_t) (p - json->data);
    }

    return NGX_OK;
}


static ngx_int_t
nxe_jwx_thumbprint_okp(struct nxe_jwx_key_s *k, ngx_pool_t *pool,
    ngx_str_t *json)
{
    u_char raw[64];
    size_t raw_len;
    ngx_str_t raw_str, x_b64;

    raw_len = sizeof(raw);
    if (!EVP_PKEY_get_raw_public_key(k->pkey, raw, &raw_len)) {
        return NGX_ERROR;
    }

    raw_str.data = raw;
    raw_str.len = raw_len;

    if (nxe_jwx_encode_b64url(&x_b64, &raw_str, pool) != NGX_OK) {
        return NGX_ERROR;
    }

    {
        static const char okp_start[] = "{\"crv\":\"";
        static const char okp_mid[] = "\",\"kty\":\"OKP\",\"x\":\"";
        static const char okp_end[] = "\"}";
        u_char *p;

        json->data = ngx_pnalloc(pool,
                                 sizeof(okp_start) - 1 + k->crv.len +
                                 sizeof(okp_mid) - 1
                                 + x_b64.len + sizeof(okp_end) - 1);
        if (json->data == NULL) {
            return NGX_ERROR;
        }

        p = json->data;
        ngx_memcpy(p, okp_start, sizeof(okp_start) - 1);
        p += sizeof(okp_start) - 1;
        ngx_memcpy(p, k->crv.data, k->crv.len);
        p += k->crv.len;
        ngx_memcpy(p, okp_mid, sizeof(okp_mid) - 1);
        p += sizeof(okp_mid) - 1;
        ngx_memcpy(p, x_b64.data, x_b64.len);
        p += x_b64.len;
        ngx_memcpy(p, okp_end, sizeof(okp_end) - 1);
        p += sizeof(okp_end) - 1;
        json->len = (size_t) (p - json->data);
    }

    return NGX_OK;
}


#if (NXE_JWX_HAVE_HMAC)
static ngx_int_t
nxe_jwx_thumbprint_oct(struct nxe_jwx_key_s *k, ngx_pool_t *pool,
    ngx_str_t *json)
{
    ngx_str_t k_b64;

    if (nxe_jwx_encode_b64url(&k_b64, &k->hmac_secret, pool) != NGX_OK) {
        return NGX_ERROR;
    }

    {
        static const char oct_start[] = "{\"k\":\"";
        static const char oct_end[] = "\",\"kty\":\"oct\"}";
        u_char *p;

        json->data = ngx_pnalloc(pool,
                                 sizeof(oct_start) - 1 + k_b64.len +
                                 sizeof(oct_end) - 1);
        if (json->data == NULL) {
            return NGX_ERROR;
        }

        p = json->data;
        ngx_memcpy(p, oct_start, sizeof(oct_start) - 1);
        p += sizeof(oct_start) - 1;
        ngx_memcpy(p, k_b64.data, k_b64.len);
        p += k_b64.len;
        ngx_memcpy(p, oct_end, sizeof(oct_end) - 1);
        p += sizeof(oct_end) - 1;
        json->len = (size_t) (p - json->data);
    }

    /*
     * k_b64 is a base64url (trivially reversible) copy of the HMAC
     * secret; its bytes now also live inside *json, but this buffer
     * itself is redundant once the copy is made, so cleanse it here
     * rather than leaving two lingering plaintext-equivalent copies.
     */
    OPENSSL_cleanse(k_b64.data, k_b64.len);

    return NGX_OK;
}
#endif


ngx_int_t
nxe_jwx_jwk_thumbprint(struct nxe_jwx_key_s *k, ngx_pool_t *pool)
{
    ngx_str_t json, digest_str;
    ngx_int_t rc;
    u_char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len;
    const EVP_MD *md;

    if (k == NULL || pool == NULL) {
        return NGX_ERROR;
    }

    ngx_str_null(&k->thumbprint);

    switch (k->kty) {
    case NXE_JWX_KTY_RSA:
        rc = nxe_jwx_thumbprint_rsa(k, pool, &json);
        break;
    case NXE_JWX_KTY_EC:
        rc = nxe_jwx_thumbprint_ec(k, pool, &json);
        break;
    case NXE_JWX_KTY_OKP:
        rc = nxe_jwx_thumbprint_okp(k, pool, &json);
        break;
#if (NXE_JWX_HAVE_HMAC)
    case NXE_JWX_KTY_OCT:
        rc = nxe_jwx_thumbprint_oct(k, pool, &json);
        break;
#endif
    default:
        return NGX_DECLINED;
    }

    if (rc != NGX_OK) {
        return NGX_ERROR;
    }

    md = EVP_get_digestbyname("SHA256");
    if (md == NULL) {
        return NGX_ERROR;
    }

    if (!EVP_Digest(json.data, json.len, digest, &digest_len, md, NULL)) {
        return NGX_ERROR;
    }

#if (NXE_JWX_HAVE_HMAC)
    /* json embeds a base64url copy of the oct secret; scrub it now
     * that the digest has been taken. */
    if (k->kty == NXE_JWX_KTY_OCT) {
        OPENSSL_cleanse(json.data, json.len);
    }
#endif

    digest_str.data = digest;
    digest_str.len = digest_len;

    return nxe_jwx_encode_b64url(&k->thumbprint, &digest_str, pool);
}
