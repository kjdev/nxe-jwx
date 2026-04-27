/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 *
 * test_crypto.h - cryptographic fixture helpers for nxe-jwx tests.
 *
 * These helpers generate keypairs, JWKs, and JWS signatures at
 * runtime so that JWS verification tests do not depend on external
 * fixture files or pre-generated material.
 */

#ifndef TEST_CRYPTO_H
#define TEST_CRYPTO_H

#include <ngx_config.h>
#include <ngx_core.h>

#include <openssl/evp.h>


/* Base64URL encode `len` bytes into a pool-allocated ngx_str_t (no padding). */
ngx_str_t test_b64url(const u_char *src, size_t len, ngx_pool_t *pool);


/*
 * Build a JWT compact serialization "header.payload.sig":
 *   - header_json / payload_json are JSON literals (not base64url)
 *   - sig is raw signature bytes (RSA/HMAC signature, or R||S for ECDSA)
 *
 * Returns an empty ngx_str_t on allocation failure.
 */
ngx_str_t test_jwt_build(const char *header_json, const char *payload_json,
    const u_char *sig, size_t sig_len, ngx_pool_t *pool);


/* Construct the signing input "header_b64.payload_b64" used to sign. */
ngx_str_t test_signing_input(const char *header_json, const char *payload_json,
    ngx_pool_t *pool);


/* Generate keypairs (caller must EVP_PKEY_free). */
EVP_PKEY *test_gen_rsa(int bits);
EVP_PKEY *test_gen_ec(int nid);
EVP_PKEY *test_gen_ed25519(void);


/*
 * Build a JWK JSON literal (NOT base64url-wrapped) for the public part
 * of `pkey`.  `kid` and `alg` may be NULL.
 *
 *   test_jwk_rsa(pkey, kid, alg, pool)         -> {"kty":"RSA",...}
 *   test_jwk_ec(pkey, crv, kid, alg, pool)     -> {"kty":"EC",...}
 *   test_jwk_okp(pkey, crv, kid, alg, pool)    -> {"kty":"OKP",...}
 *   test_jwk_oct(secret, len, kid, alg, pool)  -> {"kty":"oct","k":"..."}
 */
ngx_str_t test_jwk_rsa(EVP_PKEY *pkey, const char *kid, const char *alg,
    ngx_pool_t *pool);
ngx_str_t test_jwk_ec(EVP_PKEY *pkey, const char *crv, size_t coord_len,
    const char *kid, const char *alg, ngx_pool_t *pool);
ngx_str_t test_jwk_okp(EVP_PKEY *pkey, const char *crv, size_t key_len,
    const char *kid, const char *alg, ngx_pool_t *pool);
ngx_str_t test_jwk_oct(const u_char *secret, size_t len, const char *kid,
    const char *alg, ngx_pool_t *pool);


/* Wrap one or more JWKs in a JWKS document {"keys":[...]}. */
ngx_str_t test_jwks_build(const ngx_str_t *jwks, size_t njwks,
    ngx_pool_t *pool);


/*
 * Sign `signing_input` with `pkey` using `digest` (NULL for EdDSA).
 * If `pss` is true, RSASSA-PSS padding is used.
 *
 * For ECDSA keys, the OpenSSL DER signature is converted to raw R||S
 * fixed at `coord_len` per component when coord_len > 0.
 *
 * Returns the raw signature bytes in *out / *out_len, allocated on
 * `pool`.  Returns NGX_OK on success.
 */
ngx_int_t test_sign(EVP_PKEY *pkey, const char *digest, int pss,
    size_t ec_coord_len,
    const u_char *msg, size_t msg_len,
    u_char **out, size_t *out_len, ngx_pool_t *pool);


/* HMAC sign.  `digest` is "SHA256"/"SHA384"/"SHA512". */
ngx_int_t test_hmac_sign(const u_char *key, size_t key_len,
    const char *digest, const u_char *msg, size_t msg_len,
    u_char **out, size_t *out_len, ngx_pool_t *pool);


/* Pool-allocated PEM-encoded SubjectPublicKeyInfo of pkey. */
ngx_str_t test_pem_pubkey(EVP_PKEY *pkey, ngx_pool_t *pool);


#endif /* TEST_CRYPTO_H */
