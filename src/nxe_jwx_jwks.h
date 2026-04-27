/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 *
 * nxe_jwx_jwks.h - JWKS (JSON Web Key Set) parsing
 */

#ifndef _NXE_JWX_JWKS_H_INCLUDED_
#define _NXE_JWX_JWKS_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


/*
 * Parse a JWKS document of the form {"keys": [ {...}, ... ]}.
 *
 * Supported key types:
 *   - RSA   (kty=RSA, fields n,e)              [always]
 *   - EC    (kty=EC,  crv=P-256/P-384/P-521/secp256k1, x, y)  [always]
 *   - OKP   (kty=OKP, crv=Ed25519/Ed448, x)    [always]
 *   - oct   (kty=oct, k)                       [only if NXE_JWX_HAVE_HMAC]
 *
 * Constraints (fail-closed; document is rejected when violated):
 *   - JWKS document size <= NXE_JWX_MAX_JWKS_SIZE
 *   - Number of keys <= NXE_JWX_MAX_JWKS_KEYS
 *   - RSA modulus >= NXE_JWX_MIN_RSA_BITS
 *
 * Behavior:
 *   - Unknown / unsupported keys are skipped with a warning; parsing
 *     continues.  The document is considered valid as long as at
 *     least one usable key was decoded.
 *   - For each successfully decoded key an EVP_PKEY (or HMAC raw
 *     buffer) is allocated and a pool cleanup handler is registered
 *     that releases it when the pool is destroyed.
 *
 * Returns NULL if the document fails any hard constraint or yields
 * zero usable keys.  Errors are logged via pool->log.
 */
nxe_jwx_jwks_t *nxe_jwx_jwks_parse(const ngx_str_t *jwks_json,
    ngx_pool_t *pool);


/*
 * Parse a key-value style document of the form
 *   { "kid1": "PEM-or-raw", "kid2": "...", ... }
 *
 * Compatibility shim for nginx-auth-jwt's `auth_jwt_keyval` directive,
 * which lets operators load keys from a flat JSON map rather than a
 * proper JWKS document.  Each value is interpreted in this order:
 *   1. PEM-encoded public key (RSA / EC / OKP).  The key type is
 *      derived from the parsed EVP_PKEY.
 *   2. With NXE_JWX_HAVE_HMAC, an opaque oct (HMAC) secret.  The bytes
 *      are stored verbatim and cleansed via OPENSSL_cleanse at
 *      cleanup; no base64url decoding is performed.
 *   3. Otherwise the entry is skipped with a warning.
 *
 * Iteration order matches the JSON document's insertion order.  The
 * same DoS limits as nxe_jwx_jwks_parse apply (size, key count).
 * Returns NULL on hard failure or when no usable keys remain.
 */
nxe_jwx_jwks_t *nxe_jwx_jwks_parse_keyval(const ngx_str_t *keyval_json,
    ngx_pool_t *pool);


/* Number of usable keys held by the keyset. */
ngx_uint_t nxe_jwx_jwks_count(const nxe_jwx_jwks_t *jwks);


#endif /* _NXE_JWX_JWKS_H_INCLUDED_ */
