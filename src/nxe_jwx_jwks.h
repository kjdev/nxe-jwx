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
 *   - NXE_JWX_MIN_RSA_BITS <= RSA modulus <= NXE_JWX_MAX_RSA_BITS
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
 *   { "kid1": "<PEM>", "kid2": "<PEM>", ... }
 *
 * Compatibility shim for nginx-auth-jwt's `auth_jwt_keyval` directive,
 * which lets operators load keys from a flat JSON map rather than a
 * proper JWKS document.  Each value must be a PEM-encoded public key
 * (RSA / EC / OKP); the key type is derived from the parsed EVP_PKEY.
 * Any value that does not parse as PEM is skipped with a warning.
 *
 * HMAC (oct) secrets are intentionally NOT supported here, even when
 * the library is built with NXE_JWX_HAVE_HMAC.  Accepting raw bytes as
 * an HMAC fallback would let a typo in the operator's PEM be used as
 * the HMAC key and enable the classic RSA/EC -> HS* algorithm-
 * confusion forgery, because the operator's "public" PEM text is
 * itself public information.  Operators that need HMAC must supply a
 * proper JWKS document with `kty: "oct"` entries.
 *
 * Iteration order matches the JSON document's insertion order.  The
 * same DoS limits as nxe_jwx_jwks_parse apply (size, key count).
 * Returns NULL on hard failure or when no usable keys remain.
 */
nxe_jwx_jwks_t *nxe_jwx_jwks_parse_keyval(const ngx_str_t *keyval_json,
    ngx_pool_t *pool);


/*
 * Release all resources owned by `jwks` (EVP_PKEY objects and any
 * cleansed HMAC secrets) and disarm the pool cleanup handler that
 * nxe_jwx_jwks_parse / nxe_jwx_jwks_parse_keyval registered, so the
 * eventual pool teardown does not double-free.  Passing NULL is a
 * no-op; calling it more than once on the same handle is harmless.
 *
 * Two release patterns are therefore supported:
 *   - Pool-driven (legacy): do nothing and let ngx_destroy_pool run the
 *     registered cleanup.  Sufficient when the keyset's pool is torn
 *     down on a predictable schedule (e.g. a per-request or per-cycle
 *     pool).
 *   - Explicit: call nxe_jwx_jwks_free when the keyset must be released
 *     before its pool is destroyed -- e.g. a long-lived master-process
 *     pool that survives config reloads, where leaving the EVP_PKEY
 *     objects to pool teardown would leak them across every reload.
 *
 * The pool-owned bookkeeping (keys array and the kid/alg/crv copies) is
 * not individually freed; it is reclaimed when the parent pool is
 * destroyed.  After this call `jwks` MUST NOT be passed to any other
 * nxe_jwx_jwks_* / nxe_jwx_jws_* function.
 */
void nxe_jwx_jwks_free(nxe_jwx_jwks_t *jwks);


/* Number of usable keys held by the keyset. */
ngx_uint_t nxe_jwx_jwks_count(const nxe_jwx_jwks_t *jwks);


/*
 * Report whether the keyset contains at least one key whose kid
 * matches the supplied identifier.  Returns 1 on match, 0 otherwise.
 *
 * Pairs with nxe_jwx_jws_verify() for callers that want to log a
 * specific "kid declared but signature failed" message: under the
 * kid-strict policy, the verifier returns NGX_DECLINED in that case,
 * and the caller can use this helper to disambiguate from "no key
 * for this kid".  A NULL or zero-length kid returns 0.
 */
ngx_flag_t nxe_jwx_jwks_has_kid(const nxe_jwx_jwks_t *jwks,
    const ngx_str_t *kid);


#endif /* _NXE_JWX_JWKS_H_INCLUDED_ */
