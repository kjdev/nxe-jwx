/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 *
 * nxe_jwx_jws.h - JWS signature verification
 */

#ifndef _NXE_JWX_JWS_H_INCLUDED_
#define _NXE_JWX_JWS_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


/*
 * Verify the signature of a decoded token against the supplied keyset.
 *
 * Algorithms:
 *   RS256/384/512   RSA-PKCS1-v1_5 + SHA-2
 *   PS256/384/512   RSA-PSS         + SHA-2 (MGF1 same SHA, salt=hash size)
 *   ES256/384/512   ECDSA           + SHA-2 (R||S converted to DER)
 *   ES256K          ECDSA secp256k1 + SHA-256
 *   EdDSA           Ed25519 / Ed448 (digest is implicit, NULL md)
 *   HS256/384/512   HMAC-SHA-2  [only if NXE_JWX_HAVE_HMAC is defined]
 *
 * Algorithm policy:
 *   - "none" is rejected unconditionally.
 *   - HS* are rejected unless the library is built with
 *     NXE_JWX_HAVE_HMAC.  Even then, the keyset must contain an oct
 *     key with a matching kid (or a kid-less oct key) for the
 *     verification to succeed.
 *
 * Key selection:
 *   - If the token's header has a "kid", the verifier first tries
 *     keys whose kid matches.  If none match (or the token has no
 *     kid) it tries every key whose kty/alg is compatible.
 *   - The first key that produces a valid signature wins.
 *
 * Return value:
 *   NGX_OK        signature verified
 *   NGX_DECLINED  signature did NOT verify, or no key matched, or
 *                 the algorithm is rejected by policy.  The caller
 *                 cannot distinguish these cases (oracle-resistant).
 *   NGX_ERROR     internal failure (out of memory, OpenSSL error
 *                 unrelated to the signature itself, malformed
 *                 input that should have been caught during decode).
 *                 The caller should treat this as 5xx, not 401.
 *
 * Errors are logged via pool->log; details that would aid an
 * attacker (specific key tried, exact failure reason) are kept at
 * NGX_LOG_DEBUG level.
 */
ngx_int_t nxe_jwx_jws_verify(const nxe_jwx_token_t *token,
    const nxe_jwx_jwks_t *jwks, ngx_pool_t *pool);


#endif /* _NXE_JWX_JWS_H_INCLUDED_ */
