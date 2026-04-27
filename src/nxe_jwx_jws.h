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
 * Key selection (kid-strict):
 *   - If the token names a "kid" and the keyset contains at least
 *     one key with the same kid, ONLY those keys are tried.  A
 *     signature failure on a kid-matched key falls through to
 *     NGX_DECLINED rather than re-trying other keys.
 *   - If the token names a kid that is absent from the keyset, the
 *     verifier falls back to trying only the keyset's kid-less keys.
 *     Other kid-labelled keys are skipped: a token claiming kid A
 *     is never validated by a key that explicitly identifies as
 *     kid B, which would otherwise enable key-confusion attacks
 *     against operators who label their keys.
 *   - If the token carries no kid, every key whose kty/alg is
 *     compatible is tried.
 *   - When the JWK supplies an "alg" parameter, the token's alg
 *     must match it byte-for-byte; otherwise the key is skipped
 *     even if the underlying kty / curve is compatible.
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
