/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 *
 * nxe_jwx_jws.h - JWS signature generation and verification
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


/*
 * Build a signed compact JWS (JWT):
 *
 *     "<b64url header>.<b64url payload>.<b64url signature>"
 *
 * This is the issuing counterpart of nxe_jwx_jws_verify(); the two
 * share the algorithm table and the ECDSA R||S <-> DER conversion.
 *
 * Arguments:
 *   pool    allocation pool for `out` and all intermediates.
 *   alg     "HS256"/"HS384"/"HS512" (only with NXE_JWX_HAVE_HMAC),
 *           "RS256"/"384"/"512", "PS256"/"384"/"512",
 *           "ES256"/"384"/"512"/"ES256K", "EdDSA".  "none" is ALWAYS
 *           rejected, regardless of build flags (mirrors the verify
 *           policy).
 *   kid     optional; when its len > 0 it is emitted as the "kid"
 *           header parameter (JSON-escaped).  Pass NULL or a zero-
 *           length ngx_str_t to omit it.
 *   claims  caller-serialised compact JSON OBJECT used verbatim as the
 *           payload.  The caller owns escaping its contents; the
 *           encoder only checks that the bytes parse as a JSON object.
 *   key     HMAC secret bytes for HS*, or a PEM-encoded PRIVATE key for
 *           the asymmetric families.
 *   out     receives the compact JWS, pool-allocated and NUL-terminated
 *           (out->data[out->len] == '\0', matching the token-string
 *           contract).
 *
 * The header always carries "typ":"JWT" in addition to "alg" (and the
 * optional "kid").
 *
 * Return value:
 *   NGX_OK     `out` holds the signed token.
 *   NGX_ERROR  unknown/forbidden alg, key/claims format error, key that
 *              does not match the alg, or any crypto/allocation failure.
 *
 * Unlike the verify side there is no NGX_DECLINED: issuing is performed
 * by the operator's own code, so failure modes are not an oracle and
 * collapse to NGX_ERROR.
 */
ngx_int_t nxe_jwx_encode(ngx_pool_t *pool, const ngx_str_t *alg,
    const ngx_str_t *kid, const ngx_str_t *claims, const ngx_str_t *key,
    ngx_str_t *out);


#endif /* _NXE_JWX_JWS_H_INCLUDED_ */
