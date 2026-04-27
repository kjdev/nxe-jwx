/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 *
 * nxe_jwx_internal.h - declarations shared between nxe-jwx
 *                      translation units; not part of the public API.
 */

#ifndef _NXE_JWX_INTERNAL_H_INCLUDED_
#define _NXE_JWX_INTERNAL_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>

#include <openssl/evp.h>

#include "nxe_jwx.h"


/*
 * Resolve a log pointer from a pool, tolerating a NULL pool the way
 * nxe-json does.  When `pool` is NULL the caller is in a context
 * where ngx_log_error is a no-op.
 */
static ngx_inline ngx_log_t *
nxe_jwx_log(ngx_pool_t *pool)
{
    return pool != NULL ? pool->log : NULL;
}


/*
 * Token internals (defined in nxe_jwx_decode.c).
 *
 * The signing-input buffer is the verbatim bytes "header_b64 . payload_b64"
 * fed to EVP_DigestVerify*; the signature buffer is the base64url-decoded
 * signature.
 */
ngx_str_t *nxe_jwx_token_signing_input(nxe_jwx_token_t *token);
ngx_str_t *nxe_jwx_token_signature(nxe_jwx_token_t *token);


/*
 * JWKS internals (defined in nxe_jwx_jwks.c).
 *
 * The key structure is exposed here because the verifier walks the
 * keyset directly; we keep the definition opaque to the public API
 * while letting sibling translation units inspect it.
 */

typedef enum {
    NXE_JWX_KTY_UNKNOWN = 0,
    NXE_JWX_KTY_RSA,
    NXE_JWX_KTY_EC,
    NXE_JWX_KTY_OKP,
#if (NXE_JWX_HAVE_HMAC)
    NXE_JWX_KTY_OCT,
#endif
} nxe_jwx_kty_t;


struct nxe_jwx_key_s {
    nxe_jwx_kty_t  kty;
    ngx_str_t      kid;             /* may be empty */
    ngx_str_t      alg;             /* may be empty */
    ngx_str_t      crv;             /* may be empty */

    /* Public-key handle.  NULL for oct keys. */
    EVP_PKEY      *pkey;

#if (NXE_JWX_HAVE_HMAC)
    /* Raw symmetric secret (oct keys only). */
    ngx_str_t      hmac_secret;
#endif
};


ngx_uint_t            nxe_jwx_jwks_size_internal(const nxe_jwx_jwks_t *jwks);
struct nxe_jwx_key_s *nxe_jwx_jwks_key_at(const nxe_jwx_jwks_t *jwks,
    ngx_uint_t i);


#endif /* _NXE_JWX_INTERNAL_H_INCLUDED_ */
