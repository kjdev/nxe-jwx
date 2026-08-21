/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 *
 * nxe_jwx_thumbprint.h - RFC 7638 JWK thumbprint computation.
 *
 * Internal only: operates on struct nxe_jwx_key_s, so this header is
 * not part of the public API surface and must not be pulled in by
 * nxe_jwx.h.
 */

#ifndef _NXE_JWX_THUMBPRINT_H_INCLUDED_
#define _NXE_JWX_THUMBPRINT_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>

#include "nxe_jwx_internal.h"


/*
 * Compute the RFC 7638 JWK thumbprint of `k` (SHA-256 over the
 * lexicographically-ordered, whitespace-free canonical JSON,
 * base64url-encoded) and cache it in k->thumbprint on `pool`.
 *
 * The canonical member values are re-derived from k->pkey (or
 * k->hmac_secret for oct keys) rather than from any cached raw JWK
 * string, so the result reflects the minimal-octet / fixed-width
 * encodings RFC 7518 requires regardless of how the source JWK was
 * formatted.
 *
 * Returns NGX_OK on success, NGX_DECLINED for a key type that cannot
 * be thumbprinted (NXE_JWX_KTY_UNKNOWN), and NGX_ERROR on internal
 * failure (allocation, OpenSSL).  Failure is non-fatal to the caller:
 * k->thumbprint is left empty and the key remains otherwise usable.
 */
ngx_int_t nxe_jwx_jwk_thumbprint(struct nxe_jwx_key_s *k, ngx_pool_t *pool);


#endif /* _NXE_JWX_THUMBPRINT_H_INCLUDED_ */
