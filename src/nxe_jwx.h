/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 *
 * nxe_jwx.h - public API aggregator for nxe-jwx
 *
 * nxe-jwx provides JWT decoding, JWS signature verification, JWKS
 * parsing, and claims-extraction helpers.  It is consumed via git
 * submodule by nginx modules (nginx-auth-gate, nginx-auth-jwt,
 * nginx-oidc, ...) that previously implemented these features
 * independently.
 *
 * Design contract:
 *   - JSON parsing is delegated to nxe-json (jansson is never used
 *     directly).
 *   - OpenSSL is required at runtime.  Both 1.1.x and 3.0+ are
 *     supported via OPENSSL_VERSION_NUMBER guards.
 *   - All public types are opaque.  Callers never touch EVP_PKEY,
 *     json_t, or any backend-specific type through this API.
 *   - All allocations are pool-bound; EVP_PKEYs are released through
 *     ngx_pool_cleanup_add hooks.
 */

#ifndef _NXE_JWX_H_INCLUDED_
#define _NXE_JWX_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>

#include <nxe_json.h>


/* === Library version === */

#define NXE_JWX_VERSION_MAJOR   0
#define NXE_JWX_VERSION_MINOR   1
#define NXE_JWX_VERSION_PATCH   0
#define NXE_JWX_VERSION         "0.1.0"


/* === DoS / size limits === */
/*
 * These values are shared across all upstream modules (nginx-auth-gate,
 * nginx-auth-jwt, nginx-oidc) and are intentionally hard-coded as the
 * library's own ceiling.  Callers may impose tighter limits before
 * invoking nxe-jwx; they cannot relax these.
 */

#define NXE_JWX_MAX_JWT_SIZE        16384       /* 16 KiB raw token */
#define NXE_JWX_MAX_JWT_HEADER      8192        /* 8  KiB header segment */
#define NXE_JWX_MAX_JWKS_SIZE       262144      /* 256 KiB JWKS document */
#define NXE_JWX_MAX_JWKS_KEYS       64
#define NXE_JWX_MIN_RSA_BITS        2048
#define NXE_JWX_MAX_RSA_BITS        16384       /* upper bound to bound DoS */


/* === Opaque types === */

typedef struct nxe_jwx_token_s nxe_jwx_token_t;     /* decoded JWT */
typedef struct nxe_jwx_jwks_s nxe_jwx_jwks_t;       /* parsed JWKS */


/* === Sub-system headers === */

#include "nxe_jwx_decode.h"
#include "nxe_jwx_jwks.h"
#include "nxe_jwx_jws.h"
#include "nxe_jwx_claims.h"


#endif /* _NXE_JWX_H_INCLUDED_ */
