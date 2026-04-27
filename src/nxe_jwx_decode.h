/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 *
 * nxe_jwx_decode.h - JWT token decoding
 */

#ifndef _NXE_JWX_DECODE_H_INCLUDED_
#define _NXE_JWX_DECODE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>

#include <nxe_json.h>


/*
 * Decode a JWT (header.payload.signature) into an opaque token object.
 *
 *   - Splits the compact serialization on '.'; rejects any token
 *     that does not have exactly three non-empty segments.
 *   - Base64url-decodes header and payload using nginx core
 *     (ngx_decode_base64url).
 *   - Parses both decoded segments as JSON via
 *     nxe_json_parse_untrusted (DoS-hardened).
 *   - Retains the raw signature bytes for later use by
 *     nxe_jwx_jws_verify().
 *   - Retains the signing input ("header_b64.payload_b64") which
 *     JWS verification feeds to EVP_DigestVerify*.
 *   - Tokens larger than NXE_JWX_MAX_JWT_SIZE are rejected outright.
 *   - All buffers are zeroed via OPENSSL_cleanse before being freed
 *     when the pool is destroyed.
 *
 * The returned token is allocated from `pool` and lives until the
 * pool is destroyed.  Callers do not free it explicitly.
 *
 * Returns NULL on any error; failures are logged via pool->log.
 */
nxe_jwx_token_t *nxe_jwx_decode(const ngx_str_t *token, ngx_pool_t *pool);


/*
 * Accessors for fields parsed out of the header.
 *
 * The returned pointers reference memory owned by the token; callers
 * must not free them and must not rely on the data after the pool
 * that owns the token is destroyed.
 */

/* The full parsed header object (JSON object). */
nxe_json_t *nxe_jwx_token_header(const nxe_jwx_token_t *token);

/* The full parsed payload object (JSON object). */
nxe_json_t *nxe_jwx_token_payload(const nxe_jwx_token_t *token);

/* "alg" claim from the header, or NULL if absent / wrong type. */
const ngx_str_t *nxe_jwx_token_alg(const nxe_jwx_token_t *token);

/* "kid" claim from the header, or NULL if absent / wrong type. */
const ngx_str_t *nxe_jwx_token_kid(const nxe_jwx_token_t *token);


#endif /* _NXE_JWX_DECODE_H_INCLUDED_ */
