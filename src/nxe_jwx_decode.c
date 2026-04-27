/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 *
 * nxe_jwx_decode.c - JWT compact-serialization decoding
 */

#include <ngx_config.h>
#include <ngx_core.h>

#include <openssl/crypto.h>

#include <nxe_json.h>

#include "nxe_jwx.h"
#include "nxe_jwx_internal.h"


/*
 * Decoded token.  All buffers and JSON handles are owned by the
 * pool that produced the token; the cleanup handler released them
 * deterministically when the pool is destroyed.
 */
struct nxe_jwx_token_s {
    nxe_json_t *header;
    nxe_json_t *payload;

    /* zero-copy views into the parsed header */
    ngx_str_t   alg;
    ngx_str_t   kid;

    /*
     * "<header_b64>.<payload_b64>" -- the signing input that gets
     * fed to EVP_DigestVerify*.  Allocated as a single contiguous
     * buffer; the dot is preserved.
     */
    ngx_str_t  signing_input;

    /* raw signature bytes (base64url-decoded). */
    ngx_str_t  signature;
};


static void
nxe_jwx_token_cleanup(void *data)
{
    nxe_jwx_token_t *token = data;

    if (token == NULL) {
        return;
    }

    if (token->header != NULL) {
        nxe_json_free(token->header);
        token->header = NULL;
    }

    if (token->payload != NULL) {
        nxe_json_free(token->payload);
        token->payload = NULL;
    }

    /*
     * `signing_input` holds the public "<header_b64>.<payload_b64>" prefix of
     * the token; it carries no secret material so we do not cleanse it.
     * The signature bytes are likewise public, but cleansing them here is
     * cheap and matches the broader fail-closed posture of the library.
     */
    if (token->signature.data != NULL && token->signature.len > 0) {
        OPENSSL_cleanse(token->signature.data, token->signature.len);
    }
}


/*
 * Locate the two '.' separators of the compact serialization.
 * Rejects tokens that have fewer or more than two dots, or any empty
 * segment.  On success the segments span:
 *
 *   header   = [data,           dot1)
 *   payload  = [dot1+1,         dot2)
 *   signing  = [data,           dot2)        -- header || '.' || payload
 *   signature = [dot2+1,        end)
 */
static ngx_int_t
nxe_jwx_split_segments(const ngx_str_t *token, ngx_str_t *header,
    ngx_str_t *payload, ngx_str_t *signing, ngx_str_t *signature,
    ngx_log_t *log)
{
    u_char *p, *end, *dot1, *dot2;

    p = token->data;
    end = p + token->len;
    dot1 = NULL;
    dot2 = NULL;

    for (u_char *q = p; q < end; q++) {
        if (*q != '.') {
            continue;
        }
        if (dot1 == NULL) {
            dot1 = q;
        } else if (dot2 == NULL) {
            dot2 = q;
        } else {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "nxe_jwx: token has more than three segments");
            return NGX_ERROR;
        }
    }

    if (dot1 == NULL || dot2 == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "nxe_jwx: token must have three dot-separated segments");
        return NGX_ERROR;
    }

    header->data = p;
    header->len = (size_t) (dot1 - p);
    payload->data = dot1 + 1;
    payload->len = (size_t) (dot2 - dot1 - 1);
    signing->data = p;
    signing->len = (size_t) (dot2 - p);
    signature->data = dot2 + 1;
    signature->len = (size_t) (end - dot2 - 1);

    if (header->len == 0 || payload->len == 0 || signature->len == 0) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "nxe_jwx: token has an empty segment");
        return NGX_ERROR;
    }

    if (header->len > NXE_JWX_MAX_JWT_HEADER) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "nxe_jwx: header segment exceeds %ui bytes",
                      (ngx_uint_t) NXE_JWX_MAX_JWT_HEADER);
        return NGX_ERROR;
    }

    return NGX_OK;
}


/*
 * Allocate a buffer on `pool` sized for the base64url-decoded form
 * of `src`, then decode into it.  Sets `dst->len` to the decoded
 * length.  Returns NGX_OK / NGX_ERROR.
 */
static ngx_int_t
nxe_jwx_decode_b64url(ngx_str_t *dst, const ngx_str_t *src,
    ngx_pool_t *pool)
{
    ngx_str_t src_mut;
    size_t max_len;

    max_len = ngx_base64_decoded_length(src->len);

    dst->data = ngx_pnalloc(pool, max_len);
    if (dst->data == NULL) {
        return NGX_ERROR;
    }
    dst->len = 0;

    /* ngx_decode_base64url takes a non-const ngx_str_t * for src. */
    src_mut.data = src->data;
    src_mut.len = src->len;

    if (ngx_decode_base64url(dst, &src_mut) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


/*
 * Parse a JSON document and require it to be a JSON object.  Used
 * for both header and payload, which are always objects per
 * RFC 7519 section 7.2.
 */
static nxe_json_t *
nxe_jwx_parse_json_object(ngx_str_t *raw, ngx_pool_t *pool, const char *what)
{
    nxe_json_t *json;
    ngx_log_t *log;

    log = nxe_jwx_log(pool);

    json = nxe_json_parse_untrusted(raw, pool);
    if (json == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "nxe_jwx: failed to parse %s as JSON", what);
        return NULL;
    }

    if (nxe_json_type(json) != NXE_JSON_OBJECT) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "nxe_jwx: %s is not a JSON object", what);
        nxe_json_free(json);
        return NULL;
    }

    return json;
}


/*
 * Read a string-typed field from the header (alg / kid).  Missing or
 * non-string values leave *out zeroed; this is not an error here.
 */
static void
nxe_jwx_read_header_string(nxe_json_t *header, const char *key,
    ngx_str_t *out)
{
    nxe_json_t *node;

    out->data = NULL;
    out->len = 0;

    node = nxe_json_object_get(header, key);
    if (node == NULL) {
        return;
    }
    if (nxe_json_type(node) != NXE_JSON_STRING) {
        return;
    }

    (void) nxe_json_string(node, out);
}


nxe_jwx_token_t *
nxe_jwx_decode(const ngx_str_t *token_str, ngx_pool_t *pool)
{
    nxe_jwx_token_t *token;
    ngx_pool_cleanup_t *cln;
    ngx_str_t header_b64, payload_b64, signing_b64, signature_b64;
    ngx_str_t header_raw, payload_raw;
    ngx_log_t *log;

    if (pool == NULL) {
        return NULL;
    }
    log = nxe_jwx_log(pool);

    if (token_str == NULL || token_str->data == NULL || token_str->len == 0) {
        ngx_log_error(NGX_LOG_ERR, log, 0, "nxe_jwx: empty token");
        return NULL;
    }

    if (token_str->len > NXE_JWX_MAX_JWT_SIZE) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "nxe_jwx: token exceeds %ui bytes",
                      (ngx_uint_t) NXE_JWX_MAX_JWT_SIZE);
        return NULL;
    }

    if (nxe_jwx_split_segments(token_str, &header_b64, &payload_b64,
                               &signing_b64, &signature_b64, log) != NGX_OK)
    {
        return NULL;
    }

    token = ngx_pcalloc(pool, sizeof(*token));
    if (token == NULL) {
        return NULL;
    }

    /*
     * Register the cleanup before decoding so that any partial
     * state we've allocated below is reclaimed if a later step
     * fails.  The handler is null-safe.
     */
    cln = ngx_pool_cleanup_add(pool, 0);
    if (cln == NULL) {
        return NULL;
    }
    cln->handler = nxe_jwx_token_cleanup;
    cln->data = token;

    /* Copy the signing input into a pool buffer (we may need it after
     * the caller's `token_str` storage is gone). */
    token->signing_input.data = ngx_pnalloc(pool, signing_b64.len);
    if (token->signing_input.data == NULL) {
        return NULL;
    }
    ngx_memcpy(token->signing_input.data, signing_b64.data, signing_b64.len);
    token->signing_input.len = signing_b64.len;

    /* Header. */
    if (nxe_jwx_decode_b64url(&header_raw, &header_b64, pool) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "nxe_jwx: invalid base64url in header");
        return NULL;
    }
    token->header = nxe_jwx_parse_json_object(&header_raw, pool, "header");
    OPENSSL_cleanse(header_raw.data, header_raw.len);
    if (token->header == NULL) {
        return NULL;
    }

    /* Payload. */
    if (nxe_jwx_decode_b64url(&payload_raw, &payload_b64, pool) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "nxe_jwx: invalid base64url in payload");
        return NULL;
    }
    token->payload = nxe_jwx_parse_json_object(&payload_raw, pool, "payload");
    OPENSSL_cleanse(payload_raw.data, payload_raw.len);
    if (token->payload == NULL) {
        return NULL;
    }

    /* Signature. */
    if (nxe_jwx_decode_b64url(&token->signature, &signature_b64, pool)
        != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "nxe_jwx: invalid base64url in signature");
        return NULL;
    }

    /* Header lookups. */
    nxe_jwx_read_header_string(token->header, "alg", &token->alg);
    nxe_jwx_read_header_string(token->header, "kid", &token->kid);

    return token;
}


nxe_json_t *
nxe_jwx_token_header(const nxe_jwx_token_t *token)
{
    return token != NULL ? token->header : NULL;
}


nxe_json_t *
nxe_jwx_token_payload(const nxe_jwx_token_t *token)
{
    return token != NULL ? token->payload : NULL;
}


const ngx_str_t *
nxe_jwx_token_alg(const nxe_jwx_token_t *token)
{
    if (token == NULL || token->alg.len == 0) {
        return NULL;
    }
    return &token->alg;
}


const ngx_str_t *
nxe_jwx_token_kid(const nxe_jwx_token_t *token)
{
    if (token == NULL || token->kid.len == 0) {
        return NULL;
    }
    return &token->kid;
}


/* Internal accessors used by sibling translation units. */

ngx_str_t *
nxe_jwx_token_signing_input(nxe_jwx_token_t *token)
{
    return &token->signing_input;
}


ngx_str_t *
nxe_jwx_token_signature(nxe_jwx_token_t *token)
{
    return &token->signature;
}
