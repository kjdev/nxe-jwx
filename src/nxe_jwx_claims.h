/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 *
 * nxe_jwx_claims.h - convenience helpers for extracting claims
 *
 * The library does NOT validate registered claims (iss/aud/exp/nbf/
 * iat/jti); each upstream module enforces its own policy (e.g. clock
 * skew tolerance, multi-aud handling).  These helpers exist solely
 * to make the type-checked extraction pattern less verbose than
 * driving nxe-json directly.
 */

#ifndef _NXE_JWX_CLAIMS_H_INCLUDED_
#define _NXE_JWX_CLAIMS_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>

#include <nxe_json.h>


/*
 * Extract a top-level claim by name.  All accessors share the same
 * semantics:
 *
 *   NGX_OK        claim present and of the expected type;
 *                 *out has been populated
 *   NGX_DECLINED  claim absent
 *   NGX_ERROR     claim present but of the wrong JSON type
 *
 * The accessors do NOT walk dotted paths.  For nested access the
 * caller drills down with nxe_json_object_get / nxe_json_array_get
 * and then re-enters the helper at the leaf.
 *
 * Strings are returned as zero-copy views into the underlying JSON
 * buffer.  Callers that need the value to outlive the JSON object
 * must copy it into the pool themselves.
 */

ngx_int_t nxe_jwx_claims_get_string(nxe_json_t *obj, const char *name,
    ngx_str_t *out);

ngx_int_t nxe_jwx_claims_get_integer(nxe_json_t *obj, const char *name,
    int64_t *out);

ngx_int_t nxe_jwx_claims_get_boolean(nxe_json_t *obj, const char *name,
    ngx_flag_t *out);

ngx_int_t nxe_jwx_claims_get_array(nxe_json_t *obj, const char *name,
    nxe_json_t **out);

ngx_int_t nxe_jwx_claims_get_object(nxe_json_t *obj, const char *name,
    nxe_json_t **out);


#endif /* _NXE_JWX_CLAIMS_H_INCLUDED_ */
