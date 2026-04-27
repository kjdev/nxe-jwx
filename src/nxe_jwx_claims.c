/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 *
 * nxe_jwx_claims.c - typed accessors for JWT claims
 *
 * These are thin wrappers around nxe_json_object_get + the typed
 * scalar accessors.  They exist so callers do not have to repeat
 * the "look up, check type, extract" sequence at every claim site.
 */

#include <ngx_config.h>
#include <ngx_core.h>

#include <nxe_json.h>

#include "nxe_jwx.h"
#include "nxe_jwx_internal.h"


/*
 * Look up `name` in `obj` and return the node together with a status
 * code:
 *
 *   NGX_OK        the key exists; *node is the value
 *   NGX_DECLINED  the key does not exist (or `obj` is not an object)
 *   NGX_ERROR     argument error (NULL obj or NULL name)
 */
static ngx_int_t
nxe_jwx_claims_lookup(nxe_json_t *obj, const char *name, nxe_json_t **node)
{
    if (obj == NULL || name == NULL) {
        return NGX_ERROR;
    }

    *node = nxe_json_object_get(obj, name);
    if (*node == NULL) {
        return NGX_DECLINED;
    }

    return NGX_OK;
}


ngx_int_t
nxe_jwx_claims_get_string(nxe_json_t *obj, const char *name, ngx_str_t *out)
{
    nxe_json_t *node;
    ngx_int_t rc;

    if (out == NULL) {
        return NGX_ERROR;
    }
    out->data = NULL;
    out->len = 0;

    rc = nxe_jwx_claims_lookup(obj, name, &node);
    if (rc != NGX_OK) {
        return rc;
    }

    if (nxe_json_type(node) != NXE_JSON_STRING) {
        return NGX_ERROR;
    }

    return nxe_json_string(node, out);
}


ngx_int_t
nxe_jwx_claims_get_integer(nxe_json_t *obj, const char *name, int64_t *out)
{
    nxe_json_t *node;
    ngx_int_t rc;

    if (out == NULL) {
        return NGX_ERROR;
    }
    *out = 0;

    rc = nxe_jwx_claims_lookup(obj, name, &node);
    if (rc != NGX_OK) {
        return rc;
    }

    if (nxe_json_type(node) != NXE_JSON_INTEGER) {
        return NGX_ERROR;
    }

    return nxe_json_integer(node, out);
}


ngx_int_t
nxe_jwx_claims_get_boolean(nxe_json_t *obj, const char *name, ngx_flag_t *out)
{
    nxe_json_t *node;
    ngx_int_t rc;

    if (out == NULL) {
        return NGX_ERROR;
    }
    *out = 0;

    rc = nxe_jwx_claims_lookup(obj, name, &node);
    if (rc != NGX_OK) {
        return rc;
    }

    if (nxe_json_type(node) != NXE_JSON_BOOLEAN) {
        return NGX_ERROR;
    }

    return nxe_json_boolean(node, out);
}


ngx_int_t
nxe_jwx_claims_get_array(nxe_json_t *obj, const char *name, nxe_json_t **out)
{
    nxe_json_t *node;
    ngx_int_t rc;

    if (out == NULL) {
        return NGX_ERROR;
    }
    *out = NULL;

    rc = nxe_jwx_claims_lookup(obj, name, &node);
    if (rc != NGX_OK) {
        return rc;
    }

    if (nxe_json_type(node) != NXE_JSON_ARRAY) {
        return NGX_ERROR;
    }

    *out = node;
    return NGX_OK;
}


ngx_int_t
nxe_jwx_claims_get_object(nxe_json_t *obj, const char *name, nxe_json_t **out)
{
    nxe_json_t *node;
    ngx_int_t rc;

    if (out == NULL) {
        return NGX_ERROR;
    }
    *out = NULL;

    rc = nxe_jwx_claims_lookup(obj, name, &node);
    if (rc != NGX_OK) {
        return rc;
    }

    if (nxe_json_type(node) != NXE_JSON_OBJECT) {
        return NGX_ERROR;
    }

    *out = node;
    return NGX_OK;
}
