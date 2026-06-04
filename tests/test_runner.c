/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 *
 * test_runner.c - C unit tests for nxe-jwx
 */

#include <ngx_config.h>
#include <ngx_core.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/objects.h>

#include <nxe_json.h>

#include "nxe_jwx.h"

#include "test_crypto.h"


/* === Mini test framework === */

static int g_failed = 0;
static int g_passed = 0;

#define ASSERT(cond)                                                          \
        do {                                                                      \
            if (!(cond)) {                                                        \
                fprintf(stderr, "  FAIL  %s:%d  %s\n",                            \
                        __FILE__, __LINE__, #cond);                               \
                return -1;                                                        \
            }                                                                     \
        } while (0)

#define ASSERT_EQ_INT(a, b)                                                   \
        do {                                                                      \
            long _a = (long) (a);                                                 \
            long _b = (long) (b);                                                 \
            if (_a != _b) {                                                       \
                fprintf(stderr, "  FAIL  %s:%d  %s == %s (got %ld vs %ld)\n",     \
                        __FILE__, __LINE__, #a, #b, _a, _b);                      \
                return -1;                                                        \
            }                                                                     \
        } while (0)

#define ASSERT_STR_EQ(s, expected)                                            \
        do {                                                                      \
            size_t _l = strlen(expected);                                         \
            if ((s)->len != _l                                                    \
                || memcmp((s)->data, (expected), _l) != 0)                        \
            {                                                                     \
                fprintf(stderr,                                                   \
                        "  FAIL  %s:%d  %s != \"%s\" (got %.*s)\n",                   \
                        __FILE__, __LINE__, #s, (expected),                           \
                        (int) (s)->len, (char *) (s)->data);                          \
                return -1;                                                        \
            }                                                                     \
        } while (0)

#define TEST(name) static int test_ ## name(ngx_pool_t * pool)

#define RUN(name)                                                             \
        do {                                                                      \
            ngx_pool_t *_pool = ngx_create_pool(0, &log);                         \
            int _rc = test_ ## name(_pool);                                         \
            ngx_destroy_pool(_pool);                                              \
            if (_rc == 0) {                                                       \
                g_passed++;                                                       \
                printf("  PASS  %s\n", #name);                                    \
            } else {                                                              \
                g_failed++;                                                       \
            }                                                                     \
        } while (0)


/* === claims helpers === */

TEST(claims_get_string_ok){
    ngx_str_t input = ngx_string("{\"sub\":\"alice\",\"role\":\"admin\"}");
    nxe_json_t *obj = nxe_json_parse(&input, pool);
    ngx_str_t value;

    ASSERT(obj != NULL);

    ASSERT_EQ_INT(nxe_jwx_claims_get_string(obj, "sub", &value), NGX_OK);
    ASSERT_STR_EQ(&value, "alice");

    ASSERT_EQ_INT(nxe_jwx_claims_get_string(obj, "role", &value), NGX_OK);
    ASSERT_STR_EQ(&value, "admin");

    nxe_json_free(obj);
    return 0;
}

TEST(claims_get_string_missing){
    ngx_str_t input = ngx_string("{\"sub\":\"alice\"}");
    nxe_json_t *obj = nxe_json_parse(&input, pool);
    ngx_str_t value;

    ASSERT(obj != NULL);
    ASSERT_EQ_INT(nxe_jwx_claims_get_string(obj, "missing", &value),
                  NGX_DECLINED);

    nxe_json_free(obj);
    return 0;
}

TEST(claims_get_string_wrong_type){
    ngx_str_t input = ngx_string("{\"count\":42}");
    nxe_json_t *obj = nxe_json_parse(&input, pool);
    ngx_str_t value;

    ASSERT(obj != NULL);
    ASSERT_EQ_INT(nxe_jwx_claims_get_string(obj, "count", &value), NGX_ERROR);

    nxe_json_free(obj);
    return 0;
}

TEST(claims_get_string_null_out){
    ngx_str_t input = ngx_string("{\"sub\":\"alice\"}");
    nxe_json_t *obj = nxe_json_parse(&input, pool);

    ASSERT(obj != NULL);
    ASSERT_EQ_INT(nxe_jwx_claims_get_string(obj, "sub", NULL), NGX_ERROR);

    nxe_json_free(obj);
    return 0;
}

TEST(claims_get_integer_ok){
    ngx_str_t input = ngx_string("{\"exp\":1740000000}");
    nxe_json_t *obj = nxe_json_parse(&input, pool);
    int64_t value;

    ASSERT(obj != NULL);
    ASSERT_EQ_INT(nxe_jwx_claims_get_integer(obj, "exp", &value), NGX_OK);
    ASSERT_EQ_INT(value, 1740000000);

    nxe_json_free(obj);
    return 0;
}

TEST(claims_get_integer_missing){
    ngx_str_t input = ngx_string("{\"exp\":1}");
    nxe_json_t *obj = nxe_json_parse(&input, pool);
    int64_t value;

    ASSERT(obj != NULL);
    ASSERT_EQ_INT(nxe_jwx_claims_get_integer(obj, "missing", &value),
                  NGX_DECLINED);

    nxe_json_free(obj);
    return 0;
}

TEST(claims_get_integer_wrong_type){
    ngx_str_t input = ngx_string("{\"exp\":\"not-an-int\"}");
    nxe_json_t *obj = nxe_json_parse(&input, pool);
    int64_t value;

    ASSERT(obj != NULL);
    ASSERT_EQ_INT(nxe_jwx_claims_get_integer(obj, "exp", &value), NGX_ERROR);

    nxe_json_free(obj);
    return 0;
}

TEST(claims_get_integer_null_out){
    ngx_str_t input = ngx_string("{\"exp\":1}");
    nxe_json_t *obj = nxe_json_parse(&input, pool);

    ASSERT(obj != NULL);
    ASSERT_EQ_INT(nxe_jwx_claims_get_integer(obj, "exp", NULL), NGX_ERROR);

    nxe_json_free(obj);
    return 0;
}

TEST(claims_get_boolean_ok){
    ngx_str_t input = ngx_string("{\"verified\":true}");
    nxe_json_t *obj = nxe_json_parse(&input, pool);
    ngx_flag_t value;

    ASSERT(obj != NULL);
    ASSERT_EQ_INT(nxe_jwx_claims_get_boolean(obj, "verified", &value), NGX_OK);
    ASSERT_EQ_INT(value, 1);

    nxe_json_free(obj);
    return 0;
}

TEST(claims_get_boolean_missing){
    ngx_str_t input = ngx_string("{\"verified\":true}");
    nxe_json_t *obj = nxe_json_parse(&input, pool);
    ngx_flag_t value;

    ASSERT(obj != NULL);
    ASSERT_EQ_INT(nxe_jwx_claims_get_boolean(obj, "missing", &value),
                  NGX_DECLINED);

    nxe_json_free(obj);
    return 0;
}

TEST(claims_get_boolean_wrong_type){
    ngx_str_t input = ngx_string("{\"verified\":1}");
    nxe_json_t *obj = nxe_json_parse(&input, pool);
    ngx_flag_t value;

    ASSERT(obj != NULL);
    ASSERT_EQ_INT(nxe_jwx_claims_get_boolean(obj, "verified", &value),
                  NGX_ERROR);

    nxe_json_free(obj);
    return 0;
}

TEST(claims_get_boolean_null_out){
    ngx_str_t input = ngx_string("{\"verified\":true}");
    nxe_json_t *obj = nxe_json_parse(&input, pool);

    ASSERT(obj != NULL);
    ASSERT_EQ_INT(nxe_jwx_claims_get_boolean(obj, "verified", NULL),
                  NGX_ERROR);

    nxe_json_free(obj);
    return 0;
}

TEST(claims_get_array_ok){
    ngx_str_t input = ngx_string("{\"groups\":[\"a\",\"b\"]}");
    nxe_json_t *obj = nxe_json_parse(&input, pool);
    nxe_json_t *arr;

    ASSERT(obj != NULL);
    ASSERT_EQ_INT(nxe_jwx_claims_get_array(obj, "groups", &arr), NGX_OK);
    ASSERT(arr != NULL);
    ASSERT_EQ_INT(nxe_json_array_size(arr), 2);

    nxe_json_free(obj);
    return 0;
}

TEST(claims_get_array_missing){
    ngx_str_t input = ngx_string("{\"groups\":[]}");
    nxe_json_t *obj = nxe_json_parse(&input, pool);
    nxe_json_t *arr;

    ASSERT(obj != NULL);
    ASSERT_EQ_INT(nxe_jwx_claims_get_array(obj, "missing", &arr),
                  NGX_DECLINED);

    nxe_json_free(obj);
    return 0;
}

TEST(claims_get_array_wrong_type){
    ngx_str_t input = ngx_string("{\"groups\":\"not-an-array\"}");
    nxe_json_t *obj = nxe_json_parse(&input, pool);
    nxe_json_t *arr;

    ASSERT(obj != NULL);
    ASSERT_EQ_INT(nxe_jwx_claims_get_array(obj, "groups", &arr), NGX_ERROR);

    nxe_json_free(obj);
    return 0;
}

TEST(claims_get_array_null_out){
    ngx_str_t input = ngx_string("{\"groups\":[]}");
    nxe_json_t *obj = nxe_json_parse(&input, pool);

    ASSERT(obj != NULL);
    ASSERT_EQ_INT(nxe_jwx_claims_get_array(obj, "groups", NULL), NGX_ERROR);

    nxe_json_free(obj);
    return 0;
}

TEST(claims_get_object_ok){
    ngx_str_t input = ngx_string("{\"meta\":{\"v\":1}}");
    nxe_json_t *obj = nxe_json_parse(&input, pool);
    nxe_json_t *meta;

    ASSERT(obj != NULL);
    ASSERT_EQ_INT(nxe_jwx_claims_get_object(obj, "meta", &meta), NGX_OK);
    ASSERT(meta != NULL);
    ASSERT_EQ_INT(nxe_json_type(meta), NXE_JSON_OBJECT);

    nxe_json_free(obj);
    return 0;
}

TEST(claims_get_object_missing){
    ngx_str_t input = ngx_string("{\"meta\":{}}");
    nxe_json_t *obj = nxe_json_parse(&input, pool);
    nxe_json_t *meta;

    ASSERT(obj != NULL);
    ASSERT_EQ_INT(nxe_jwx_claims_get_object(obj, "missing", &meta),
                  NGX_DECLINED);

    nxe_json_free(obj);
    return 0;
}

TEST(claims_get_object_wrong_type){
    ngx_str_t input = ngx_string("{\"meta\":\"oops\"}");
    nxe_json_t *obj = nxe_json_parse(&input, pool);
    nxe_json_t *meta;

    ASSERT(obj != NULL);
    ASSERT_EQ_INT(nxe_jwx_claims_get_object(obj, "meta", &meta), NGX_ERROR);

    nxe_json_free(obj);
    return 0;
}

TEST(claims_get_object_null_out){
    ngx_str_t input = ngx_string("{\"meta\":{}}");
    nxe_json_t *obj = nxe_json_parse(&input, pool);

    ASSERT(obj != NULL);
    ASSERT_EQ_INT(nxe_jwx_claims_get_object(obj, "meta", NULL), NGX_ERROR);

    nxe_json_free(obj);
    return 0;
}

TEST(claims_null_args){
    ngx_str_t value;

    ASSERT_EQ_INT(nxe_jwx_claims_get_string(NULL, "x", &value), NGX_ERROR);
    return 0;
}


/* === JWT decode === */

/*
 * The fixtures below were generated as:
 *   header  = {"alg":"RS256","kid":"k1"}
 *   payload = {"sub":"alice","exp":1740000000}
 *   sig     = arbitrary 4 bytes ("AAAA" -> 0x00 0x00 0x00)
 */
#define FIXTURE_TOKEN_OK                                                      \
        "eyJhbGciOiJSUzI1NiIsImtpZCI6ImsxIn0."                                    \
        "eyJzdWIiOiJhbGljZSIsImV4cCI6MTc0MDAwMDAwMH0."                            \
        "AAAA"


TEST(decode_ok){
    ngx_str_t token = ngx_string(FIXTURE_TOKEN_OK);
    nxe_jwx_token_t *t;
    const ngx_str_t *s;
    nxe_json_t *header, *payload;
    ngx_str_t sub;
    int64_t exp;

    t = nxe_jwx_decode(&token, pool);
    ASSERT(t != NULL);

    s = nxe_jwx_token_alg(t);
    ASSERT(s != NULL);
    ASSERT_STR_EQ(s, "RS256");
    /* data is NUL-terminated (inherited from nxe_json_string contract) */
    ASSERT(s->data[s->len] == '\0');

    s = nxe_jwx_token_kid(t);
    ASSERT(s != NULL);
    ASSERT_STR_EQ(s, "k1");
    ASSERT(s->data[s->len] == '\0');

    header = nxe_jwx_token_header(t);
    ASSERT(header != NULL);
    ASSERT_EQ_INT(nxe_json_type(header), NXE_JSON_OBJECT);

    payload = nxe_jwx_token_payload(t);
    ASSERT(payload != NULL);

    ASSERT_EQ_INT(nxe_jwx_claims_get_string(payload, "sub", &sub), NGX_OK);
    ASSERT_STR_EQ(&sub, "alice");

    ASSERT_EQ_INT(nxe_jwx_claims_get_integer(payload, "exp", &exp), NGX_OK);
    ASSERT_EQ_INT(exp, 1740000000);

    return 0;
}

TEST(decode_too_few_segments){
    ngx_str_t token = ngx_string("aaa.bbb");
    ASSERT(nxe_jwx_decode(&token, pool) == NULL);
    return 0;
}

TEST(decode_too_many_segments){
    ngx_str_t token = ngx_string("aaa.bbb.ccc.ddd");
    ASSERT(nxe_jwx_decode(&token, pool) == NULL);
    return 0;
}

TEST(decode_empty_segment){
    /* Empty header or payload is still rejected; only the signature
     * segment is allowed to be zero-length (covered separately). */
    ngx_str_t token = ngx_string("aaa..ccc");
    ASSERT(nxe_jwx_decode(&token, pool) == NULL);
    return 0;
}

TEST(decode_empty_signature_accepted){
    /* alg=none / unsigned tokens carry an empty signature segment.
     * The decoder accepts them so callers that only consume claims
     * (e.g. trusted-upstream propagation) can still extract the
     * payload; verification will reject the same token via
     * jws_empty_signature_rejected below. */
    ngx_str_t token = ngx_string(
        "eyJhbGciOiJub25lIn0."
        "eyJzdWIiOiJhbGljZSJ9.");
    nxe_jwx_token_t *t;
    nxe_json_t *payload;
    ngx_str_t sub;

    t = nxe_jwx_decode(&token, pool);
    ASSERT(t != NULL);

    payload = nxe_jwx_token_payload(t);
    ASSERT(payload != NULL);
    ASSERT_EQ_INT(nxe_jwx_claims_get_string(payload, "sub", &sub), NGX_OK);
    ASSERT_STR_EQ(&sub, "alice");
    return 0;
}

TEST(decode_invalid_base64){
    /* '@' is not in the base64url alphabet. */
    ngx_str_t token = ngx_string("@@@.bbb.ccc");
    ASSERT(nxe_jwx_decode(&token, pool) == NULL);
    return 0;
}

TEST(decode_header_not_object){
    /* base64url("\"hello\"") is "ImhlbGxvIg" */
    ngx_str_t token = ngx_string(
        "ImhlbGxvIg."
        "eyJzdWIiOiJhbGljZSJ9."
        "AAAA");
    ASSERT(nxe_jwx_decode(&token, pool) == NULL);
    return 0;
}

TEST(decode_token_too_large){
    /* 16 KiB + 1 of 'a' followed by ".b.c" -- exceeds JWT cap. */
    size_t big = NXE_JWX_MAX_JWT_SIZE + 4;
    u_char *buf = ngx_palloc(pool, big);
    ngx_str_t token;

    ASSERT(buf != NULL);
    memset(buf, 'a', big - 4);
    buf[big - 4] = '.';
    buf[big - 3] = 'b';
    buf[big - 2] = '.';
    buf[big - 1] = 'c';
    token.data = buf;
    token.len = big;

    ASSERT(nxe_jwx_decode(&token, pool) == NULL);
    return 0;
}

TEST(decode_null_pool){
    ngx_str_t token = ngx_string(FIXTURE_TOKEN_OK);
    (void) pool;
    ASSERT(nxe_jwx_decode(&token, NULL) == NULL);
    return 0;
}

TEST(decode_null_token){
    ASSERT(nxe_jwx_decode(NULL, pool) == NULL);
    return 0;
}

TEST(decode_empty_token){
    ngx_str_t token = ngx_null_string;
    ASSERT(nxe_jwx_decode(&token, pool) == NULL);
    return 0;
}

TEST(decode_token_alg_kid_null_args){
    ASSERT(nxe_jwx_token_alg(NULL) == NULL);
    ASSERT(nxe_jwx_token_kid(NULL) == NULL);
    ASSERT(nxe_jwx_token_header(NULL) == NULL);
    ASSERT(nxe_jwx_token_payload(NULL) == NULL);
    return 0;
}

TEST(decode_no_alg_no_kid){
    /* Header without alg/kid is structurally valid -- the verifier is
     * the layer that rejects it. */
    ngx_str_t token = ngx_string(
        "e30."                                          /* "{}" */
        "eyJzdWIiOiJhbGljZSJ9."                          /* {"sub":"alice"} */
        "AAAA");
    nxe_jwx_token_t *t;

    t = nxe_jwx_decode(&token, pool);
    ASSERT(t != NULL);
    ASSERT(nxe_jwx_token_alg(t) == NULL);
    ASSERT(nxe_jwx_token_kid(t) == NULL);
    return 0;
}

TEST(decode_alg_not_string){
    /* Header {"alg":42}; alg is non-string -> alg accessor returns NULL */
    ngx_str_t token = ngx_string(
        "eyJhbGciOjQyfQ."                                /* {"alg":42}     */
        "eyJzdWIiOiJhbGljZSJ9."
        "AAAA");
    nxe_jwx_token_t *t;

    t = nxe_jwx_decode(&token, pool);
    ASSERT(t != NULL);
    ASSERT(nxe_jwx_token_alg(t) == NULL);
    return 0;
}

TEST(decode_invalid_b64_payload){
    /* header is valid b64url; payload contains '@' -> decode fails. */
    ngx_str_t token = ngx_string(
        "eyJhbGciOiJSUzI1NiJ9."
        "@@@."
        "AAAA");
    ASSERT(nxe_jwx_decode(&token, pool) == NULL);
    return 0;
}

TEST(decode_invalid_b64_signature){
    ngx_str_t token = ngx_string(
        "eyJhbGciOiJSUzI1NiJ9."
        "eyJzdWIiOiJhbGljZSJ9."
        "@@@");
    ASSERT(nxe_jwx_decode(&token, pool) == NULL);
    return 0;
}

TEST(decode_payload_not_object){
    /* payload "hello" -- not a JSON object */
    ngx_str_t token = ngx_string(
        "eyJhbGciOiJSUzI1NiJ9."
        "ImhlbGxvIg."
        "AAAA");
    ASSERT(nxe_jwx_decode(&token, pool) == NULL);
    return 0;
}

TEST(decode_payload_invalid_json){
    /* payload "{not-json" */
    ngx_str_t token = ngx_string(
        "eyJhbGciOiJSUzI1NiJ9."
        "e25vdC1qc29u."
        "AAAA");
    ASSERT(nxe_jwx_decode(&token, pool) == NULL);
    return 0;
}

TEST(decode_header_too_large){
    /*
     * Header segment > NXE_JWX_MAX_JWT_HEADER but token under
     * NXE_JWX_MAX_JWT_SIZE so the per-segment cap fires first.
     */
    size_t header_len = NXE_JWX_MAX_JWT_HEADER + 16;
    size_t total = header_len + 1 + 4 + 1 + 4;
    u_char *buf = ngx_palloc(pool, total);
    ngx_str_t token;

    ASSERT(buf != NULL);
    memset(buf, 'a', header_len);
    buf[header_len] = '.';
    memcpy(buf + header_len + 1, "Yg==", 4);    /* "b" */
    buf[header_len + 5] = '.';
    memcpy(buf + header_len + 6, "Yg==", 4);
    token.data = buf;
    token.len = total;

    ASSERT(nxe_jwx_decode(&token, pool) == NULL);
    return 0;
}


/* === JWKS (negative paths that don't need real keys) === */

TEST(jwks_root_not_object){
    ngx_str_t input = ngx_string("[]");
    ASSERT(nxe_jwx_jwks_parse(&input, pool) == NULL);
    return 0;
}

TEST(jwks_missing_keys_array){
    ngx_str_t input = ngx_string("{\"foo\":1}");
    ASSERT(nxe_jwx_jwks_parse(&input, pool) == NULL);
    return 0;
}

TEST(jwks_empty_keys_array){
    ngx_str_t input = ngx_string("{\"keys\":[]}");
    ASSERT(nxe_jwx_jwks_parse(&input, pool) == NULL);
    return 0;
}

TEST(jwks_unsupported_kty_only){
    ngx_str_t input = ngx_string("{\"keys\":[{\"kty\":\"WTF\"}]}");
    ASSERT(nxe_jwx_jwks_parse(&input, pool) == NULL);
    return 0;
}

TEST(jwks_size_too_large){
    size_t big = NXE_JWX_MAX_JWKS_SIZE + 16;
    u_char *buf = ngx_palloc(pool, big);
    ngx_str_t input;

    ASSERT(buf != NULL);
    memset(buf, 'x', big);
    input.data = buf;
    input.len = big;

    ASSERT(nxe_jwx_jwks_parse(&input, pool) == NULL);
    return 0;
}

TEST(jwks_null_args){
    ngx_str_t empty = ngx_null_string;
    ngx_str_t any = ngx_string("{\"keys\":[]}");

    ASSERT(nxe_jwx_jwks_parse(NULL, pool) == NULL);
    ASSERT(nxe_jwx_jwks_parse(&any, NULL) == NULL);
    ASSERT(nxe_jwx_jwks_parse(&empty, pool) == NULL);
    ASSERT_EQ_INT(nxe_jwx_jwks_count(NULL), 0);
    return 0;
}

TEST(jwks_invalid_json){
    ngx_str_t input = ngx_string("{not-json");
    ASSERT(nxe_jwx_jwks_parse(&input, pool) == NULL);
    return 0;
}

TEST(jwks_missing_kty){
    ngx_str_t input = ngx_string("{\"keys\":[{\"alg\":\"RS256\"}]}");
    ASSERT(nxe_jwx_jwks_parse(&input, pool) == NULL);
    return 0;
}

TEST(jwks_keys_entry_not_object){
    /* keys[0] is a number, not an object -> skipped, then zero usable */
    ngx_str_t input = ngx_string("{\"keys\":[42]}");
    ASSERT(nxe_jwx_jwks_parse(&input, pool) == NULL);
    return 0;
}

TEST(jwks_too_many_keys){
    /*
     * Generate a {"keys":[{"kty":"WTF"}, ...]} with more than
     * NXE_JWX_MAX_JWKS_KEYS placeholder entries.  The size cap is
     * not exceeded; the count cap fires.
     */
    size_t cap = NXE_JWX_MAX_JWKS_KEYS + 1;
    size_t per = sizeof("{\"kty\":\"WTF\"}") - 1;
    size_t total = sizeof("{\"keys\":[]}") - 1 + cap * per + cap;
    u_char *buf = ngx_palloc(pool, total);
    u_char *p;
    ngx_str_t input;
    size_t i;

    ASSERT(buf != NULL);
    p = buf;
    memcpy(p, "{\"keys\":[", 9); p += 9;
    for (i = 0; i < cap; i++) {
        memcpy(p, "{\"kty\":\"WTF\"}", per); p += per;
        if (i + 1 < cap) {
            *p++ = ',';
        }
    }
    memcpy(p, "]}", 2); p += 2;
    input.data = buf;
    input.len = (size_t) (p - buf);

    ASSERT(nxe_jwx_jwks_parse(&input, pool) == NULL);
    return 0;
}


/* === JWKS / JWS round-trip with real keys === */

TEST(jwks_rsa_ok){
    EVP_PKEY *pkey;
    ngx_str_t jwk, doc;
    nxe_jwx_jwks_t *jwks;

    pkey = test_gen_rsa(2048);
    ASSERT(pkey != NULL);
    jwk = test_jwk_rsa(pkey, "rk", "RS256", pool);
    ASSERT(jwk.len > 0);
    doc = test_jwks_build(&jwk, 1, pool);
    ASSERT(doc.len > 0);

    jwks = nxe_jwx_jwks_parse(&doc, pool);
    ASSERT(jwks != NULL);
    ASSERT_EQ_INT(nxe_jwx_jwks_count(jwks), 1);

    EVP_PKEY_free(pkey);
    return 0;
}

TEST(jwks_free_explicit){
    /*
     * Explicit release must free the OpenSSL key material immediately
     * and disarm the pool cleanup handler so the per-test pool teardown
     * (run by the harness on return) does not double-free.  ASan /
     * Valgrind enforce the no-double-free contract here.  A redundant
     * second nxe_jwx_jwks_free must be a harmless no-op.
     */
    EVP_PKEY *pkey;
    ngx_str_t jwk, doc;
    nxe_jwx_jwks_t *jwks;

    pkey = test_gen_rsa(2048);
    ASSERT(pkey != NULL);
    jwk = test_jwk_rsa(pkey, "rk", "RS256", pool);
    ASSERT(jwk.len > 0);
    doc = test_jwks_build(&jwk, 1, pool);
    ASSERT(doc.len > 0);

    jwks = nxe_jwx_jwks_parse(&doc, pool);
    ASSERT(jwks != NULL);
    ASSERT_EQ_INT(nxe_jwx_jwks_count(jwks), 1);

    nxe_jwx_jwks_free(jwks);
    nxe_jwx_jwks_free(jwks);

    EVP_PKEY_free(pkey);
    return 0;
}

TEST(jwks_free_null){
    /* Documented NULL no-op. */
    nxe_jwx_jwks_free(NULL);
    return 0;
}

TEST(jwks_rsa_modulus_too_small){
    /*
     * Synthesize an RSA JWK whose modulus has BN_num_bits == 1024,
     * below NXE_JWX_MIN_RSA_BITS (2048).  A 128-byte modulus with its
     * most-significant bit set yields exactly 1024 bits.  Hand-crafting
     * the JWK (mirroring jwks_rsa_modulus_too_large) avoids generating a
     * real sub-2048-bit RSA key at test time, which static analyzers
     * flag as insufficient key size, while still exercising the same
     * BN_num_bits rejection path in nxe_jwx_jwks_parse.
     */
    size_t n_len = 1024 / 8;
    u_char *n_buf;
    static const u_char e_bytes[] = { 0x01, 0x00, 0x01 };
    ngx_str_t n_b64, e_b64;
    u_char *p;
    static const char head[] = "{\"keys\":[{\"kty\":\"RSA\",\"n\":\"";
    static const char mid[] = "\",\"e\":\"";
    static const char tail[] = "\"}]}";
    ngx_str_t doc;

    n_buf = ngx_pcalloc(pool, n_len);
    ASSERT(n_buf != NULL);
    n_buf[0] = 0x80;
    n_b64 = test_b64url(n_buf, n_len, pool);
    ASSERT(n_b64.len > 0);
    e_b64 = test_b64url(e_bytes, sizeof(e_bytes), pool);
    ASSERT(e_b64.len > 0);

    doc.len = sizeof(head) - 1 + n_b64.len + sizeof(mid) - 1
              + e_b64.len + sizeof(tail) - 1;
    doc.data = ngx_pnalloc(pool, doc.len);
    ASSERT(doc.data != NULL);
    p = doc.data;
    memcpy(p, head, sizeof(head) - 1); p += sizeof(head) - 1;
    memcpy(p, n_b64.data, n_b64.len); p += n_b64.len;
    memcpy(p, mid, sizeof(mid) - 1); p += sizeof(mid) - 1;
    memcpy(p, e_b64.data, e_b64.len); p += e_b64.len;
    memcpy(p, tail, sizeof(tail) - 1);

    /* Modulus below NXE_JWX_MIN_RSA_BITS -> rejected. */
    ASSERT(nxe_jwx_jwks_parse(&doc, pool) == NULL);
    return 0;
}

TEST(jwks_rsa_modulus_too_large){
    /*
     * Synthesize an RSA JWK whose modulus has BN_num_bits ==
     * NXE_JWX_MAX_RSA_BITS + 1.  Generating a real RSA key of that
     * size at test time would be prohibitively slow, so we hand-craft
     * the JWK with a synthetic n value of 0x01 followed by zero bytes
     * and the standard 65537 public exponent.
     */
    size_t n_len = (NXE_JWX_MAX_RSA_BITS / 8) + 1;
    u_char *n_buf;
    static const u_char e_bytes[] = { 0x01, 0x00, 0x01 };
    ngx_str_t n_b64, e_b64;
    u_char *p;
    static const char head[] = "{\"keys\":[{\"kty\":\"RSA\",\"n\":\"";
    static const char mid[] = "\",\"e\":\"";
    static const char tail[] = "\"}]}";
    ngx_str_t doc;

    n_buf = ngx_pcalloc(pool, n_len);
    ASSERT(n_buf != NULL);
    n_buf[0] = 0x01;
    n_b64 = test_b64url(n_buf, n_len, pool);
    ASSERT(n_b64.len > 0);
    e_b64 = test_b64url(e_bytes, sizeof(e_bytes), pool);
    ASSERT(e_b64.len > 0);

    doc.len = sizeof(head) - 1 + n_b64.len + sizeof(mid) - 1
              + e_b64.len + sizeof(tail) - 1;
    doc.data = ngx_pnalloc(pool, doc.len);
    ASSERT(doc.data != NULL);
    p = doc.data;
    memcpy(p, head, sizeof(head) - 1); p += sizeof(head) - 1;
    memcpy(p, n_b64.data, n_b64.len); p += n_b64.len;
    memcpy(p, mid, sizeof(mid) - 1); p += sizeof(mid) - 1;
    memcpy(p, e_b64.data, e_b64.len); p += e_b64.len;
    memcpy(p, tail, sizeof(tail) - 1);

    /* Modulus exceeds NXE_JWX_MAX_RSA_BITS -> rejected. */
    ASSERT(nxe_jwx_jwks_parse(&doc, pool) == NULL);
    return 0;
}

TEST(jwks_rsa_missing_n){
    ngx_str_t input = ngx_string(
        "{\"keys\":[{\"kty\":\"RSA\",\"e\":\"AQAB\"}]}");
    ASSERT(nxe_jwx_jwks_parse(&input, pool) == NULL);
    return 0;
}

TEST(jwks_rsa_missing_e){
    ngx_str_t input = ngx_string(
        "{\"keys\":[{\"kty\":\"RSA\",\"n\":\"AQAB\"}]}");
    ASSERT(nxe_jwx_jwks_parse(&input, pool) == NULL);
    return 0;
}

TEST(jwks_ec_p256_ok){
    EVP_PKEY *pkey;
    ngx_str_t jwk, doc;
    nxe_jwx_jwks_t *jwks;

    pkey = test_gen_ec(NID_X9_62_prime256v1);
    ASSERT(pkey != NULL);
    jwk = test_jwk_ec(pkey, "P-256", 32, "ec1", "ES256", pool);
    ASSERT(jwk.len > 0);
    doc = test_jwks_build(&jwk, 1, pool);

    jwks = nxe_jwx_jwks_parse(&doc, pool);
    ASSERT(jwks != NULL);
    ASSERT_EQ_INT(nxe_jwx_jwks_count(jwks), 1);

    EVP_PKEY_free(pkey);
    return 0;
}

TEST(jwks_ec_p384_ok){
    EVP_PKEY *pkey;
    ngx_str_t jwk, doc;
    nxe_jwx_jwks_t *jwks;

    pkey = test_gen_ec(NID_secp384r1);
    ASSERT(pkey != NULL);
    jwk = test_jwk_ec(pkey, "P-384", 48, NULL, NULL, pool);
    ASSERT(jwk.len > 0);
    doc = test_jwks_build(&jwk, 1, pool);

    jwks = nxe_jwx_jwks_parse(&doc, pool);
    ASSERT(jwks != NULL);
    ASSERT_EQ_INT(nxe_jwx_jwks_count(jwks), 1);

    EVP_PKEY_free(pkey);
    return 0;
}

TEST(jwks_ec_p521_ok){
    EVP_PKEY *pkey;
    ngx_str_t jwk, doc;
    nxe_jwx_jwks_t *jwks;

    pkey = test_gen_ec(NID_secp521r1);
    ASSERT(pkey != NULL);
    jwk = test_jwk_ec(pkey, "P-521", 66, NULL, NULL, pool);
    ASSERT(jwk.len > 0);
    doc = test_jwks_build(&jwk, 1, pool);

    jwks = nxe_jwx_jwks_parse(&doc, pool);
    ASSERT(jwks != NULL);
    ASSERT_EQ_INT(nxe_jwx_jwks_count(jwks), 1);

    EVP_PKEY_free(pkey);
    return 0;
}

TEST(jwks_ec_secp256k1_ok){
    EVP_PKEY *pkey;
    ngx_str_t jwk, doc;
    nxe_jwx_jwks_t *jwks;

    pkey = test_gen_ec(NID_secp256k1);
    ASSERT(pkey != NULL);
    jwk = test_jwk_ec(pkey, "secp256k1", 32, NULL, NULL, pool);
    ASSERT(jwk.len > 0);
    doc = test_jwks_build(&jwk, 1, pool);

    jwks = nxe_jwx_jwks_parse(&doc, pool);
    ASSERT(jwks != NULL);
    ASSERT_EQ_INT(nxe_jwx_jwks_count(jwks), 1);

    EVP_PKEY_free(pkey);
    return 0;
}

TEST(jwks_ec_unsupported_crv){
    /*
     * Build a properly-shaped EC jwk but advertise an unknown
     * crv name -> skipped key -> zero usable -> NULL.
     */
    ngx_str_t input = ngx_string(
        "{\"keys\":[{\"kty\":\"EC\",\"crv\":\"P-999\","
        "\"x\":\"AAAA\",\"y\":\"AAAA\"}]}");
    ASSERT(nxe_jwx_jwks_parse(&input, pool) == NULL);
    return 0;
}

TEST(jwks_ec_missing_crv){
    ngx_str_t input = ngx_string(
        "{\"keys\":[{\"kty\":\"EC\","
        "\"x\":\"AAAA\",\"y\":\"AAAA\"}]}");
    ASSERT(nxe_jwx_jwks_parse(&input, pool) == NULL);
    return 0;
}

TEST(jwks_ec_wrong_coord_len){
    /* P-256 needs 32-byte x/y; supplying short bytes -> declined. */
    ngx_str_t input = ngx_string(
        "{\"keys\":[{\"kty\":\"EC\",\"crv\":\"P-256\","
        "\"x\":\"AAAA\",\"y\":\"AAAA\"}]}");
    ASSERT(nxe_jwx_jwks_parse(&input, pool) == NULL);
    return 0;
}

TEST(jwks_ec_missing_y){
    /* P-256 needs both x and y. */
    EVP_PKEY *pkey;
    ngx_str_t empty = ngx_string(
        "{\"keys\":[{\"kty\":\"EC\",\"crv\":\"P-256\","
        "\"x\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"}]}");
    pkey = NULL;
    (void) pkey;
    ASSERT(nxe_jwx_jwks_parse(&empty, pool) == NULL);
    return 0;
}

TEST(jwks_okp_ed25519_ok){
    EVP_PKEY *pkey;
    ngx_str_t jwk, doc;
    nxe_jwx_jwks_t *jwks;

    pkey = test_gen_ed25519();
    ASSERT(pkey != NULL);
    jwk = test_jwk_okp(pkey, "Ed25519", 32, "okp1", "EdDSA", pool);
    ASSERT(jwk.len > 0);
    doc = test_jwks_build(&jwk, 1, pool);

    jwks = nxe_jwx_jwks_parse(&doc, pool);
    ASSERT(jwks != NULL);
    ASSERT_EQ_INT(nxe_jwx_jwks_count(jwks), 1);

    EVP_PKEY_free(pkey);
    return 0;
}

TEST(jwks_okp_unsupported_crv){
    ngx_str_t input = ngx_string(
        "{\"keys\":[{\"kty\":\"OKP\",\"crv\":\"X25519\","
        "\"x\":\"AAAA\"}]}");
    ASSERT(nxe_jwx_jwks_parse(&input, pool) == NULL);
    return 0;
}

TEST(jwks_okp_missing_crv){
    ngx_str_t input = ngx_string(
        "{\"keys\":[{\"kty\":\"OKP\",\"x\":\"AAAA\"}]}");
    ASSERT(nxe_jwx_jwks_parse(&input, pool) == NULL);
    return 0;
}

TEST(jwks_okp_wrong_x_len){
    ngx_str_t input = ngx_string(
        "{\"keys\":[{\"kty\":\"OKP\",\"crv\":\"Ed25519\","
        "\"x\":\"AAAA\"}]}");
    ASSERT(nxe_jwx_jwks_parse(&input, pool) == NULL);
    return 0;
}

TEST(jwks_oct_ok){
    static const u_char secret[] = "0123456789abcdef0123456789abcdef";
    ngx_str_t jwk, doc;
    nxe_jwx_jwks_t *jwks;

    jwk = test_jwk_oct(secret, sizeof(secret) - 1, "h1", "HS256", pool);
    ASSERT(jwk.len > 0);
    doc = test_jwks_build(&jwk, 1, pool);

    jwks = nxe_jwx_jwks_parse(&doc, pool);
    ASSERT(jwks != NULL);
    ASSERT_EQ_INT(nxe_jwx_jwks_count(jwks), 1);
    return 0;
}

TEST(jwks_oct_missing_k){
    ngx_str_t input = ngx_string("{\"keys\":[{\"kty\":\"oct\"}]}");
    ASSERT(nxe_jwx_jwks_parse(&input, pool) == NULL);
    return 0;
}

/*
 * Corrupt base64 in a JWK field must propagate as a hard error
 * (NGX_ERROR), rejecting the entire JWKS document.  A "missing field"
 * skip would let a valid sibling JWK survive, so these tests pair a
 * well-formed key with a corrupt one and assert the whole parse fails.
 */
TEST(jwks_rsa_corrupt_base64_n){
    EVP_PKEY *ec;
    ngx_str_t parts[2];
    ngx_str_t doc;

    ec = test_gen_ec(NID_X9_62_prime256v1);
    ASSERT(ec != NULL);
    parts[0] = test_jwk_ec(ec, "P-256", 32, "good", "ES256", pool);
    ngx_str_set(&parts[1],
                "{\"kty\":\"RSA\",\"kid\":\"bad\","
                "\"n\":\"AA@AA\",\"e\":\"AQAB\"}");
    doc = test_jwks_build(parts, 2, pool);

    ASSERT(nxe_jwx_jwks_parse(&doc, pool) == NULL);

    EVP_PKEY_free(ec);
    return 0;
}

TEST(jwks_rsa_corrupt_base64_e){
    EVP_PKEY *ec;
    ngx_str_t parts[2];
    ngx_str_t doc;

    ec = test_gen_ec(NID_X9_62_prime256v1);
    ASSERT(ec != NULL);
    parts[0] = test_jwk_ec(ec, "P-256", 32, "good", "ES256", pool);
    ngx_str_set(&parts[1],
                "{\"kty\":\"RSA\",\"kid\":\"bad\","
                "\"n\":\"AQAB\",\"e\":\"AA@AA\"}");
    doc = test_jwks_build(parts, 2, pool);

    ASSERT(nxe_jwx_jwks_parse(&doc, pool) == NULL);

    EVP_PKEY_free(ec);
    return 0;
}

TEST(jwks_ec_corrupt_base64_x){
    EVP_PKEY *rsa;
    ngx_str_t parts[2];
    ngx_str_t doc;

    rsa = test_gen_rsa(2048);
    ASSERT(rsa != NULL);
    parts[0] = test_jwk_rsa(rsa, "good", "RS256", pool);
    ngx_str_set(&parts[1],
                "{\"kty\":\"EC\",\"crv\":\"P-256\",\"kid\":\"bad\","
                "\"x\":\"AA@AA\",\"y\":\"AAAA\"}");
    doc = test_jwks_build(parts, 2, pool);

    ASSERT(nxe_jwx_jwks_parse(&doc, pool) == NULL);

    EVP_PKEY_free(rsa);
    return 0;
}

TEST(jwks_okp_corrupt_base64_x){
    EVP_PKEY *rsa;
    ngx_str_t parts[2];
    ngx_str_t doc;

    rsa = test_gen_rsa(2048);
    ASSERT(rsa != NULL);
    parts[0] = test_jwk_rsa(rsa, "good", "RS256", pool);
    ngx_str_set(&parts[1],
                "{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"kid\":\"bad\","
                "\"x\":\"AA@AA\"}");
    doc = test_jwks_build(parts, 2, pool);

    ASSERT(nxe_jwx_jwks_parse(&doc, pool) == NULL);

    EVP_PKEY_free(rsa);
    return 0;
}

#if (NXE_JWX_HAVE_HMAC)
TEST(jwks_oct_corrupt_base64_k){
    EVP_PKEY *rsa;
    ngx_str_t parts[2];
    ngx_str_t doc;

    rsa = test_gen_rsa(2048);
    ASSERT(rsa != NULL);
    parts[0] = test_jwk_rsa(rsa, "good", "RS256", pool);
    ngx_str_set(&parts[1],
                "{\"kty\":\"oct\",\"kid\":\"bad\","
                "\"k\":\"AA@AA\"}");
    doc = test_jwks_build(parts, 2, pool);

    ASSERT(nxe_jwx_jwks_parse(&doc, pool) == NULL);

    EVP_PKEY_free(rsa);
    return 0;
}
#endif

TEST(jwks_multi_keys){
    /* RSA + EC + OKP + oct in a single doc. */
    EVP_PKEY *rsa, *ec, *okp;
    ngx_str_t parts[4];
    ngx_str_t doc;
    nxe_jwx_jwks_t *jwks;
    static const u_char secret[] = "0123456789abcdef0123456789abcdef";

    rsa = test_gen_rsa(2048); ASSERT(rsa != NULL);
    ec = test_gen_ec(NID_X9_62_prime256v1); ASSERT(ec != NULL);
    okp = test_gen_ed25519(); ASSERT(okp != NULL);

    parts[0] = test_jwk_rsa(rsa, "r", "RS256", pool);
    parts[1] = test_jwk_ec(ec, "P-256", 32, "e", "ES256", pool);
    parts[2] = test_jwk_okp(okp, "Ed25519", 32, "o", "EdDSA", pool);
    parts[3] = test_jwk_oct(secret, sizeof(secret) - 1, "h", "HS256", pool);
    doc = test_jwks_build(parts, 4, pool);

    jwks = nxe_jwx_jwks_parse(&doc, pool);
    ASSERT(jwks != NULL);
    ASSERT_EQ_INT(nxe_jwx_jwks_count(jwks), 4);

    EVP_PKEY_free(rsa);
    EVP_PKEY_free(ec);
    EVP_PKEY_free(okp);
    return 0;
}

TEST(jwks_empty_kid_skipped){
    /*
     * A standard JWKS document mixing one well-formed JWK with an
     * explicit empty-kid JWK should yield only the well-formed kid;
     * the empty-kid entry is rejected with a warning so it cannot
     * become a silent kid-less fallback candidate at verification
     * time, mirroring the keyval-side guard.
     */
    EVP_PKEY *pkey;
    ngx_str_t parts[2], doc;
    nxe_jwx_jwks_t *jwks;
    ngx_str_t alpha = ngx_string("alpha");

    pkey = test_gen_rsa(2048);
    ASSERT(pkey != NULL);
    parts[0] = test_jwk_rsa(pkey, "alpha", "RS256", pool);
    parts[1] = test_jwk_rsa(pkey, "", "RS256", pool);
    ASSERT(parts[0].len > 0);
    ASSERT(parts[1].len > 0);
    doc = test_jwks_build(parts, 2, pool);
    ASSERT(doc.len > 0);

    jwks = nxe_jwx_jwks_parse(&doc, pool);
    ASSERT(jwks != NULL);
    ASSERT_EQ_INT(nxe_jwx_jwks_count(jwks), 1);
    ASSERT_EQ_INT(nxe_jwx_jwks_has_kid(jwks, &alpha), 1);

    EVP_PKEY_free(pkey);
    return 0;
}

TEST(jwks_empty_kid_only_rejected){
    /* Sole JWK entry has "kid":"" -> zero usable keys -> NULL. */
    EVP_PKEY *pkey;
    ngx_str_t jwk, doc;

    pkey = test_gen_rsa(2048);
    ASSERT(pkey != NULL);
    jwk = test_jwk_rsa(pkey, "", "RS256", pool);
    ASSERT(jwk.len > 0);
    doc = test_jwks_build(&jwk, 1, pool);
    ASSERT(doc.len > 0);

    ASSERT(nxe_jwx_jwks_parse(&doc, pool) == NULL);

    EVP_PKEY_free(pkey);
    return 0;
}

TEST(jwks_kid_field_absent_ok){
    /*
     * Regression: a JWK that omits the "kid" field entirely (RFC 7517
     * leaves it optional) must still be accepted as a kid-less key.
     * The empty-kid rejection applies only when the field is present
     * with an empty string, not when it is absent.
     */
    EVP_PKEY *pkey;
    ngx_str_t jwk, doc;
    nxe_jwx_jwks_t *jwks;

    pkey = test_gen_rsa(2048);
    ASSERT(pkey != NULL);
    jwk = test_jwk_rsa(pkey, NULL, "RS256", pool);
    ASSERT(jwk.len > 0);
    doc = test_jwks_build(&jwk, 1, pool);
    ASSERT(doc.len > 0);

    jwks = nxe_jwx_jwks_parse(&doc, pool);
    ASSERT(jwks != NULL);
    ASSERT_EQ_INT(nxe_jwx_jwks_count(jwks), 1);

    EVP_PKEY_free(pkey);
    return 0;
}


/* === JWKS keyval === */

TEST(jwks_keyval_pem_ok){
    EVP_PKEY *pkey;
    ngx_str_t pem, doc;
    nxe_jwx_jwks_t *jwks;
    static const char prefix[] = "{\"k\":\"";
    static const char suffix[] = "\"}";
    u_char *p;
    size_t i;

    pkey = test_gen_rsa(2048);
    ASSERT(pkey != NULL);
    pem = test_pem_pubkey(pkey, pool);
    ASSERT(pem.len > 0);

    /* Wrap PEM in a JSON string with newlines escaped as \n. */
    {
        size_t escaped = 0;
        for (i = 0; i < pem.len; i++) {
            escaped += (pem.data[i] == '\n') ? 2 : 1;
        }
        doc.len = sizeof(prefix) - 1 + escaped + sizeof(suffix) - 1;
        doc.data = ngx_pnalloc(pool, doc.len);
        ASSERT(doc.data != NULL);

        p = doc.data;
        memcpy(p, prefix, sizeof(prefix) - 1); p += sizeof(prefix) - 1;
        for (i = 0; i < pem.len; i++) {
            if (pem.data[i] == '\n') {
                *p++ = '\\'; *p++ = 'n';
            } else {
                *p++ = pem.data[i];
            }
        }
        memcpy(p, suffix, sizeof(suffix) - 1);
    }

    jwks = nxe_jwx_jwks_parse_keyval(&doc, pool);
    ASSERT(jwks != NULL);
    ASSERT_EQ_INT(nxe_jwx_jwks_count(jwks), 1);

    EVP_PKEY_free(pkey);
    return 0;
}

/*
 * Wrap a PEM blob into the {"k":"<pem>"} keyval JSON shape, escaping
 * embedded newlines as "\\n" so the JSON parser sees a single line.
 */
static ngx_str_t
make_keyval_doc(const ngx_str_t *pem, ngx_pool_t *pool)
{
    static const char prefix[] = "{\"k\":\"";
    static const char suffix[] = "\"}";
    ngx_str_t doc;
    u_char *p;
    size_t i, escaped;

    doc.data = NULL;
    doc.len = 0;

    escaped = 0;
    for (i = 0; i < pem->len; i++) {
        escaped += (pem->data[i] == '\n') ? 2 : 1;
    }
    doc.len = sizeof(prefix) - 1 + escaped + sizeof(suffix) - 1;
    doc.data = ngx_pnalloc(pool, doc.len);
    if (doc.data == NULL) {
        return doc;
    }

    p = doc.data;
    memcpy(p, prefix, sizeof(prefix) - 1); p += sizeof(prefix) - 1;
    for (i = 0; i < pem->len; i++) {
        if (pem->data[i] == '\n') {
            *p++ = '\\'; *p++ = 'n';
        } else {
            *p++ = pem->data[i];
        }
    }
    memcpy(p, suffix, sizeof(suffix) - 1);
    return doc;
}


/*
 * Sign an ES256 JWT with `pkey`, then verify it through a keyval-loaded
 * JWKS that holds the same key as a PEM SubjectPublicKeyInfo.  This
 * locks in the kty-from-pkey detection in the keyval path: if
 * jwks_parse_keyval mis-typed the EC key as RSA the verifier would
 * reject it before ever attempting EVP_DigestVerify.
 */
TEST(jwks_keyval_ec_pem_verifies){
    EVP_PKEY *pkey;
    ngx_str_t pem, doc, signing, jwt;
    nxe_jwx_jwks_t *jwks;
    nxe_jwx_token_t *t;
    u_char *sig;
    size_t sig_len;

    pkey = test_gen_ec(NID_X9_62_prime256v1);
    ASSERT(pkey != NULL);
    pem = test_pem_pubkey(pkey, pool);
    ASSERT(pem.len > 0);

    doc = make_keyval_doc(&pem, pool);
    ASSERT(doc.data != NULL);

    jwks = nxe_jwx_jwks_parse_keyval(&doc, pool);
    ASSERT(jwks != NULL);
    ASSERT_EQ_INT(nxe_jwx_jwks_count(jwks), 1);

    signing = test_signing_input(
        "{\"alg\":\"ES256\"}",
        "{\"sub\":\"alice\"}", pool);
    ASSERT_EQ_INT(test_sign(pkey, "SHA256", 0, 32,
                            signing.data, signing.len,
                            &sig, &sig_len, pool), NGX_OK);
    jwt = test_jwt_build("{\"alg\":\"ES256\"}",
                         "{\"sub\":\"alice\"}",
                         sig, sig_len, pool);
    t = nxe_jwx_decode(&jwt, pool);
    ASSERT(t != NULL);
    ASSERT_EQ_INT(nxe_jwx_jws_verify(t, jwks, pool), NGX_OK);

    EVP_PKEY_free(pkey);
    return 0;
}


TEST(jwks_keyval_empty_object){
    ngx_str_t doc = ngx_string("{}");
    ASSERT(nxe_jwx_jwks_parse_keyval(&doc, pool) == NULL);
    return 0;
}


TEST(jwks_keyval_empty_kid_skipped){
    /*
     * A keyval document with an "" kid alongside a real kid should
     * surface only the real kid; the empty-kid entry is dropped with
     * a warning so it does not silently become a kid-less fallback
     * candidate at verification time.
     */
    EVP_PKEY *pkey;
    ngx_str_t pem, doc;
    nxe_jwx_jwks_t *jwks;
    ngx_str_t alpha = ngx_string("alpha");
    static const char head[] = "{\"\":\"";
    static const char mid[] = "\",\"alpha\":\"";
    static const char tail[] = "\"}";
    u_char *p;
    size_t escaped = 0, i;

    pkey = test_gen_rsa(2048);
    ASSERT(pkey != NULL);
    pem = test_pem_pubkey(pkey, pool);
    ASSERT(pem.len > 0);

    for (i = 0; i < pem.len; i++) escaped += (pem.data[i] == '\n') ? 2 : 1;
    doc.len = sizeof(head) - 1 + escaped + sizeof(mid) - 1
              + escaped + sizeof(tail) - 1;
    doc.data = ngx_pnalloc(pool, doc.len);
    ASSERT(doc.data != NULL);

    p = doc.data;
    memcpy(p, head, sizeof(head) - 1); p += sizeof(head) - 1;
    for (i = 0; i < pem.len; i++) {
        if (pem.data[i] == '\n') {
            *p++ = '\\'; *p++ = 'n';
        } else {
            *p++ = pem.data[i];
        }
    }
    memcpy(p, mid, sizeof(mid) - 1); p += sizeof(mid) - 1;
    for (i = 0; i < pem.len; i++) {
        if (pem.data[i] == '\n') {
            *p++ = '\\'; *p++ = 'n';
        } else {
            *p++ = pem.data[i];
        }
    }
    memcpy(p, tail, sizeof(tail) - 1);

    jwks = nxe_jwx_jwks_parse_keyval(&doc, pool);
    ASSERT(jwks != NULL);
    ASSERT_EQ_INT(nxe_jwx_jwks_count(jwks), 1);
    ASSERT_EQ_INT(nxe_jwx_jwks_has_kid(jwks, &alpha), 1);

    EVP_PKEY_free(pkey);
    return 0;
}


TEST(jwks_keyval_empty_kid_only_rejected){
    /* All entries are empty-kid -> zero usable keys -> NULL. */
    EVP_PKEY *pkey;
    ngx_str_t pem, doc;
    static const char head[] = "{\"\":\"";
    static const char tail[] = "\"}";
    u_char *p;
    size_t escaped = 0, i;

    pkey = test_gen_rsa(2048);
    ASSERT(pkey != NULL);
    pem = test_pem_pubkey(pkey, pool);
    ASSERT(pem.len > 0);

    for (i = 0; i < pem.len; i++) escaped += (pem.data[i] == '\n') ? 2 : 1;
    doc.len = sizeof(head) - 1 + escaped + sizeof(tail) - 1;
    doc.data = ngx_pnalloc(pool, doc.len);
    ASSERT(doc.data != NULL);

    p = doc.data;
    memcpy(p, head, sizeof(head) - 1); p += sizeof(head) - 1;
    for (i = 0; i < pem.len; i++) {
        if (pem.data[i] == '\n') {
            *p++ = '\\'; *p++ = 'n';
        } else {
            *p++ = pem.data[i];
        }
    }
    memcpy(p, tail, sizeof(tail) - 1);

    ASSERT(nxe_jwx_jwks_parse_keyval(&doc, pool) == NULL);
    EVP_PKEY_free(pkey);
    return 0;
}


TEST(jwks_keyval_non_pem_rejected){
    /* keyval only accepts PEM public keys.  A non-PEM string is never
     * interpreted as an HMAC secret -- accepting that would expose the
     * operator's public PEM text as an HMAC key (algorithm confusion). */
    ngx_str_t doc = ngx_string("{\"k\":\"not a pem\"}");
    ASSERT(nxe_jwx_jwks_parse_keyval(&doc, pool) == NULL);
    return 0;
}


TEST(jwks_keyval_pem_looking_corrupt_rejected){
    /* A value that starts with the PEM marker but fails to parse must
     * be rejected, never silently accepted as an HMAC secret.  This is
     * the configuration-time variant of the RSA/EC -> HS*
     * algorithm-confusion attack. */
    ngx_str_t doc = ngx_string(
        "{\"k\":\"-----BEGIN PUBLIC KEY-----\\nGARBAGE\\n"
        "-----END PUBLIC KEY-----\\n\"}");
    ASSERT(nxe_jwx_jwks_parse_keyval(&doc, pool) == NULL);
    return 0;
}


TEST(jwks_keyval_multi_kid_hmac_rejected){
    /* Multiple non-PEM values: every entry is skipped, so the document
     * has zero usable keys and parse_keyval returns NULL.  Mirrors the
     * pre-fix "multi-kid hmac" fixture to guard against regression. */
    ngx_str_t doc = ngx_string(
        "{\"k1\":\"alpha-secret\",\"k2\":\"beta-secret\"}");
    ASSERT(nxe_jwx_jwks_parse_keyval(&doc, pool) == NULL);
    return 0;
}


TEST(jwks_keyval_multi_kid_pem){
    /* Two PEM RSA public keys on different kids. */
    EVP_PKEY *p1, *p2;
    ngx_str_t pem1, pem2, doc;
    nxe_jwx_jwks_t *jwks;
    static const char head[] = "{\"alpha\":\"";
    static const char mid[] = "\",\"beta\":\"";
    static const char tail[] = "\"}";
    u_char *p;
    size_t e1 = 0, e2 = 0, i;

    p1 = test_gen_rsa(2048);
    ASSERT(p1 != NULL);
    p2 = test_gen_rsa(2048);
    ASSERT(p2 != NULL);
    pem1 = test_pem_pubkey(p1, pool);
    pem2 = test_pem_pubkey(p2, pool);
    ASSERT(pem1.len > 0);
    ASSERT(pem2.len > 0);

    for (i = 0; i < pem1.len; i++) e1 += (pem1.data[i] == '\n') ? 2 : 1;
    for (i = 0; i < pem2.len; i++) e2 += (pem2.data[i] == '\n') ? 2 : 1;
    doc.len = sizeof(head) - 1 + e1 + sizeof(mid) - 1 + e2
              + sizeof(tail) - 1;
    doc.data = ngx_pnalloc(pool, doc.len);
    ASSERT(doc.data != NULL);

    p = doc.data;
    memcpy(p, head, sizeof(head) - 1); p += sizeof(head) - 1;
    for (i = 0; i < pem1.len; i++) {
        if (pem1.data[i] == '\n') {
            *p++ = '\\'; *p++ = 'n';
        } else {
            *p++ = pem1.data[i];
        }
    }
    memcpy(p, mid, sizeof(mid) - 1); p += sizeof(mid) - 1;
    for (i = 0; i < pem2.len; i++) {
        if (pem2.data[i] == '\n') {
            *p++ = '\\'; *p++ = 'n';
        } else {
            *p++ = pem2.data[i];
        }
    }
    memcpy(p, tail, sizeof(tail) - 1);

    jwks = nxe_jwx_jwks_parse_keyval(&doc, pool);
    ASSERT(jwks != NULL);
    ASSERT_EQ_INT(nxe_jwx_jwks_count(jwks), 2);

    EVP_PKEY_free(p1);
    EVP_PKEY_free(p2);
    return 0;
}

TEST(jwks_keyval_root_not_object){
    ngx_str_t doc = ngx_string("\"hello\"");
    ASSERT(nxe_jwx_jwks_parse_keyval(&doc, pool) == NULL);
    return 0;
}

TEST(jwks_keyval_invalid_json){
    ngx_str_t doc = ngx_string("{");
    ASSERT(nxe_jwx_jwks_parse_keyval(&doc, pool) == NULL);
    return 0;
}

TEST(jwks_keyval_null_args){
    ngx_str_t empty = ngx_null_string;
    ngx_str_t doc = ngx_string("{}");

    ASSERT(nxe_jwx_jwks_parse_keyval(NULL, pool) == NULL);
    ASSERT(nxe_jwx_jwks_parse_keyval(&doc, NULL) == NULL);
    ASSERT(nxe_jwx_jwks_parse_keyval(&empty, pool) == NULL);
    return 0;
}

TEST(jwks_keyval_too_large){
    size_t big = NXE_JWX_MAX_JWKS_SIZE + 8;
    u_char *buf = ngx_palloc(pool, big);
    ngx_str_t doc;

    ASSERT(buf != NULL);
    memset(buf, 'x', big);
    doc.data = buf;
    doc.len = big;

    ASSERT(nxe_jwx_jwks_parse_keyval(&doc, pool) == NULL);
    return 0;
}


/* === JWS verification round-trips === */

typedef struct {
    EVP_PKEY   *pkey;
    const char *jwk_alg;
    const char *digest;
    int         pss;
    size_t      ec_coord_len;
    const char *crv;
    size_t      okp_key_len;
} jws_signer_t;


static ngx_int_t
make_signed_token(ngx_str_t *jwt_out, const char *header, const char *payload,
    EVP_PKEY *pkey, const char *digest, int pss, size_t ec_coord_len,
    ngx_pool_t *pool)
{
    ngx_str_t signing;
    u_char *sig;
    size_t sig_len;

    signing = test_signing_input(header, payload, pool);
    if (signing.len == 0) {
        return NGX_ERROR;
    }
    if (test_sign(pkey, digest, pss, ec_coord_len,
                  signing.data, signing.len, &sig, &sig_len, pool) != NGX_OK)
    {
        return NGX_ERROR;
    }
    *jwt_out = test_jwt_build(header, payload, sig, sig_len, pool);
    return jwt_out->len > 0 ? NGX_OK : NGX_ERROR;
}


static int
verify_with_alg(ngx_pool_t *pool, EVP_PKEY *pkey, const char *jwk_kind,
    const char *jwk_crv, size_t jwk_coord, const char *jwk_alg,
    const char *header_alg, const char *digest, int pss, size_t ec_coord_len)
{
    ngx_str_t jwk, doc, jwt;
    nxe_jwx_jwks_t *jwks;
    nxe_jwx_token_t *t;
    char header[128];
    int n;

    if (strcmp(jwk_kind, "RSA") == 0) {
        jwk = test_jwk_rsa(pkey, "k1", jwk_alg, pool);
    } else if (strcmp(jwk_kind, "EC") == 0) {
        jwk = test_jwk_ec(pkey, jwk_crv, jwk_coord, "k1", jwk_alg, pool);
    } else if (strcmp(jwk_kind, "OKP") == 0) {
        jwk = test_jwk_okp(pkey, jwk_crv, jwk_coord, "k1", jwk_alg, pool);
    } else {
        return -1;
    }
    if (jwk.len == 0) return -1;
    doc = test_jwks_build(&jwk, 1, pool);
    jwks = nxe_jwx_jwks_parse(&doc, pool);
    if (jwks == NULL) return -1;

    n = snprintf(header, sizeof(header),
                 "{\"alg\":\"%s\",\"kid\":\"k1\"}", header_alg);
    if (n <= 0) return -1;

    if (make_signed_token(&jwt,
                          header,
                          "{\"sub\":\"alice\"}",
                          pkey, digest, pss, ec_coord_len, pool) != NGX_OK)
    {
        return -1;
    }
    t = nxe_jwx_decode(&jwt, pool);
    if (t == NULL) return -1;

    return (int) nxe_jwx_jws_verify(t, jwks, pool);
}


TEST(jws_rs256_roundtrip){
    EVP_PKEY *pkey = test_gen_rsa(2048);
    ASSERT(pkey != NULL);
    ASSERT_EQ_INT(verify_with_alg(pool, pkey, "RSA", NULL, 0, "RS256",
                                  "RS256", "SHA256", 0, 0), NGX_OK);
    EVP_PKEY_free(pkey);
    return 0;
}

TEST(jws_rs384_roundtrip){
    EVP_PKEY *pkey = test_gen_rsa(2048);
    ASSERT(pkey != NULL);
    ASSERT_EQ_INT(verify_with_alg(pool, pkey, "RSA", NULL, 0, "RS384",
                                  "RS384", "SHA384", 0, 0), NGX_OK);
    EVP_PKEY_free(pkey);
    return 0;
}

TEST(jws_rs512_roundtrip){
    EVP_PKEY *pkey = test_gen_rsa(2048);
    ASSERT(pkey != NULL);
    ASSERT_EQ_INT(verify_with_alg(pool, pkey, "RSA", NULL, 0, "RS512",
                                  "RS512", "SHA512", 0, 0), NGX_OK);
    EVP_PKEY_free(pkey);
    return 0;
}

TEST(jws_ps256_roundtrip){
    EVP_PKEY *pkey = test_gen_rsa(2048);
    ASSERT(pkey != NULL);
    ASSERT_EQ_INT(verify_with_alg(pool, pkey, "RSA", NULL, 0, "PS256",
                                  "PS256", "SHA256", 1, 0), NGX_OK);
    EVP_PKEY_free(pkey);
    return 0;
}

TEST(jws_ps384_roundtrip){
    EVP_PKEY *pkey = test_gen_rsa(2048);
    ASSERT(pkey != NULL);
    ASSERT_EQ_INT(verify_with_alg(pool, pkey, "RSA", NULL, 0, "PS384",
                                  "PS384", "SHA384", 1, 0), NGX_OK);
    EVP_PKEY_free(pkey);
    return 0;
}

TEST(jws_ps512_roundtrip){
    EVP_PKEY *pkey = test_gen_rsa(2048);
    ASSERT(pkey != NULL);
    ASSERT_EQ_INT(verify_with_alg(pool, pkey, "RSA", NULL, 0, "PS512",
                                  "PS512", "SHA512", 1, 0), NGX_OK);
    EVP_PKEY_free(pkey);
    return 0;
}

TEST(jws_es256_roundtrip){
    EVP_PKEY *pkey = test_gen_ec(NID_X9_62_prime256v1);
    ASSERT(pkey != NULL);
    ASSERT_EQ_INT(verify_with_alg(pool, pkey, "EC", "P-256", 32, "ES256",
                                  "ES256", "SHA256", 0, 32), NGX_OK);
    EVP_PKEY_free(pkey);
    return 0;
}

TEST(jws_es384_roundtrip){
    EVP_PKEY *pkey = test_gen_ec(NID_secp384r1);
    ASSERT(pkey != NULL);
    ASSERT_EQ_INT(verify_with_alg(pool, pkey, "EC", "P-384", 48, "ES384",
                                  "ES384", "SHA384", 0, 48), NGX_OK);
    EVP_PKEY_free(pkey);
    return 0;
}

TEST(jws_es512_roundtrip){
    EVP_PKEY *pkey = test_gen_ec(NID_secp521r1);
    ASSERT(pkey != NULL);
    ASSERT_EQ_INT(verify_with_alg(pool, pkey, "EC", "P-521", 66, "ES512",
                                  "ES512", "SHA512", 0, 66), NGX_OK);
    EVP_PKEY_free(pkey);
    return 0;
}

TEST(jws_es256k_roundtrip){
    EVP_PKEY *pkey = test_gen_ec(NID_secp256k1);
    ASSERT(pkey != NULL);
    ASSERT_EQ_INT(verify_with_alg(pool, pkey, "EC", "secp256k1", 32, "ES256K",
                                  "ES256K", "SHA256", 0, 32), NGX_OK);
    EVP_PKEY_free(pkey);
    return 0;
}

TEST(jws_eddsa_roundtrip){
    EVP_PKEY *pkey = test_gen_ed25519();
    ASSERT(pkey != NULL);
    ASSERT_EQ_INT(verify_with_alg(pool, pkey, "OKP", "Ed25519", 32, "EdDSA",
                                  "EdDSA", NULL, 0, 0), NGX_OK);
    EVP_PKEY_free(pkey);
    return 0;
}

TEST(jws_hs256_roundtrip){
    static const u_char secret[] = "0123456789abcdef0123456789abcdef";
    ngx_str_t jwk, doc, signing, jwt;
    nxe_jwx_jwks_t *jwks;
    nxe_jwx_token_t *t;
    u_char *sig;
    size_t sig_len;

    jwk = test_jwk_oct(secret, sizeof(secret) - 1, "h1", "HS256", pool);
    ASSERT(jwk.len > 0);
    doc = test_jwks_build(&jwk, 1, pool);
    jwks = nxe_jwx_jwks_parse(&doc, pool);
    ASSERT(jwks != NULL);

    signing = test_signing_input(
        "{\"alg\":\"HS256\",\"kid\":\"h1\"}",
        "{\"sub\":\"alice\"}", pool);
    ASSERT_EQ_INT(test_hmac_sign(secret, sizeof(secret) - 1, "SHA256",
                                 signing.data, signing.len, &sig, &sig_len,
                                 pool), NGX_OK);
    jwt = test_jwt_build("{\"alg\":\"HS256\",\"kid\":\"h1\"}",
                         "{\"sub\":\"alice\"}", sig, sig_len, pool);
    t = nxe_jwx_decode(&jwt, pool);
    ASSERT(t != NULL);
    ASSERT_EQ_INT(nxe_jwx_jws_verify(t, jwks, pool), NGX_OK);
    return 0;
}

TEST(jws_hs384_roundtrip){
    static const u_char secret[] = "0123456789abcdef0123456789abcdef";
    ngx_str_t jwk, doc, signing, jwt;
    nxe_jwx_jwks_t *jwks;
    nxe_jwx_token_t *t;
    u_char *sig;
    size_t sig_len;

    jwk = test_jwk_oct(secret, sizeof(secret) - 1, "h1", "HS384", pool);
    doc = test_jwks_build(&jwk, 1, pool);
    jwks = nxe_jwx_jwks_parse(&doc, pool);
    ASSERT(jwks != NULL);

    signing = test_signing_input(
        "{\"alg\":\"HS384\",\"kid\":\"h1\"}",
        "{\"sub\":\"alice\"}", pool);
    ASSERT_EQ_INT(test_hmac_sign(secret, sizeof(secret) - 1, "SHA384",
                                 signing.data, signing.len, &sig, &sig_len,
                                 pool), NGX_OK);
    jwt = test_jwt_build("{\"alg\":\"HS384\",\"kid\":\"h1\"}",
                         "{\"sub\":\"alice\"}", sig, sig_len, pool);
    t = nxe_jwx_decode(&jwt, pool);
    ASSERT(t != NULL);
    ASSERT_EQ_INT(nxe_jwx_jws_verify(t, jwks, pool), NGX_OK);
    return 0;
}

TEST(jws_hs512_roundtrip){
    static const u_char secret[] = "0123456789abcdef0123456789abcdef";
    ngx_str_t jwk, doc, signing, jwt;
    nxe_jwx_jwks_t *jwks;
    nxe_jwx_token_t *t;
    u_char *sig;
    size_t sig_len;

    jwk = test_jwk_oct(secret, sizeof(secret) - 1, "h1", "HS512", pool);
    doc = test_jwks_build(&jwk, 1, pool);
    jwks = nxe_jwx_jwks_parse(&doc, pool);
    ASSERT(jwks != NULL);

    signing = test_signing_input(
        "{\"alg\":\"HS512\",\"kid\":\"h1\"}",
        "{\"sub\":\"alice\"}", pool);
    ASSERT_EQ_INT(test_hmac_sign(secret, sizeof(secret) - 1, "SHA512",
                                 signing.data, signing.len, &sig, &sig_len,
                                 pool), NGX_OK);
    jwt = test_jwt_build("{\"alg\":\"HS512\",\"kid\":\"h1\"}",
                         "{\"sub\":\"alice\"}", sig, sig_len, pool);
    t = nxe_jwx_decode(&jwt, pool);
    ASSERT(t != NULL);
    ASSERT_EQ_INT(nxe_jwx_jws_verify(t, jwks, pool), NGX_OK);
    return 0;
}


TEST(jws_alg_none_rejected){
    EVP_PKEY *pkey;
    ngx_str_t jwk, doc, jwt;
    nxe_jwx_jwks_t *jwks;
    nxe_jwx_token_t *t;
    static const u_char fake[] = "AAAA";

    pkey = test_gen_rsa(2048);
    ASSERT(pkey != NULL);
    jwk = test_jwk_rsa(pkey, "k1", "RS256", pool);
    doc = test_jwks_build(&jwk, 1, pool);
    jwks = nxe_jwx_jwks_parse(&doc, pool);
    ASSERT(jwks != NULL);

    jwt = test_jwt_build("{\"alg\":\"none\",\"kid\":\"k1\"}",
                         "{\"sub\":\"alice\"}",
                         fake, sizeof(fake) - 1, pool);
    t = nxe_jwx_decode(&jwt, pool);
    ASSERT(t != NULL);
    ASSERT_EQ_INT(nxe_jwx_jws_verify(t, jwks, pool), NGX_DECLINED);

    EVP_PKEY_free(pkey);
    return 0;
}

TEST(jws_alg_unknown_rejected){
    EVP_PKEY *pkey;
    ngx_str_t jwk, doc, jwt;
    nxe_jwx_jwks_t *jwks;
    nxe_jwx_token_t *t;
    static const u_char fake[] = "AAAA";

    pkey = test_gen_rsa(2048);
    jwk = test_jwk_rsa(pkey, "k1", NULL, pool);
    doc = test_jwks_build(&jwk, 1, pool);
    jwks = nxe_jwx_jwks_parse(&doc, pool);
    ASSERT(jwks != NULL);

    jwt = test_jwt_build("{\"alg\":\"WAT123\",\"kid\":\"k1\"}",
                         "{\"sub\":\"alice\"}",
                         fake, sizeof(fake) - 1, pool);
    t = nxe_jwx_decode(&jwt, pool);
    ASSERT(t != NULL);
    ASSERT_EQ_INT(nxe_jwx_jws_verify(t, jwks, pool), NGX_DECLINED);

    EVP_PKEY_free(pkey);
    return 0;
}

TEST(jws_empty_signature_rejected){
    /* Pairs with decode_empty_signature_accepted: a token whose
     * signature segment is empty (alg=none with empty third segment)
     * decodes successfully but jws_verify must reject it before any
     * key is consulted. */
    EVP_PKEY *pkey;
    ngx_str_t jwk, doc, token;
    nxe_jwx_jwks_t *jwks;
    nxe_jwx_token_t *t;

    pkey = test_gen_rsa(2048);
    jwk = test_jwk_rsa(pkey, "k1", "RS256", pool);
    doc = test_jwks_build(&jwk, 1, pool);
    jwks = nxe_jwx_jwks_parse(&doc, pool);
    ASSERT(jwks != NULL);

    /* alg=RS256 + empty signature (note trailing dot, no third segment). */
    token.data = (u_char *) "eyJhbGciOiJSUzI1NiIsImtpZCI6ImsxIn0."
                 "eyJzdWIiOiJhbGljZSJ9.";
    token.len = ngx_strlen(token.data);

    t = nxe_jwx_decode(&token, pool);
    ASSERT(t != NULL);
    ASSERT_EQ_INT(nxe_jwx_jws_verify(t, jwks, pool), NGX_DECLINED);

    EVP_PKEY_free(pkey);
    return 0;
}


TEST(jws_no_alg_rejected){
    EVP_PKEY *pkey;
    ngx_str_t jwk, doc, jwt;
    nxe_jwx_jwks_t *jwks;
    nxe_jwx_token_t *t;
    static const u_char fake[] = "AAAA";

    pkey = test_gen_rsa(2048);
    jwk = test_jwk_rsa(pkey, "k1", NULL, pool);
    doc = test_jwks_build(&jwk, 1, pool);
    jwks = nxe_jwx_jwks_parse(&doc, pool);
    ASSERT(jwks != NULL);

    jwt = test_jwt_build("{\"kid\":\"k1\"}",
                         "{\"sub\":\"alice\"}",
                         fake, sizeof(fake) - 1, pool);
    t = nxe_jwx_decode(&jwt, pool);
    ASSERT(t != NULL);
    ASSERT_EQ_INT(nxe_jwx_jws_verify(t, jwks, pool), NGX_DECLINED);

    EVP_PKEY_free(pkey);
    return 0;
}

TEST(jws_signature_tampered){
    EVP_PKEY *pkey;
    ngx_str_t signing, jwk, doc, jwt;
    nxe_jwx_jwks_t *jwks;
    nxe_jwx_token_t *t;
    u_char *sig;
    size_t sig_len;

    pkey = test_gen_rsa(2048); ASSERT(pkey != NULL);
    jwk = test_jwk_rsa(pkey, "k1", "RS256", pool);
    doc = test_jwks_build(&jwk, 1, pool);
    jwks = nxe_jwx_jwks_parse(&doc, pool);
    ASSERT(jwks != NULL);

    signing = test_signing_input(
        "{\"alg\":\"RS256\",\"kid\":\"k1\"}",
        "{\"sub\":\"alice\"}", pool);
    ASSERT_EQ_INT(test_sign(pkey, "SHA256", 0, 0,
                            signing.data, signing.len,
                            &sig, &sig_len, pool), NGX_OK);
    sig[0] ^= 0xff;     /* flip a byte to invalidate the signature */

    jwt = test_jwt_build("{\"alg\":\"RS256\",\"kid\":\"k1\"}",
                         "{\"sub\":\"alice\"}",
                         sig, sig_len, pool);
    t = nxe_jwx_decode(&jwt, pool);
    ASSERT(t != NULL);
    ASSERT_EQ_INT(nxe_jwx_jws_verify(t, jwks, pool), NGX_DECLINED);

    EVP_PKEY_free(pkey);
    return 0;
}

TEST(jws_kid_no_match_falls_back){
    /*
     * kid-strict policy: when no key in the JWKS carries the token's
     * kid at all, the verifier falls back to trying every compatible
     * key.  Two keys here -- kid="other" and kid-less -- neither one
     * matches the token's kid="ghost", so pass 2 runs and the
     * kid-less key validates the signature.
     */
    EVP_PKEY *pkey;
    ngx_str_t parts[2], doc, signing, jwt;
    nxe_jwx_jwks_t *jwks;
    nxe_jwx_token_t *t;
    u_char *sig;
    size_t sig_len;

    pkey = test_gen_rsa(2048); ASSERT(pkey != NULL);
    parts[0] = test_jwk_rsa(pkey, "other", "RS256", pool);
    parts[1] = test_jwk_rsa(pkey, NULL,    "RS256", pool);
    doc = test_jwks_build(parts, 2, pool);
    jwks = nxe_jwx_jwks_parse(&doc, pool);
    ASSERT(jwks != NULL);

    signing = test_signing_input(
        "{\"alg\":\"RS256\",\"kid\":\"ghost\"}",
        "{\"sub\":\"alice\"}", pool);
    ASSERT_EQ_INT(test_sign(pkey, "SHA256", 0, 0,
                            signing.data, signing.len,
                            &sig, &sig_len, pool), NGX_OK);
    jwt = test_jwt_build("{\"alg\":\"RS256\",\"kid\":\"ghost\"}",
                         "{\"sub\":\"alice\"}", sig, sig_len, pool);
    t = nxe_jwx_decode(&jwt, pool);
    ASSERT(t != NULL);
    ASSERT_EQ_INT(nxe_jwx_jws_verify(t, jwks, pool), NGX_OK);

    EVP_PKEY_free(pkey);
    return 0;
}

TEST(jwks_has_kid_basic){
    /* Helper that lets callers tell "kid present but signature failed"
     * apart from "kid not in keyset" when nxe_jwx_jws_verify returns
     * NGX_DECLINED.  Required by nginx-auth-jwt's audit-log message
     * that names the kid only when it was actually attempted. */
    EVP_PKEY *p1, *p2;
    ngx_str_t parts[2], doc;
    nxe_jwx_jwks_t *jwks;
    ngx_str_t k_yes = ngx_string("present");
    ngx_str_t k_no = ngx_string("absent");
    ngx_str_t k_empty = ngx_null_string;

    p1 = test_gen_rsa(2048); ASSERT(p1 != NULL);
    p2 = test_gen_rsa(2048); ASSERT(p2 != NULL);
    parts[0] = test_jwk_rsa(p1, "present", "RS256", pool);
    parts[1] = test_jwk_rsa(p2, NULL,      "RS256", pool);
    doc = test_jwks_build(parts, 2, pool);
    jwks = nxe_jwx_jwks_parse(&doc, pool);
    ASSERT(jwks != NULL);

    ASSERT_EQ_INT(nxe_jwx_jwks_has_kid(jwks, &k_yes), 1);
    ASSERT_EQ_INT(nxe_jwx_jwks_has_kid(jwks, &k_no),  0);
    ASSERT_EQ_INT(nxe_jwx_jwks_has_kid(jwks, &k_empty), 0);
    ASSERT_EQ_INT(nxe_jwx_jwks_has_kid(NULL,  &k_yes),  0);
    ASSERT_EQ_INT(nxe_jwx_jwks_has_kid(jwks, NULL), 0);

    EVP_PKEY_free(p1);
    EVP_PKEY_free(p2);
    return 0;
}


TEST(jws_kid_mismatch_with_other_kid_only_rejected){
    /*
     * Tighter kid-strict: when the token names a kid and the JWKS
     * contains other kid-labelled keys but NO kid-less key, the
     * verifier must refuse rather than fall through to the
     * other-kid keys.  This blocks key-confusion attacks where a
     * caller asserts kid="prod" but the JWKS just happens to
     * contain another kid that successfully validates the
     * signature.
     */
    EVP_PKEY *pkey;
    ngx_str_t jwk, doc, signing, jwt;
    nxe_jwx_jwks_t *jwks;
    nxe_jwx_token_t *t;
    u_char *sig;
    size_t sig_len;

    pkey = test_gen_rsa(2048); ASSERT(pkey != NULL);
    jwk = test_jwk_rsa(pkey, "wrong-kid", "RS256", pool);
    doc = test_jwks_build(&jwk, 1, pool);
    jwks = nxe_jwx_jwks_parse(&doc, pool);
    ASSERT(jwks != NULL);

    signing = test_signing_input(
        "{\"alg\":\"RS256\",\"kid\":\"requested-kid\"}",
        "{\"sub\":\"alice\"}", pool);
    ASSERT_EQ_INT(test_sign(pkey, "SHA256", 0, 0,
                            signing.data, signing.len,
                            &sig, &sig_len, pool), NGX_OK);
    jwt = test_jwt_build("{\"alg\":\"RS256\",\"kid\":\"requested-kid\"}",
                         "{\"sub\":\"alice\"}", sig, sig_len, pool);
    t = nxe_jwx_decode(&jwt, pool);
    ASSERT(t != NULL);
    ASSERT_EQ_INT(nxe_jwx_jws_verify(t, jwks, pool), NGX_DECLINED);

    EVP_PKEY_free(pkey);
    return 0;
}


TEST(jws_alg_pinned_in_jwk){
    /*
     * JWK declares alg=RS384 but the token claims alg=RS256.  Both
     * are RSA and the underlying RSA key can sign either size; the
     * JWK's pinned alg must still cause the verifier to skip it.
     */
    EVP_PKEY *pkey;
    ngx_str_t jwk, doc, signing, jwt;
    nxe_jwx_jwks_t *jwks;
    nxe_jwx_token_t *t;
    u_char *sig;
    size_t sig_len;

    pkey = test_gen_rsa(2048); ASSERT(pkey != NULL);
    jwk = test_jwk_rsa(pkey, "k1", "RS384", pool);
    doc = test_jwks_build(&jwk, 1, pool);
    jwks = nxe_jwx_jwks_parse(&doc, pool);
    ASSERT(jwks != NULL);

    signing = test_signing_input(
        "{\"alg\":\"RS256\",\"kid\":\"k1\"}",
        "{\"sub\":\"alice\"}", pool);
    ASSERT_EQ_INT(test_sign(pkey, "SHA256", 0, 0,
                            signing.data, signing.len,
                            &sig, &sig_len, pool), NGX_OK);
    jwt = test_jwt_build("{\"alg\":\"RS256\",\"kid\":\"k1\"}",
                         "{\"sub\":\"alice\"}", sig, sig_len, pool);
    t = nxe_jwx_decode(&jwt, pool);
    ASSERT(t != NULL);
    ASSERT_EQ_INT(nxe_jwx_jws_verify(t, jwks, pool), NGX_DECLINED);

    EVP_PKEY_free(pkey);
    return 0;
}


TEST(jwks_use_enc_skipped){
    /*
     * JWK with use="enc" must not be picked up for signature
     * verification.  Here the document has only one key (an RSA
     * encryption key), so the parse must reject the document
     * outright (zero usable signing keys).  The trick used to
     * inject the "use" field is to take the JWK literal produced
     * by test_jwk_rsa() and splice "use":"enc" in after the kty
     * field; doing it this way avoids re-implementing n/e
     * extraction in test code.
     */
    EVP_PKEY *pkey;
    ngx_str_t jwk, jwk_enc, doc;
    static const char marker[] = "{\"kty\":\"RSA\"";
    static const char inject[] = "{\"kty\":\"RSA\",\"use\":\"enc\"";
    u_char *p;

    pkey = test_gen_rsa(2048); ASSERT(pkey != NULL);
    jwk = test_jwk_rsa(pkey, "k1", "RS256", pool);
    ASSERT(jwk.len > 0);
    /* test_jwk_rsa always emits the kty field first, so the marker
     * sits at offset 0. */
    ASSERT(jwk.len >= sizeof(marker) - 1);
    ASSERT(ngx_strncmp(jwk.data, marker, sizeof(marker) - 1) == 0);

    jwk_enc.len = jwk.len + (sizeof(inject) - sizeof(marker));
    jwk_enc.data = ngx_pnalloc(pool, jwk_enc.len);
    ASSERT(jwk_enc.data != NULL);
    p = jwk_enc.data;
    ngx_memcpy(p, inject, sizeof(inject) - 1);
    p += sizeof(inject) - 1;
    ngx_memcpy(p, jwk.data + sizeof(marker) - 1,
               jwk.len - (sizeof(marker) - 1));

    doc = test_jwks_build(&jwk_enc, 1, pool);
    ASSERT(doc.len > 0);

    ASSERT(nxe_jwx_jwks_parse(&doc, pool) == NULL);

    EVP_PKEY_free(pkey);
    return 0;
}


TEST(jws_kid_match_pins_to_that_key){
    /*
     * kid-strict policy: when the kid matches a key but its signature
     * fails (here the token is signed with rsa_b but kid="a" maps to
     * rsa_a), the verifier MUST NOT fall back to other compatible
     * keys -- doing so would let an attacker who knows any key in
     * the keyset forge tokens for any kid.  The kid-less rsa_b key
     * could verify the signature on its own merits, but pass 1 has
     * already pinned us to kid="a".
     */
    EVP_PKEY *rsa_a, *rsa_b;
    ngx_str_t parts[2], doc, signing, jwt;
    nxe_jwx_jwks_t *jwks;
    nxe_jwx_token_t *t;
    u_char *sig;
    size_t sig_len;

    rsa_a = test_gen_rsa(2048); ASSERT(rsa_a != NULL);
    rsa_b = test_gen_rsa(2048); ASSERT(rsa_b != NULL);

    parts[0] = test_jwk_rsa(rsa_a, "a", "RS256", pool);
    parts[1] = test_jwk_rsa(rsa_b, NULL, "RS256", pool);
    doc = test_jwks_build(parts, 2, pool);
    jwks = nxe_jwx_jwks_parse(&doc, pool);
    ASSERT(jwks != NULL);

    signing = test_signing_input(
        "{\"alg\":\"RS256\",\"kid\":\"a\"}",
        "{\"sub\":\"alice\"}", pool);
    ASSERT_EQ_INT(test_sign(rsa_b, "SHA256", 0, 0,
                            signing.data, signing.len,
                            &sig, &sig_len, pool), NGX_OK);
    jwt = test_jwt_build("{\"alg\":\"RS256\",\"kid\":\"a\"}",
                         "{\"sub\":\"alice\"}", sig, sig_len, pool);
    t = nxe_jwx_decode(&jwt, pool);
    ASSERT(t != NULL);
    ASSERT_EQ_INT(nxe_jwx_jws_verify(t, jwks, pool), NGX_DECLINED);

    EVP_PKEY_free(rsa_a);
    EVP_PKEY_free(rsa_b);
    return 0;
}

TEST(jws_kty_mismatch){
    /*
     * Token signed with RSA key, but JWKS contains only EC key.
     * Verification must fail (NGX_DECLINED, not NGX_OK).
     */
    EVP_PKEY *rsa, *ec;
    ngx_str_t jwk, doc, signing, jwt;
    nxe_jwx_jwks_t *jwks;
    nxe_jwx_token_t *t;
    u_char *sig;
    size_t sig_len;

    rsa = test_gen_rsa(2048); ASSERT(rsa != NULL);
    ec = test_gen_ec(NID_X9_62_prime256v1); ASSERT(ec != NULL);

    jwk = test_jwk_ec(ec, "P-256", 32, "k1", "ES256", pool);
    doc = test_jwks_build(&jwk, 1, pool);
    jwks = nxe_jwx_jwks_parse(&doc, pool);
    ASSERT(jwks != NULL);

    signing = test_signing_input(
        "{\"alg\":\"RS256\",\"kid\":\"k1\"}",
        "{\"sub\":\"alice\"}", pool);
    ASSERT_EQ_INT(test_sign(rsa, "SHA256", 0, 0,
                            signing.data, signing.len,
                            &sig, &sig_len, pool), NGX_OK);
    jwt = test_jwt_build("{\"alg\":\"RS256\",\"kid\":\"k1\"}",
                         "{\"sub\":\"alice\"}", sig, sig_len, pool);
    t = nxe_jwx_decode(&jwt, pool);
    ASSERT(t != NULL);
    ASSERT_EQ_INT(nxe_jwx_jws_verify(t, jwks, pool), NGX_DECLINED);

    EVP_PKEY_free(rsa);
    EVP_PKEY_free(ec);
    return 0;
}

TEST(jws_ec_curve_mismatch){
    /*
     * JWKS has only a P-384 key; token advertises ES256 (which
     * requires a P-256 key).  No signature attempt should succeed
     * (incompatible curve), so verify must return NGX_DECLINED.
     * The signature bytes can be arbitrary 64 bytes since the curve
     * filter rejects the key before any verification is attempted.
     */
    EVP_PKEY *p384;
    ngx_str_t jwk, doc, jwt;
    nxe_jwx_jwks_t *jwks;
    nxe_jwx_token_t *t;
    u_char fake_sig[64];

    p384 = test_gen_ec(NID_secp384r1); ASSERT(p384 != NULL);
    jwk = test_jwk_ec(p384, "P-384", 48, "k1", "ES384", pool);
    doc = test_jwks_build(&jwk, 1, pool);
    jwks = nxe_jwx_jwks_parse(&doc, pool);
    ASSERT(jwks != NULL);

    memset(fake_sig, 0xAB, sizeof(fake_sig));
    jwt = test_jwt_build("{\"alg\":\"ES256\",\"kid\":\"k1\"}",
                         "{\"sub\":\"alice\"}",
                         fake_sig, sizeof(fake_sig), pool);
    t = nxe_jwx_decode(&jwt, pool);
    ASSERT(t != NULL);
    ASSERT_EQ_INT(nxe_jwx_jws_verify(t, jwks, pool), NGX_DECLINED);

    EVP_PKEY_free(p384);
    return 0;
}

TEST(jws_es256_bad_sig_length){
    /*
     * ES256 verification rejects an R||S signature whose length is
     * not exactly 64 bytes.
     */
    EVP_PKEY *pkey;
    ngx_str_t jwk, doc, jwt;
    nxe_jwx_jwks_t *jwks;
    nxe_jwx_token_t *t;
    u_char short_sig[10] = {0};

    pkey = test_gen_ec(NID_X9_62_prime256v1); ASSERT(pkey != NULL);
    jwk = test_jwk_ec(pkey, "P-256", 32, "k1", "ES256", pool);
    doc = test_jwks_build(&jwk, 1, pool);
    jwks = nxe_jwx_jwks_parse(&doc, pool);
    ASSERT(jwks != NULL);

    jwt = test_jwt_build("{\"alg\":\"ES256\",\"kid\":\"k1\"}",
                         "{\"sub\":\"alice\"}",
                         short_sig, sizeof(short_sig), pool);
    t = nxe_jwx_decode(&jwt, pool);
    ASSERT(t != NULL);
    ASSERT_EQ_INT(nxe_jwx_jws_verify(t, jwks, pool), NGX_DECLINED);

    EVP_PKEY_free(pkey);
    return 0;
}

TEST(jws_null_args){
    ngx_str_t jwt = ngx_string(FIXTURE_TOKEN_OK);
    nxe_jwx_token_t *t;

    t = nxe_jwx_decode(&jwt, pool);
    ASSERT(t != NULL);

    ASSERT_EQ_INT(nxe_jwx_jws_verify(NULL, NULL, pool), NGX_ERROR);
    ASSERT_EQ_INT(nxe_jwx_jws_verify(t, NULL, pool), NGX_ERROR);
    ASSERT_EQ_INT(nxe_jwx_jws_verify(t, NULL, NULL), NGX_ERROR);
    return 0;
}


/* === JWS issuing (nxe_jwx_encode) round-trips === */

/*
 * Encode `claims` with `alg`/`kid`/`key`, then decode the result and
 * verify it against `jwks_doc`.  Returns the nxe_jwx_jws_verify status
 * (NGX_OK on a successful round-trip), or a negative sentinel when an
 * earlier step fails so the caller's ASSERT pinpoints the stage.
 */
static int
encode_then_verify(ngx_pool_t *pool, const char *alg, const char *kid,
    const char *claims_json, const ngx_str_t *key, const ngx_str_t *jwks_doc)
{
    ngx_str_t alg_s, kid_s = { 0, NULL }, claims_s, out;
    nxe_jwx_jwks_t *jwks;
    nxe_jwx_token_t *t;

    alg_s.data = (u_char *) alg;
    alg_s.len = strlen(alg);
    claims_s.data = (u_char *) claims_json;
    claims_s.len = strlen(claims_json);
    if (kid != NULL) {
        kid_s.data = (u_char *) kid;
        kid_s.len = strlen(kid);
    }

    if (nxe_jwx_encode(pool, &alg_s, kid != NULL ? &kid_s : NULL,
                       &claims_s, key, &out) != NGX_OK)
    {
        return -1;
    }
    /* token-string contract: NUL-terminated just past out->len. */
    if (out.data == NULL || out.data[out.len] != '\0') {
        return -2;
    }
    t = nxe_jwx_decode(&out, pool);
    if (t == NULL) {
        return -3;
    }
    jwks = nxe_jwx_jwks_parse(jwks_doc, pool);
    if (jwks == NULL) {
        return -4;
    }
    return (int) nxe_jwx_jws_verify(t, jwks, pool);
}


TEST(encode_rs256_roundtrip){
    EVP_PKEY *pkey = test_gen_rsa(2048);
    ngx_str_t priv, jwk, doc;

    ASSERT(pkey != NULL);
    priv = test_pem_privkey(pkey, pool);
    ASSERT(priv.len > 0);
    jwk = test_jwk_rsa(pkey, "k1", NULL, pool);
    ASSERT(jwk.len > 0);
    doc = test_jwks_build(&jwk, 1, pool);
    ASSERT_EQ_INT(encode_then_verify(pool, "RS256", "k1",
                                     "{\"sub\":\"alice\"}", &priv, &doc),
                  NGX_OK);
    EVP_PKEY_free(pkey);
    return 0;
}

TEST(encode_ps256_roundtrip){
    EVP_PKEY *pkey = test_gen_rsa(2048);
    ngx_str_t priv, jwk, doc;

    ASSERT(pkey != NULL);
    priv = test_pem_privkey(pkey, pool);
    ASSERT(priv.len > 0);
    jwk = test_jwk_rsa(pkey, "k1", NULL, pool);
    ASSERT(jwk.len > 0);
    doc = test_jwks_build(&jwk, 1, pool);
    ASSERT_EQ_INT(encode_then_verify(pool, "PS256", "k1",
                                     "{\"sub\":\"bob\"}", &priv, &doc),
                  NGX_OK);
    EVP_PKEY_free(pkey);
    return 0;
}

TEST(encode_es256_roundtrip){
    EVP_PKEY *pkey = test_gen_ec(NID_X9_62_prime256v1);
    ngx_str_t priv, jwk, doc;

    ASSERT(pkey != NULL);
    priv = test_pem_privkey(pkey, pool);
    ASSERT(priv.len > 0);
    jwk = test_jwk_ec(pkey, "P-256", 32, "k1", NULL, pool);
    ASSERT(jwk.len > 0);
    doc = test_jwks_build(&jwk, 1, pool);
    ASSERT_EQ_INT(encode_then_verify(pool, "ES256", "k1",
                                     "{\"sub\":\"carol\"}", &priv, &doc),
                  NGX_OK);
    EVP_PKEY_free(pkey);
    return 0;
}

TEST(encode_es384_roundtrip){
    EVP_PKEY *pkey = test_gen_ec(NID_secp384r1);
    ngx_str_t priv, jwk, doc;

    ASSERT(pkey != NULL);
    priv = test_pem_privkey(pkey, pool);
    ASSERT(priv.len > 0);
    jwk = test_jwk_ec(pkey, "P-384", 48, "k1", NULL, pool);
    ASSERT(jwk.len > 0);
    doc = test_jwks_build(&jwk, 1, pool);
    ASSERT_EQ_INT(encode_then_verify(pool, "ES384", "k1",
                                     "{\"sub\":\"dave\"}", &priv, &doc),
                  NGX_OK);
    EVP_PKEY_free(pkey);
    return 0;
}

TEST(encode_eddsa_roundtrip){
    EVP_PKEY *pkey = test_gen_ed25519();
    ngx_str_t priv, jwk, doc;

    ASSERT(pkey != NULL);
    priv = test_pem_privkey(pkey, pool);
    ASSERT(priv.len > 0);
    jwk = test_jwk_okp(pkey, "Ed25519", 32, "k1", NULL, pool);
    ASSERT(jwk.len > 0);
    doc = test_jwks_build(&jwk, 1, pool);
    ASSERT_EQ_INT(encode_then_verify(pool, "EdDSA", "k1",
                                     "{\"sub\":\"erin\"}", &priv, &doc),
                  NGX_OK);
    EVP_PKEY_free(pkey);
    return 0;
}

TEST(encode_hs256_roundtrip){
    static const u_char secret[] = "0123456789abcdef0123456789abcdef";
    ngx_str_t key, jwk, doc;

    key.data = (u_char *) secret;
    key.len = sizeof(secret) - 1;
    jwk = test_jwk_oct(secret, sizeof(secret) - 1, "k1", NULL, pool);
    ASSERT(jwk.len > 0);
    doc = test_jwks_build(&jwk, 1, pool);
    ASSERT_EQ_INT(encode_then_verify(pool, "HS256", "k1",
                                     "{\"sub\":\"frank\"}", &key, &doc),
                  NGX_OK);
    return 0;
}

TEST(encode_no_kid_roundtrip){
    EVP_PKEY *pkey = test_gen_rsa(2048);
    ngx_str_t priv, jwk, doc;

    ASSERT(pkey != NULL);
    priv = test_pem_privkey(pkey, pool);
    ASSERT(priv.len > 0);
    /* kid-less JWK so the kid-less token verifies via pass 2. */
    jwk = test_jwk_rsa(pkey, NULL, NULL, pool);
    ASSERT(jwk.len > 0);
    doc = test_jwks_build(&jwk, 1, pool);
    ASSERT_EQ_INT(encode_then_verify(pool, "RS256", NULL,
                                     "{\"sub\":\"grace\"}", &priv, &doc),
                  NGX_OK);
    EVP_PKEY_free(pkey);
    return 0;
}

/* Header carries alg + typ + kid; payload survives verbatim. */
TEST(encode_header_and_payload){
    EVP_PKEY *pkey = test_gen_rsa(2048);
    ngx_str_t priv, alg_s, kid_s, claims_s, out;
    nxe_jwx_token_t *t;
    nxe_json_t *header;
    ngx_str_t typ, sub;
    const ngx_str_t *got;

    ASSERT(pkey != NULL);
    priv = test_pem_privkey(pkey, pool);
    ASSERT(priv.len > 0);

    alg_s.data = (u_char *) "RS256"; alg_s.len = 5;
    kid_s.data = (u_char *) "my-key"; kid_s.len = 6;
    claims_s.data = (u_char *) "{\"sub\":\"alice\",\"cid\":\"web\"}";
    claims_s.len = strlen((char *) claims_s.data);

    ASSERT_EQ_INT(nxe_jwx_encode(pool, &alg_s, &kid_s, &claims_s, &priv, &out),
                  NGX_OK);

    t = nxe_jwx_decode(&out, pool);
    ASSERT(t != NULL);

    got = nxe_jwx_token_alg(t);
    ASSERT(got != NULL);
    ASSERT_STR_EQ(got, "RS256");

    got = nxe_jwx_token_kid(t);
    ASSERT(got != NULL);
    ASSERT_STR_EQ(got, "my-key");

    header = nxe_jwx_token_header(t);
    ASSERT(header != NULL);
    ASSERT_EQ_INT(nxe_jwx_claims_get_string(header, "typ", &typ), NGX_OK);
    ASSERT_STR_EQ(&typ, "JWT");

    ASSERT_EQ_INT(nxe_jwx_claims_get_string(nxe_jwx_token_payload(t),
                                            "sub", &sub), NGX_OK);
    ASSERT_STR_EQ(&sub, "alice");

    EVP_PKEY_free(pkey);
    return 0;
}

/* kid containing a JSON metacharacter is escaped, not injected. */
TEST(encode_kid_is_json_escaped){
    EVP_PKEY *pkey = test_gen_rsa(2048);
    ngx_str_t priv, alg_s, kid_s, claims_s, out;
    nxe_jwx_token_t *t;
    const ngx_str_t *got;

    ASSERT(pkey != NULL);
    priv = test_pem_privkey(pkey, pool);
    ASSERT(priv.len > 0);

    alg_s.data = (u_char *) "RS256"; alg_s.len = 5;
    kid_s.data = (u_char *) "a\"b"; kid_s.len = 3;   /* embedded quote */
    claims_s.data = (u_char *) "{\"sub\":\"x\"}";
    claims_s.len = strlen((char *) claims_s.data);

    ASSERT_EQ_INT(nxe_jwx_encode(pool, &alg_s, &kid_s, &claims_s, &priv, &out),
                  NGX_OK);

    /* The header must still parse (escaping kept it well-formed) and the
     * kid round-trips with the literal quote intact. */
    t = nxe_jwx_decode(&out, pool);
    ASSERT(t != NULL);
    got = nxe_jwx_token_kid(t);
    ASSERT(got != NULL);
    ASSERT_STR_EQ(got, "a\"b");

    EVP_PKEY_free(pkey);
    return 0;
}

TEST(encode_alg_none_rejected){
    ngx_str_t alg_s = ngx_string("none");
    ngx_str_t key = ngx_string("secret");
    ngx_str_t claims = ngx_string("{\"sub\":\"x\"}");
    ngx_str_t out;

    ASSERT_EQ_INT(nxe_jwx_encode(pool, &alg_s, NULL, &claims, &key, &out),
                  NGX_ERROR);
    return 0;
}

TEST(encode_alg_unknown_rejected){
    ngx_str_t alg_s = ngx_string("FOO");
    ngx_str_t key = ngx_string("secret");
    ngx_str_t claims = ngx_string("{\"sub\":\"x\"}");
    ngx_str_t out;

    ASSERT_EQ_INT(nxe_jwx_encode(pool, &alg_s, NULL, &claims, &key, &out),
                  NGX_ERROR);
    return 0;
}

/* RS256 with an EC private key -> family mismatch -> NGX_ERROR. */
TEST(encode_key_mismatch_rejected){
    EVP_PKEY *pkey = test_gen_ec(NID_X9_62_prime256v1);
    ngx_str_t priv, alg_s, claims, out;

    ASSERT(pkey != NULL);
    priv = test_pem_privkey(pkey, pool);
    ASSERT(priv.len > 0);
    alg_s.data = (u_char *) "RS256"; alg_s.len = 5;
    claims.data = (u_char *) "{\"sub\":\"x\"}";
    claims.len = strlen((char *) claims.data);

    ASSERT_EQ_INT(nxe_jwx_encode(pool, &alg_s, NULL, &claims, &priv, &out),
                  NGX_ERROR);
    EVP_PKEY_free(pkey);
    return 0;
}

/* ES256 expects prime256v1; a P-384 key is the wrong curve -> NGX_ERROR. */
TEST(encode_ec_curve_mismatch_rejected){
    EVP_PKEY *pkey = test_gen_ec(NID_secp384r1);
    ngx_str_t priv, alg_s, claims, out;

    ASSERT(pkey != NULL);
    priv = test_pem_privkey(pkey, pool);
    ASSERT(priv.len > 0);
    alg_s.data = (u_char *) "ES256"; alg_s.len = 5;
    claims.data = (u_char *) "{\"sub\":\"x\"}";
    claims.len = strlen((char *) claims.data);

    ASSERT_EQ_INT(nxe_jwx_encode(pool, &alg_s, NULL, &claims, &priv, &out),
                  NGX_ERROR);
    EVP_PKEY_free(pkey);
    return 0;
}

/* A bad PEM that is not a private key at all -> NGX_ERROR. */
TEST(encode_bad_pem_rejected){
    ngx_str_t alg_s = ngx_string("RS256");
    ngx_str_t key = ngx_string("-----BEGIN PRIVATE KEY-----\nnot-base64\n"
                               "-----END PRIVATE KEY-----\n");
    ngx_str_t claims = ngx_string("{\"sub\":\"x\"}");
    ngx_str_t out;

    ASSERT_EQ_INT(nxe_jwx_encode(pool, &alg_s, NULL, &claims, &key, &out),
                  NGX_ERROR);
    return 0;
}

TEST(encode_claims_not_object_rejected){
    ngx_str_t alg_s = ngx_string("HS256");
    ngx_str_t key = ngx_string("0123456789abcdef0123456789abcdef");
    ngx_str_t out;
    ngx_str_t s_claims = ngx_string("\"hello\"");
    ngx_str_t a_claims = ngx_string("[1,2,3]");

    ASSERT_EQ_INT(nxe_jwx_encode(pool, &alg_s, NULL, &s_claims, &key, &out),
                  NGX_ERROR);
    ASSERT_EQ_INT(nxe_jwx_encode(pool, &alg_s, NULL, &a_claims, &key, &out),
                  NGX_ERROR);
    return 0;
}

TEST(encode_claims_invalid_json_rejected){
    ngx_str_t alg_s = ngx_string("HS256");
    ngx_str_t key = ngx_string("0123456789abcdef0123456789abcdef");
    ngx_str_t claims = ngx_string("{bad");
    ngx_str_t out;

    ASSERT_EQ_INT(nxe_jwx_encode(pool, &alg_s, NULL, &claims, &key, &out),
                  NGX_ERROR);
    return 0;
}

/*
 * A kid large enough that the base64url-encoded header segment exceeds
 * NXE_JWX_MAX_JWT_HEADER must be rejected, mirroring the decode side's
 * per-segment cap (otherwise the issued token would be undecodable).
 */
TEST(encode_oversized_header_rejected){
    ngx_str_t alg_s = ngx_string("HS256");
    ngx_str_t key = ngx_string("0123456789abcdef0123456789abcdef");
    ngx_str_t claims = ngx_string("{\"sub\":\"x\"}");
    ngx_str_t kid, out;

    /* 6500 ASCII bytes -> header JSON ~6.5 KiB -> base64url > 8 KiB. */
    kid.len = 6500;
    kid.data = ngx_pnalloc(pool, kid.len);
    ASSERT(kid.data != NULL);
    ngx_memset(kid.data, 'a', kid.len);

    ASSERT_EQ_INT(nxe_jwx_encode(pool, &alg_s, &kid, &claims, &key, &out),
                  NGX_ERROR);
    ASSERT(out.data == NULL && out.len == 0);
    return 0;
}

/*
 * A kid + claims combination where each individual cap (header segment,
 * raw claims) passes but the assembled compact token exceeds
 * NXE_JWX_MAX_JWT_SIZE must be rejected before emission.
 */
TEST(encode_oversized_token_rejected){
    ngx_str_t alg_s = ngx_string("HS256");
    ngx_str_t key = ngx_string("0123456789abcdef0123456789abcdef");
    ngx_str_t kid, claims, out;
    u_char *p;

    /* Header base64url ~8 KiB, under the 8 KiB segment cap. */
    kid.len = 6000;
    kid.data = ngx_pnalloc(pool, kid.len);
    ASSERT(kid.data != NULL);
    ngx_memset(kid.data, 'a', kid.len);

    /*
     * claims {"x":"aaa..."} ~7 KiB raw, under the 16 KiB claims cap, but
     * header + payload + signature together exceed 16 KiB.
     */
    claims.len = 7008;
    claims.data = ngx_pnalloc(pool, claims.len);
    ASSERT(claims.data != NULL);
    p = claims.data;
    ngx_memcpy(p, "{\"x\":\"", 6); p += 6;
    ngx_memset(p, 'a', claims.len - 8); p += claims.len - 8;
    ngx_memcpy(p, "\"}", 2);

    ASSERT_EQ_INT(nxe_jwx_encode(pool, &alg_s, &kid, &claims, &key, &out),
                  NGX_ERROR);
    ASSERT(out.data == NULL && out.len == 0);
    return 0;
}

TEST(encode_null_args_rejected){
    ngx_str_t alg_s = ngx_string("HS256");
    ngx_str_t key = ngx_string("0123456789abcdef0123456789abcdef");
    ngx_str_t claims = ngx_string("{\"sub\":\"x\"}");
    ngx_str_t empty = { 0, NULL };
    ngx_str_t out;

    ASSERT_EQ_INT(nxe_jwx_encode(NULL, &alg_s, NULL, &claims, &key, &out),
                  NGX_ERROR);
    ASSERT_EQ_INT(nxe_jwx_encode(pool, NULL, NULL, &claims, &key, &out),
                  NGX_ERROR);
    ASSERT_EQ_INT(nxe_jwx_encode(pool, &alg_s, NULL, NULL, &key, &out),
                  NGX_ERROR);
    ASSERT_EQ_INT(nxe_jwx_encode(pool, &alg_s, NULL, &claims, NULL, &out),
                  NGX_ERROR);
    ASSERT_EQ_INT(nxe_jwx_encode(pool, &alg_s, NULL, &claims, &key, NULL),
                  NGX_ERROR);
    ASSERT_EQ_INT(nxe_jwx_encode(pool, &empty, NULL, &claims, &key, &out),
                  NGX_ERROR);
    ASSERT_EQ_INT(nxe_jwx_encode(pool, &alg_s, NULL, &empty, &key, &out),
                  NGX_ERROR);
    ASSERT_EQ_INT(nxe_jwx_encode(pool, &alg_s, NULL, &claims, &empty, &out),
                  NGX_ERROR);
    return 0;
}


/* === main === */

int
main(void)
{
    ngx_log_t log;

    log.log_level = (getenv("NXE_JWX_TEST_VERBOSE") != NULL)
        ? NGX_LOG_DEBUG : NGX_LOG_STDERR;

    /* claims */
    RUN(claims_get_string_ok);
    RUN(claims_get_string_missing);
    RUN(claims_get_string_wrong_type);
    RUN(claims_get_string_null_out);
    RUN(claims_get_integer_ok);
    RUN(claims_get_integer_missing);
    RUN(claims_get_integer_wrong_type);
    RUN(claims_get_integer_null_out);
    RUN(claims_get_boolean_ok);
    RUN(claims_get_boolean_missing);
    RUN(claims_get_boolean_wrong_type);
    RUN(claims_get_boolean_null_out);
    RUN(claims_get_array_ok);
    RUN(claims_get_array_missing);
    RUN(claims_get_array_wrong_type);
    RUN(claims_get_array_null_out);
    RUN(claims_get_object_ok);
    RUN(claims_get_object_missing);
    RUN(claims_get_object_wrong_type);
    RUN(claims_get_object_null_out);
    RUN(claims_null_args);

    /* decode */
    RUN(decode_ok);
    RUN(decode_too_few_segments);
    RUN(decode_too_many_segments);
    RUN(decode_empty_signature_accepted);
    RUN(decode_empty_segment);
    RUN(decode_invalid_base64);
    RUN(decode_header_not_object);
    RUN(decode_token_too_large);
    RUN(decode_null_pool);
    RUN(decode_null_token);
    RUN(decode_empty_token);
    RUN(decode_token_alg_kid_null_args);
    RUN(decode_no_alg_no_kid);
    RUN(decode_alg_not_string);
    RUN(decode_invalid_b64_payload);
    RUN(decode_invalid_b64_signature);
    RUN(decode_payload_not_object);
    RUN(decode_payload_invalid_json);
    RUN(decode_header_too_large);

    /* jwks */
    RUN(jwks_root_not_object);
    RUN(jwks_missing_keys_array);
    RUN(jwks_empty_keys_array);
    RUN(jwks_unsupported_kty_only);
    RUN(jwks_size_too_large);
    RUN(jwks_null_args);
    RUN(jwks_invalid_json);
    RUN(jwks_missing_kty);
    RUN(jwks_keys_entry_not_object);
    RUN(jwks_too_many_keys);
    RUN(jwks_rsa_ok);
    RUN(jwks_free_explicit);
    RUN(jwks_free_null);
    RUN(jwks_rsa_modulus_too_small);
    RUN(jwks_rsa_modulus_too_large);
    RUN(jwks_rsa_missing_n);
    RUN(jwks_rsa_missing_e);
    RUN(jwks_ec_p256_ok);
    RUN(jwks_ec_p384_ok);
    RUN(jwks_ec_p521_ok);
    RUN(jwks_ec_secp256k1_ok);
    RUN(jwks_ec_unsupported_crv);
    RUN(jwks_ec_missing_crv);
    RUN(jwks_ec_wrong_coord_len);
    RUN(jwks_ec_missing_y);
    RUN(jwks_okp_ed25519_ok);
    RUN(jwks_okp_unsupported_crv);
    RUN(jwks_okp_missing_crv);
    RUN(jwks_okp_wrong_x_len);
    RUN(jwks_oct_ok);
    RUN(jwks_oct_missing_k);
    RUN(jwks_rsa_corrupt_base64_n);
    RUN(jwks_rsa_corrupt_base64_e);
    RUN(jwks_ec_corrupt_base64_x);
    RUN(jwks_okp_corrupt_base64_x);
#if (NXE_JWX_HAVE_HMAC)
    RUN(jwks_oct_corrupt_base64_k);
#endif
    RUN(jwks_multi_keys);
    RUN(jwks_empty_kid_skipped);
    RUN(jwks_empty_kid_only_rejected);
    RUN(jwks_kid_field_absent_ok);

    /* jwks keyval */
    RUN(jwks_keyval_pem_ok);
    RUN(jwks_keyval_ec_pem_verifies);
    RUN(jwks_keyval_empty_object);
    RUN(jwks_keyval_empty_kid_skipped);
    RUN(jwks_keyval_empty_kid_only_rejected);
    RUN(jwks_keyval_multi_kid_pem);
    RUN(jwks_keyval_non_pem_rejected);
    RUN(jwks_keyval_pem_looking_corrupt_rejected);
    RUN(jwks_keyval_multi_kid_hmac_rejected);
    RUN(jwks_keyval_root_not_object);
    RUN(jwks_keyval_invalid_json);
    RUN(jwks_keyval_null_args);
    RUN(jwks_keyval_too_large);

    /* jws verify */
    RUN(jws_rs256_roundtrip);
    RUN(jws_rs384_roundtrip);
    RUN(jws_rs512_roundtrip);
    RUN(jws_ps256_roundtrip);
    RUN(jws_ps384_roundtrip);
    RUN(jws_ps512_roundtrip);
    RUN(jws_es256_roundtrip);
    RUN(jws_es384_roundtrip);
    RUN(jws_es512_roundtrip);
    RUN(jws_es256k_roundtrip);
    RUN(jws_eddsa_roundtrip);
    RUN(jws_hs256_roundtrip);
    RUN(jws_hs384_roundtrip);
    RUN(jws_hs512_roundtrip);
    RUN(jws_alg_none_rejected);
    RUN(jws_empty_signature_rejected);
    RUN(jws_alg_unknown_rejected);
    RUN(jws_no_alg_rejected);
    RUN(jws_signature_tampered);
    RUN(jws_kid_no_match_falls_back);
    RUN(jwks_has_kid_basic);
    RUN(jws_kid_mismatch_with_other_kid_only_rejected);
    RUN(jws_alg_pinned_in_jwk);
    RUN(jwks_use_enc_skipped);
    RUN(jws_kid_match_pins_to_that_key);
    RUN(jws_kty_mismatch);
    RUN(jws_ec_curve_mismatch);
    RUN(jws_es256_bad_sig_length);
    RUN(jws_null_args);

    /* encode (issuing) */
    RUN(encode_rs256_roundtrip);
    RUN(encode_ps256_roundtrip);
    RUN(encode_es256_roundtrip);
    RUN(encode_es384_roundtrip);
    RUN(encode_eddsa_roundtrip);
    RUN(encode_hs256_roundtrip);
    RUN(encode_no_kid_roundtrip);
    RUN(encode_header_and_payload);
    RUN(encode_kid_is_json_escaped);
    RUN(encode_alg_none_rejected);
    RUN(encode_alg_unknown_rejected);
    RUN(encode_key_mismatch_rejected);
    RUN(encode_ec_curve_mismatch_rejected);
    RUN(encode_bad_pem_rejected);
    RUN(encode_claims_not_object_rejected);
    RUN(encode_claims_invalid_json_rejected);
    RUN(encode_oversized_header_rejected);
    RUN(encode_oversized_token_rejected);
    RUN(encode_null_args_rejected);

    printf("\n%d passed, %d failed\n", g_passed, g_failed);
    return g_failed == 0 ? 0 : 1;
}
