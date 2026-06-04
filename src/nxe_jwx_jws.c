/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 *
 * nxe_jwx_jws.c - JWS signature generation and verification
 *
 * Algorithm policy:
 *   - "none" is rejected unconditionally.
 *   - HS256/384/512 are rejected unless built with NXE_JWX_HAVE_HMAC.
 *
 * Key selection (verify):
 *   - If the token has a kid, keys with a matching kid are tried first.
 *   - Then all keys whose kty/alg are compatible with the token's alg
 *     are tried.
 *   - The first key that produces a valid signature wins.
 *
 * Issuing (nxe_jwx_encode) is the symmetric counterpart of verify: it
 * shares the algorithm table and the ECDSA R||S <-> DER conversion,
 * signs "<b64url header>.<b64url payload>" with the supplied key, and
 * assembles the compact JWS.
 */

#include <ngx_config.h>
#include <ngx_core.h>

#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

#include <nxe_json.h>

#include "nxe_jwx.h"
#include "nxe_jwx_internal.h"


/* === Algorithm table === */

typedef enum {
    NXE_JWX_ALG_FAMILY_RSA,         /* RSASSA-PKCS1-v1_5 */
    NXE_JWX_ALG_FAMILY_RSA_PSS,     /* RSASSA-PSS */
    NXE_JWX_ALG_FAMILY_ECDSA,       /* ECDSA (raw R||S signature) */
    NXE_JWX_ALG_FAMILY_EDDSA,       /* Ed25519 / Ed448 */
#if (NXE_JWX_HAVE_HMAC)
    NXE_JWX_ALG_FAMILY_HMAC,
#endif
} nxe_jwx_alg_family_t;


typedef struct {
    const char           *name;
    nxe_jwx_alg_family_t  family;
    const char           *digest;   /* OpenSSL digest name (NULL for EdDSA) */
    const char           *ec_curve; /* required EC curve, NULL if N/A */
    size_t                ec_coord_len; /* per-component sig length */
} nxe_jwx_alg_t;


static const nxe_jwx_alg_t nxe_jwx_algs[] = {
    { "RS256", NXE_JWX_ALG_FAMILY_RSA,     "SHA256", NULL, 0 },
    { "RS384", NXE_JWX_ALG_FAMILY_RSA,     "SHA384", NULL, 0 },
    { "RS512", NXE_JWX_ALG_FAMILY_RSA,     "SHA512", NULL, 0 },

    { "PS256", NXE_JWX_ALG_FAMILY_RSA_PSS, "SHA256", NULL, 0 },
    { "PS384", NXE_JWX_ALG_FAMILY_RSA_PSS, "SHA384", NULL, 0 },
    { "PS512", NXE_JWX_ALG_FAMILY_RSA_PSS, "SHA512", NULL, 0 },

    /*
     * `ec_curve` holds the OpenSSL short name (matched against
     * EVP_PKEY_get_group_name / OBJ_nid2sn output), not the JWK
     * "crv" alias.
     */
    { "ES256",  NXE_JWX_ALG_FAMILY_ECDSA, "SHA256", "prime256v1", 32 },
    { "ES384",  NXE_JWX_ALG_FAMILY_ECDSA, "SHA384", "secp384r1",  48 },
    { "ES512",  NXE_JWX_ALG_FAMILY_ECDSA, "SHA512", "secp521r1",  66 },
    { "ES256K", NXE_JWX_ALG_FAMILY_ECDSA, "SHA256", "secp256k1",  32 },

    { "EdDSA", NXE_JWX_ALG_FAMILY_EDDSA, NULL, NULL, 0 },

#if (NXE_JWX_HAVE_HMAC)
    { "HS256", NXE_JWX_ALG_FAMILY_HMAC, "SHA256", NULL, 0 },
    { "HS384", NXE_JWX_ALG_FAMILY_HMAC, "SHA384", NULL, 0 },
    { "HS512", NXE_JWX_ALG_FAMILY_HMAC, "SHA512", NULL, 0 },
#endif

    { NULL, 0, NULL, NULL, 0 }
};


static const nxe_jwx_alg_t *
nxe_jwx_lookup_alg(const ngx_str_t *alg)
{
    const nxe_jwx_alg_t *a;

    for (a = nxe_jwx_algs; a->name != NULL; a++) {
        size_t n = ngx_strlen(a->name);
        if (alg->len == n && ngx_strncmp(alg->data, a->name, n) == 0) {
            return a;
        }
    }
    return NULL;
}


static ngx_flag_t
nxe_jwx_str_eq(const ngx_str_t *a, const ngx_str_t *b)
{
    if (a->len != b->len) {
        return 0;
    }
    if (a->len == 0) {
        return 1;
    }
    return ngx_memcmp(a->data, b->data, a->len) == 0 ? 1 : 0;
}


/*
 * Convert a raw ECDSA signature (R || S, fixed-width) into the DER
 * encoding that OpenSSL's EVP_DigestVerify* expects.  Returns a
 * pool-allocated buffer in *der; caller does not free.  Returns
 * NGX_DECLINED on length mismatch (= signature is structurally
 * wrong) and NGX_ERROR on internal error.
 */
static ngx_int_t
nxe_jwx_ecdsa_raw_to_der(const ngx_str_t *raw, size_t coord_len,
    ngx_str_t *der, ngx_pool_t *pool)
{
    ECDSA_SIG *sig = NULL;
    BIGNUM *r = NULL, *s = NULL;
    int der_len;
    u_char *p;
    ngx_int_t rc = NGX_ERROR;

    der->data = NULL;
    der->len = 0;

    if (raw->len != coord_len * 2) {
        return NGX_DECLINED;
    }

    r = BN_bin2bn(raw->data, (int) coord_len, NULL);
    s = BN_bin2bn(raw->data + coord_len, (int) coord_len, NULL);
    if (r == NULL || s == NULL) {
        goto out;
    }

    sig = ECDSA_SIG_new();
    if (sig == NULL) {
        goto out;
    }
    if (ECDSA_SIG_set0(sig, r, s) != 1) {
        goto out;
    }
    /* sig now owns r and s. */
    r = NULL;
    s = NULL;

    der_len = i2d_ECDSA_SIG(sig, NULL);
    if (der_len <= 0) {
        goto out;
    }
    der->data = ngx_pnalloc(pool, der_len);
    if (der->data == NULL) {
        goto out;
    }
    p = der->data;
    if (i2d_ECDSA_SIG(sig, &p) != der_len) {
        goto out;
    }
    der->len = (size_t) der_len;

    rc = NGX_OK;

out:
    BN_free(r);
    BN_free(s);
    ECDSA_SIG_free(sig);
    return rc;
}


/*
 * Confirm that an EC EVP_PKEY uses the curve `expected`.  Returns 1
 * on match, 0 otherwise.
 */
static ngx_flag_t
nxe_jwx_ec_curve_matches(EVP_PKEY *pkey, const char *expected)
{
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    /*
     * EVP_PKEY_get_group_name writes a NUL-terminated UTF-8 string when
     * the buffer is large enough; the OpenSSL short names we compare
     * against ("prime256v1", "secp384r1", "secp521r1", "secp256k1")
     * are all <= 10 characters, so a 32-byte buffer cannot truncate.
     */
    char name[32];

    if (EVP_PKEY_get_group_name(pkey, name, sizeof(name), NULL) != 1) {
        return 0;
    }
    return ngx_strcmp(name, expected) == 0 ? 1 : 0;
#else
    EC_KEY *ec;
    const EC_GROUP *group;
    int nid;
    const char *sname;

    ec = EVP_PKEY_get0_EC_KEY(pkey);
    if (ec == NULL) {
        return 0;
    }
    group = EC_KEY_get0_group(ec);
    if (group == NULL) {
        return 0;
    }
    nid = EC_GROUP_get_curve_name(group);
    sname = OBJ_nid2sn(nid);
    if (sname == NULL) {
        return 0;
    }
    return ngx_strcmp(sname, expected) == 0 ? 1 : 0;
#endif
}


/*
 * Run EVP_DigestVerify with `digest` (or NULL for EdDSA) on
 * `signing_input`.
 *
 *   1   verified
 *   0   signature did not verify
 *  -1   internal/setup error
 */
static int
nxe_jwx_evp_verify(EVP_PKEY *pkey, const char *digest_name,
    const ngx_str_t *signing_input, const ngx_str_t *signature,
    ngx_flag_t pss)
{
    EVP_MD_CTX *ctx;
    EVP_PKEY_CTX *pctx = NULL;
    const EVP_MD *md = NULL;
    int rc;

    if (digest_name != NULL) {
        md = EVP_get_digestbyname(digest_name);
        if (md == NULL) {
            return -1;
        }
    }

    ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        return -1;
    }

    if (EVP_DigestVerifyInit(ctx, &pctx, md, NULL, pkey) != 1) {
        EVP_MD_CTX_free(ctx);
        return -1;
    }

    if (pss) {
        if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) <= 0
            || EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, RSA_PSS_SALTLEN_DIGEST)
            <= 0
            || EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, md) <= 0)
        {
            EVP_MD_CTX_free(ctx);
            return -1;
        }
    }

    /*
     * EVP_DigestVerify is the single-shot form for both digest-based
     * algorithms (RSA / RSA-PSS / ECDSA) and EdDSA, where the digest
     * argument to Init is NULL and the whole message is hashed
     * internally.  No branching needed here.
     */
    rc = EVP_DigestVerify(ctx, signature->data, signature->len,
                          signing_input->data, signing_input->len);

    EVP_MD_CTX_free(ctx);

    /*
     * Per OpenSSL EVP_DigestVerify(3), only a return of exactly 1 means the
     * signature verified.  A return of 0 means the signature did not match;
     * a negative value also indicates verification failure (often an
     * "invalid signature form" the encoder rejected before doing the math).
     * Either case is fail-closed for us: do not escalate to an internal
     * error and never let the caller see a different code than for any
     * other rejected key.
     */
    return rc == 1 ? 1 : 0;
}


#if (NXE_JWX_HAVE_HMAC)
/*
 * HMAC verify with constant-time comparison.
 */
static int
nxe_jwx_hmac_verify(const ngx_str_t *secret, const char *digest_name,
    const ngx_str_t *signing_input, const ngx_str_t *signature)
{
    const EVP_MD *md;
    u_char mac[EVP_MAX_MD_SIZE];
    unsigned int mac_len = 0;

    md = EVP_get_digestbyname(digest_name);
    if (md == NULL) {
        return -1;
    }

    if (HMAC(md, secret->data, (int) secret->len,
             signing_input->data, signing_input->len,
             mac, &mac_len) == NULL)
    {
        return -1;
    }

    if (signature->len != mac_len) {
        OPENSSL_cleanse(mac, sizeof(mac));
        return 0;
    }
    if (CRYPTO_memcmp(mac, signature->data, mac_len) != 0) {
        OPENSSL_cleanse(mac, sizeof(mac));
        return 0;
    }
    OPENSSL_cleanse(mac, sizeof(mac));
    return 1;
}
#endif


/*
 * Decide whether `key` is structurally compatible with `alg`.
 * "Compatible" here means:
 *   1. The key type / curve will not cause EVP_DigestVerify to error
 *      out for reasons unrelated to the signature itself, AND
 *   2. If the JWK pinned itself to a specific algorithm via the
 *      "alg" parameter, the token's alg matches it byte-for-byte.
 *      A key whose JWK declared alg=RS384 is not used to verify an
 *      RS256 token even though both share kty=RSA: operators that
 *      take the trouble to label keys with an alg expect it to be
 *      enforced.
 */
static ngx_flag_t
nxe_jwx_key_compatible(const struct nxe_jwx_key_s *k,
    const nxe_jwx_alg_t *alg)
{
    int pkey_id;
    size_t alg_name_len;

    /* Strict alg pinning when the JWK supplies one. */
    if (k->alg.len > 0) {
        alg_name_len = ngx_strlen(alg->name);
        if (k->alg.len != alg_name_len
            || ngx_strncmp(k->alg.data, alg->name, alg_name_len) != 0)
        {
            return 0;
        }
    }

    switch (alg->family) {
    case NXE_JWX_ALG_FAMILY_RSA:
    case NXE_JWX_ALG_FAMILY_RSA_PSS:
        if (k->kty != NXE_JWX_KTY_RSA) {
            return 0;
        }
        return 1;

    case NXE_JWX_ALG_FAMILY_ECDSA:
        if (k->kty != NXE_JWX_KTY_EC) {
            return 0;
        }
        if (alg->ec_curve != NULL
            && !nxe_jwx_ec_curve_matches(k->pkey, alg->ec_curve))
        {
            return 0;
        }
        return 1;

    case NXE_JWX_ALG_FAMILY_EDDSA:
        if (k->kty != NXE_JWX_KTY_OKP) {
            return 0;
        }
        pkey_id = EVP_PKEY_base_id(k->pkey);
        return (pkey_id == EVP_PKEY_ED25519 || pkey_id == EVP_PKEY_ED448)
            ? 1 : 0;

#if (NXE_JWX_HAVE_HMAC)
    case NXE_JWX_ALG_FAMILY_HMAC:
        return k->kty == NXE_JWX_KTY_OCT ? 1 : 0;
#endif
    }

    return 0;
}


/*
 * Single-key verification.  Returns 1 (verified), 0 (rejected), -1
 * (internal error).
 */
static int
nxe_jwx_verify_with_key(const struct nxe_jwx_key_s *k,
    const nxe_jwx_alg_t *alg, const ngx_str_t *signing_input,
    const ngx_str_t *signature, ngx_pool_t *pool)
{
    if (!nxe_jwx_key_compatible(k, alg)) {
        return 0;
    }

    switch (alg->family) {
    case NXE_JWX_ALG_FAMILY_RSA:
        return nxe_jwx_evp_verify(k->pkey, alg->digest, signing_input,
                                  signature, 0);

    case NXE_JWX_ALG_FAMILY_RSA_PSS:
        return nxe_jwx_evp_verify(k->pkey, alg->digest, signing_input,
                                  signature, 1);

    case NXE_JWX_ALG_FAMILY_ECDSA:
    {
        ngx_str_t der;
        ngx_int_t rc;

        rc = nxe_jwx_ecdsa_raw_to_der(signature, alg->ec_coord_len,
                                      &der, pool);
        if (rc == NGX_DECLINED) {
            return 0;       /* malformed sig length */
        }
        if (rc != NGX_OK) {
            return -1;
        }
        return nxe_jwx_evp_verify(k->pkey, alg->digest, signing_input,
                                  &der, 0);
    }

    case NXE_JWX_ALG_FAMILY_EDDSA:
        return nxe_jwx_evp_verify(k->pkey, NULL, signing_input,
                                  signature, 0);

#if (NXE_JWX_HAVE_HMAC)
    case NXE_JWX_ALG_FAMILY_HMAC:
        return nxe_jwx_hmac_verify(&k->hmac_secret, alg->digest,
                                   signing_input, signature);
#endif
    }

    return -1;
}


ngx_int_t
nxe_jwx_jws_verify(const nxe_jwx_token_t *token, const nxe_jwx_jwks_t *jwks,
    ngx_pool_t *pool)
{
    const ngx_str_t *alg_str, *kid;
    const nxe_jwx_alg_t *alg;
    ngx_str_t *signing_input, *signature;
    ngx_log_t *log;
    ngx_uint_t i, n;
    ngx_flag_t any_internal_error = 0;
    ngx_flag_t has_kid;
    ngx_flag_t kid_matched_any = 0;

    if (token == NULL || jwks == NULL || pool == NULL) {
        return NGX_ERROR;
    }
    log = nxe_jwx_log(pool);

    alg_str = nxe_jwx_token_alg(token);
    if (alg_str == NULL || alg_str->len == 0) {
        ngx_log_error(NGX_LOG_ERR, log, 0, "nxe_jwx: token has no alg");
        return NGX_DECLINED;
    }

    /* Reject "none" before any other policy check. */
    if (alg_str->len == 4
        && ngx_strncmp(alg_str->data, "none", 4) == 0)
    {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "nxe_jwx: 'none' algorithm rejected");
        return NGX_DECLINED;
    }

    alg = nxe_jwx_lookup_alg(alg_str);
    if (alg == NULL) {
        /* Unsupported alg, including HS* when HMAC is disabled at
         * compile time.  Treat indistinguishable from a verification
         * failure to avoid leaking the policy. */
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "nxe_jwx: alg \"%V\" is not supported", alg_str);
        return NGX_DECLINED;
    }

    signing_input = nxe_jwx_token_signing_input((nxe_jwx_token_t *) token);
    signature = nxe_jwx_token_signature((nxe_jwx_token_t *) token);
    if (signing_input == NULL || signature == NULL) {
        return NGX_ERROR;
    }

    /* A zero-length signature can occur for tokens that the decoder
     * accepted (see nxe_jwx_split_segments) but which carry no actual
     * signature material.  No key can ever validate such a token, so
     * reject before walking the keyset. */
    if (signature->len == 0) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "nxe_jwx: token has no signature material");
        return NGX_DECLINED;
    }

    kid = nxe_jwx_token_kid(token);
    has_kid = (kid != NULL && kid->len > 0);
    n = nxe_jwx_jwks_size_internal(jwks);

    /*
     * Pass 1: kid-strict.  When the token names a kid and the keyset
     * contains at least one key with that kid, only those keys are
     * tried.  This pins the verifier to the operator's labelled key
     * choice and prevents key-confusion regressions where a token
     * intended for kid A is accepted by another compatible kid B
     * sitting in the same JWKS.
     *
     * `kid_matched_any` distinguishes "the operator declared this
     * kid but the signature didn't verify" (-> stop, fail closed)
     * from "no key in the JWKS carries this kid" (-> fall through
     * to pass 2 so kid-less or differently-labelled keys still get
     * a chance).
     */
    if (has_kid) {
        for (i = 0; i < n; i++) {
            struct nxe_jwx_key_s *k = nxe_jwx_jwks_key_at(jwks, i);
            int rc;

            if (k == NULL || k->kid.len == 0) {
                continue;
            }
            if (!nxe_jwx_str_eq(kid, &k->kid)) {
                continue;
            }
            kid_matched_any = 1;
            rc = nxe_jwx_verify_with_key(k, alg, signing_input,
                                         signature, pool);
            if (rc == 1) {
                return NGX_OK;
            }
            if (rc < 0) {
                any_internal_error = 1;
            }
        }
    }

    /*
     * Pass 2.  Eligibility depends on whether the token names a kid:
     *
     *   - Token has a kid AND pass 1 matched at least one key:
     *     pass 2 is skipped entirely (kid-strict).
     *
     *   - Token has a kid AND pass 1 matched nothing: only kid-less
     *     keys are eligible.  This preserves the legitimate "JWKS
     *     contains some unlabeled keys" use case while denying
     *     other-kid keys, which would otherwise admit key-confusion
     *     attacks ("token claims kid X, but kid Y in the JWKS just
     *     happens to verify").
     *
     *   - Token has no kid: all compatible keys are tried.  There
     *     is no kid to confuse in this branch.
     */
    if (!(has_kid && kid_matched_any)) {
        for (i = 0; i < n; i++) {
            struct nxe_jwx_key_s *k = nxe_jwx_jwks_key_at(jwks, i);
            int rc;

            if (k == NULL) {
                continue;
            }
            if (has_kid && k->kid.len > 0) {
                continue;
            }
            rc = nxe_jwx_verify_with_key(k, alg, signing_input,
                                         signature, pool);
            if (rc == 1) {
                return NGX_OK;
            }
            if (rc < 0) {
                any_internal_error = 1;
            }
        }
    }

    if (any_internal_error) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "nxe_jwx: internal verification error (no key produced "
                      "a definitive result)");
        /* Still return NGX_DECLINED; the operator can see the ERR
         * line in the log without leaking it through the API.
         * Callers that want to distinguish should treat any failure
         * as auth failure anyway. */
    }

    return NGX_DECLINED;
}


/* === Issuing (nxe_jwx_encode) === */

/*
 * Base64url-encode `src` into a pool buffer (URL-safe alphabet, no
 * padding -- the form JWS requires).  ngx_encode_base64url sets
 * dst->len to the actual encoded length.
 */
static ngx_int_t
nxe_jwx_encode_b64url(ngx_str_t *dst, const ngx_str_t *src, ngx_pool_t *pool)
{
    ngx_str_t src_mut;

    dst->data = ngx_pnalloc(pool, ngx_base64_encoded_length(src->len));
    if (dst->data == NULL) {
        return NGX_ERROR;
    }
    dst->len = 0;

    /* ngx_encode_base64url takes a non-const ngx_str_t * for src. */
    src_mut.data = src->data;
    src_mut.len = src->len;

    ngx_encode_base64url(dst, &src_mut);
    return NGX_OK;
}


/*
 * Convert OpenSSL's DER ECDSA-Sig-Value into the fixed-width R||S
 * concatenation that JWS requires.  This is the inverse of
 * nxe_jwx_ecdsa_raw_to_der.  Returns a pool-allocated buffer in *raw;
 * NGX_ERROR on any structural failure.
 */
static ngx_int_t
nxe_jwx_ecdsa_der_to_raw(const ngx_str_t *der, size_t coord_len,
    ngx_str_t *raw, ngx_pool_t *pool)
{
    ECDSA_SIG *sig;
    const BIGNUM *r, *s;
    const u_char *p;
    ngx_int_t rc = NGX_ERROR;

    raw->data = NULL;
    raw->len = 0;

    p = der->data;
    sig = d2i_ECDSA_SIG(NULL, &p, (long) der->len);
    if (sig == NULL) {
        return NGX_ERROR;
    }

    ECDSA_SIG_get0(sig, &r, &s);

    raw->data = ngx_pnalloc(pool, coord_len * 2);
    if (raw->data == NULL) {
        goto out;
    }

    /*
     * BN_bn2binpad left-pads each component to coord_len bytes and
     * returns -1 if the value does not fit.  A short-fall would mean
     * the curve and coord_len disagree, so treat anything other than
     * an exact coord_len write as a hard error.
     */
    if (BN_bn2binpad(r, raw->data, (int) coord_len) != (int) coord_len
        || BN_bn2binpad(s, raw->data + coord_len, (int) coord_len)
        != (int) coord_len)
    {
        goto out;
    }
    raw->len = coord_len * 2;
    rc = NGX_OK;

out:
    ECDSA_SIG_free(sig);
    return rc;
}


/*
 * Sign `signing_input` with `pkey` using `digest` (or NULL for EdDSA),
 * producing a pool-allocated signature in *sig.  When `pss` is set the
 * PSS parameters mirror the verify path (MGF1 = digest, salt = digest
 * length).  For ECDSA keys the signature is DER-encoded here; the
 * caller converts it to the JWS R||S form.
 *
 * Returns NGX_OK / NGX_ERROR.
 */
static ngx_int_t
nxe_jwx_evp_sign(EVP_PKEY *pkey, const char *digest_name,
    const ngx_str_t *signing_input, ngx_flag_t pss, ngx_str_t *sig,
    ngx_pool_t *pool)
{
    EVP_MD_CTX *ctx;
    EVP_PKEY_CTX *pctx = NULL;
    const EVP_MD *md = NULL;
    size_t sig_len = 0;
    ngx_int_t rc = NGX_ERROR;

    sig->data = NULL;
    sig->len = 0;

    if (digest_name != NULL) {
        md = EVP_get_digestbyname(digest_name);
        if (md == NULL) {
            return NGX_ERROR;
        }
    }

    ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    if (EVP_DigestSignInit(ctx, &pctx, md, NULL, pkey) != 1) {
        goto out;
    }

    if (pss) {
        if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) <= 0
            || EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, RSA_PSS_SALTLEN_DIGEST)
            <= 0
            || EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, md) <= 0)
        {
            goto out;
        }
    }

    /*
     * EVP_DigestSign is the single-shot form for both digest-based
     * algorithms (RSA / RSA-PSS / ECDSA) and EdDSA.  The first call
     * sizes the signature; the second produces it.
     */
    if (EVP_DigestSign(ctx, NULL, &sig_len, signing_input->data,
                       signing_input->len) != 1)
    {
        goto out;
    }
    sig->data = ngx_pnalloc(pool, sig_len);
    if (sig->data == NULL) {
        goto out;
    }
    if (EVP_DigestSign(ctx, sig->data, &sig_len, signing_input->data,
                       signing_input->len) != 1)
    {
        sig->data = NULL;
        goto out;
    }
    sig->len = sig_len;
    rc = NGX_OK;

out:
    EVP_MD_CTX_free(ctx);
    return rc;
}


#if (NXE_JWX_HAVE_HMAC)
/*
 * HMAC-sign `signing_input` into a pool buffer.  No constant-time
 * handling is needed on the issuing side; the transient MAC buffer is
 * cleansed before returning.
 */
static ngx_int_t
nxe_jwx_hmac_sign(const ngx_str_t *secret, const char *digest_name,
    const ngx_str_t *signing_input, ngx_str_t *mac, ngx_pool_t *pool)
{
    const EVP_MD *md;
    u_char tmp[EVP_MAX_MD_SIZE];
    unsigned int tmp_len = 0;

    mac->data = NULL;
    mac->len = 0;

    md = EVP_get_digestbyname(digest_name);
    if (md == NULL) {
        return NGX_ERROR;
    }

    if (HMAC(md, secret->data, (int) secret->len,
             signing_input->data, signing_input->len,
             tmp, &tmp_len) == NULL)
    {
        return NGX_ERROR;
    }

    mac->data = ngx_pnalloc(pool, tmp_len);
    if (mac->data == NULL) {
        OPENSSL_cleanse(tmp, sizeof(tmp));
        return NGX_ERROR;
    }
    ngx_memcpy(mac->data, tmp, tmp_len);
    mac->len = tmp_len;

    OPENSSL_cleanse(tmp, sizeof(tmp));
    return NGX_OK;
}
#endif


/*
 * Load a PEM-encoded private key into an EVP_PKEY.  Returns NULL when
 * the bytes are not a valid PEM private key.
 */
static EVP_PKEY *
nxe_jwx_load_pem_privkey(const ngx_str_t *pem)
{
    BIO *bio;
    EVP_PKEY *pkey;

    bio = BIO_new_mem_buf(pem->data, (int) pem->len);
    if (bio == NULL) {
        return NULL;
    }
    pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    BIO_free(bio);
    return pkey;
}


/*
 * Confirm the loaded private key matches the requested algorithm family
 * (and, for ECDSA, the algorithm's curve).  A mismatch is the issuing-
 * side equivalent of "wrong key" and is reported as an error.
 */
static ngx_flag_t
nxe_jwx_privkey_compatible(EVP_PKEY *pkey, const nxe_jwx_alg_t *alg)
{
    int pkey_id = EVP_PKEY_base_id(pkey);

    switch (alg->family) {
    case NXE_JWX_ALG_FAMILY_RSA:
    case NXE_JWX_ALG_FAMILY_RSA_PSS:
        return (pkey_id == EVP_PKEY_RSA || pkey_id == EVP_PKEY_RSA_PSS)
            ? 1 : 0;

    case NXE_JWX_ALG_FAMILY_ECDSA:
        if (pkey_id != EVP_PKEY_EC) {
            return 0;
        }
        return (alg->ec_curve != NULL
                && nxe_jwx_ec_curve_matches(pkey, alg->ec_curve)) ? 1 : 0;

    case NXE_JWX_ALG_FAMILY_EDDSA:
        return (pkey_id == EVP_PKEY_ED25519 || pkey_id == EVP_PKEY_ED448)
            ? 1 : 0;

#if (NXE_JWX_HAVE_HMAC)
    case NXE_JWX_ALG_FAMILY_HMAC:
        /* HMAC does not use an EVP_PKEY; handled before this point. */
        return 0;
#endif
    }

    return 0;
}


/*
 * Validate that `claims` parses as a JSON object.  This keeps the
 * issuing path fail-closed: a malformed or non-object payload is
 * refused instead of being base64url-wrapped into a structurally
 * broken token.
 */
static ngx_int_t
nxe_jwx_validate_claims_object(const ngx_str_t *claims, ngx_pool_t *pool)
{
    nxe_json_t *json;
    ngx_str_t input;

    input.data = claims->data;
    input.len = claims->len;

    json = nxe_json_parse_untrusted(&input, pool);
    if (json == NULL) {
        return NGX_ERROR;
    }
    if (nxe_json_type(json) != NXE_JSON_OBJECT) {
        nxe_json_free(json);
        return NGX_ERROR;
    }
    nxe_json_free(json);
    return NGX_OK;
}


/*
 * Build the JWS protected header JSON:
 *
 *     {"alg":"<name>","typ":"JWT"}
 *
 * with an optional ,"kid":<escaped> inserted before the closing brace.
 * `alg_name` comes from the trusted algorithm table (safe ASCII, no
 * escaping needed); the kid is JSON-escaped via nxe-json so an
 * operator-supplied value cannot inject extra header parameters.
 */
static ngx_int_t
nxe_jwx_build_header(const char *alg_name, const ngx_str_t *kid,
    ngx_str_t *header, ngx_pool_t *pool)
{
    static const char start[] = "{\"alg\":\"";
    static const char mid[] = "\",\"typ\":\"JWT\"";
    static const char kidkey[] = ",\"kid\":";
    static const char end[] = "}";

    size_t alg_len = ngx_strlen(alg_name);
    ngx_str_t *kid_quoted = NULL;
    size_t total;
    u_char *p;

    if (kid != NULL && kid->len > 0) {
        nxe_json_t *node;
        ngx_str_t kid_mut;

        kid_mut.data = kid->data;
        kid_mut.len = kid->len;

        /*
         * nxe_json_from_string + stringify_compact yields the kid as a
         * properly JSON-escaped, double-quoted string ("...") that we
         * splice in verbatim after the "kid": key.
         */
        node = nxe_json_from_string(&kid_mut);
        if (node == NULL) {
            return NGX_ERROR;
        }
        kid_quoted = nxe_json_stringify_compact(node, pool);
        nxe_json_free(node);
        if (kid_quoted == NULL) {
            return NGX_ERROR;
        }
    }

    total = sizeof(start) - 1 + alg_len + sizeof(mid) - 1 + sizeof(end) - 1;
    if (kid_quoted != NULL) {
        total += sizeof(kidkey) - 1 + kid_quoted->len;
    }

    header->data = ngx_pnalloc(pool, total);
    if (header->data == NULL) {
        return NGX_ERROR;
    }
    p = header->data;
    ngx_memcpy(p, start, sizeof(start) - 1); p += sizeof(start) - 1;
    ngx_memcpy(p, alg_name, alg_len); p += alg_len;
    ngx_memcpy(p, mid, sizeof(mid) - 1); p += sizeof(mid) - 1;
    if (kid_quoted != NULL) {
        ngx_memcpy(p, kidkey, sizeof(kidkey) - 1); p += sizeof(kidkey) - 1;
        ngx_memcpy(p, kid_quoted->data, kid_quoted->len);
        p += kid_quoted->len;
    }
    ngx_memcpy(p, end, sizeof(end) - 1); p += sizeof(end) - 1;
    header->len = (size_t) (p - header->data);

    return NGX_OK;
}


ngx_int_t
nxe_jwx_encode(ngx_pool_t *pool, const ngx_str_t *alg, const ngx_str_t *kid,
    const ngx_str_t *claims, const ngx_str_t *key, ngx_str_t *out)
{
    const nxe_jwx_alg_t *a;
    ngx_log_t *log;
    ngx_str_t header_json, header_b64, payload_b64, signing_input;
    ngx_str_t sig_raw = { 0, NULL };
    ngx_str_t sig_b64;
    EVP_PKEY *pkey = NULL;
    ngx_int_t rc = NGX_ERROR;
    u_char *p;

    if (pool == NULL || alg == NULL || claims == NULL || key == NULL
        || out == NULL
        || alg->len == 0 || claims->len == 0 || key->len == 0)
    {
        return NGX_ERROR;
    }
    log = nxe_jwx_log(pool);

    out->data = NULL;
    out->len = 0;

    if (claims->len > NXE_JWX_MAX_JWT_SIZE) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "nxe_jwx: encode claims exceed %ui bytes",
                      (ngx_uint_t) NXE_JWX_MAX_JWT_SIZE);
        return NGX_ERROR;
    }

    /* Reject "none" before any other policy check, regardless of build
     * flags (mirrors the verify side). */
    if (alg->len == 4 && ngx_strncmp(alg->data, "none", 4) == 0) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "nxe_jwx: 'none' algorithm rejected for encode");
        return NGX_ERROR;
    }

    a = nxe_jwx_lookup_alg(alg);
    if (a == NULL) {
        /* Unsupported alg, including HS* when HMAC is disabled at
         * compile time. */
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "nxe_jwx: encode alg \"%V\" is not supported", alg);
        return NGX_ERROR;
    }

    if (nxe_jwx_validate_claims_object(claims, pool) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "nxe_jwx: encode claims are not a JSON object");
        return NGX_ERROR;
    }

    if (nxe_jwx_build_header(a->name, kid, &header_json, pool) != NGX_OK) {
        return NGX_ERROR;
    }

    if (nxe_jwx_encode_b64url(&header_b64, &header_json, pool) != NGX_OK
        || nxe_jwx_encode_b64url(&payload_b64, claims, pool) != NGX_OK)
    {
        return NGX_ERROR;
    }

    /*
     * Mirror the decode side: the encoded header segment must fit within
     * NXE_JWX_MAX_JWT_HEADER, otherwise nxe_jwx_decode() would reject the
     * token we are about to emit (a large kid can push it over the limit).
     */
    if (header_b64.len > NXE_JWX_MAX_JWT_HEADER) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "nxe_jwx: encode header segment exceeds %ui bytes",
                      (ngx_uint_t) NXE_JWX_MAX_JWT_HEADER);
        return NGX_ERROR;
    }

    /* signing_input = header_b64 "." payload_b64 */
    signing_input.len = header_b64.len + 1 + payload_b64.len;
    signing_input.data = ngx_pnalloc(pool, signing_input.len);
    if (signing_input.data == NULL) {
        return NGX_ERROR;
    }
    p = signing_input.data;
    ngx_memcpy(p, header_b64.data, header_b64.len); p += header_b64.len;
    *p++ = '.';
    ngx_memcpy(p, payload_b64.data, payload_b64.len);

    /* Produce the raw signature bytes for the algorithm family. */
    switch (a->family) {

#if (NXE_JWX_HAVE_HMAC)
    case NXE_JWX_ALG_FAMILY_HMAC:
        if (nxe_jwx_hmac_sign(key, a->digest, &signing_input, &sig_raw, pool)
            != NGX_OK)
        {
            goto out;
        }
        break;
#endif

    case NXE_JWX_ALG_FAMILY_ECDSA:
    {
        ngx_str_t der;

        pkey = nxe_jwx_load_pem_privkey(key);
        if (pkey == NULL || !nxe_jwx_privkey_compatible(pkey, a)) {
            goto out;
        }
        if (nxe_jwx_evp_sign(pkey, a->digest, &signing_input, 0, &der, pool)
            != NGX_OK)
        {
            goto out;
        }
        if (nxe_jwx_ecdsa_der_to_raw(&der, a->ec_coord_len, &sig_raw, pool)
            != NGX_OK)
        {
            goto out;
        }
        break;
    }

    case NXE_JWX_ALG_FAMILY_RSA:
    case NXE_JWX_ALG_FAMILY_RSA_PSS:
    case NXE_JWX_ALG_FAMILY_EDDSA:
        pkey = nxe_jwx_load_pem_privkey(key);
        if (pkey == NULL || !nxe_jwx_privkey_compatible(pkey, a)) {
            goto out;
        }
        if (nxe_jwx_evp_sign(pkey, a->digest, &signing_input,
                             a->family == NXE_JWX_ALG_FAMILY_RSA_PSS,
                             &sig_raw, pool) != NGX_OK)
        {
            goto out;
        }
        break;

    default:
        goto out;
    }

    if (nxe_jwx_encode_b64url(&sig_b64, &sig_raw, pool) != NGX_OK) {
        goto out;
    }

    /* out = signing_input "." sig_b64, NUL-terminated. */
    out->len = signing_input.len + 1 + sig_b64.len;

    /*
     * Mirror the decode side: the final compact token must fit within
     * NXE_JWX_MAX_JWT_SIZE.  base64url expansion plus the signature
     * segment can push a claims-sized payload over the limit, so check
     * the assembled length before allocating the output buffer.
     */
    if (out->len > NXE_JWX_MAX_JWT_SIZE) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "nxe_jwx: encode token exceeds %ui bytes",
                      (ngx_uint_t) NXE_JWX_MAX_JWT_SIZE);
        out->len = 0;
        goto out;
    }

    out->data = ngx_pnalloc(pool, out->len + 1);
    if (out->data == NULL) {
        out->len = 0;
        goto out;
    }
    p = out->data;
    ngx_memcpy(p, signing_input.data, signing_input.len);
    p += signing_input.len;
    *p++ = '.';
    ngx_memcpy(p, sig_b64.data, sig_b64.len); p += sig_b64.len;
    *p = '\0';

    rc = NGX_OK;

out:
    if (pkey != NULL) {
        EVP_PKEY_free(pkey);
    }
    if (rc != NGX_OK) {
        out->data = NULL;
        out->len = 0;
    }
    return rc;
}
