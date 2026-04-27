/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 *
 * nxe_jwx_jws.c - JWS signature verification
 *
 * Algorithm policy:
 *   - "none" is rejected unconditionally.
 *   - HS256/384/512 are rejected unless built with NXE_JWX_HAVE_HMAC.
 *
 * Key selection:
 *   - If the token has a kid, keys with a matching kid are tried first.
 *   - Then all keys whose kty/alg are compatible with the token's alg
 *     are tried.
 *   - The first key that produces a valid signature wins.
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
#include <openssl/rsa.h>

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
 * "Compatible" here means: the key type / curve will not cause
 * EVP_DigestVerify to error out for reasons unrelated to the
 * signature itself.
 */
static ngx_flag_t
nxe_jwx_key_compatible(const struct nxe_jwx_key_s *k,
    const nxe_jwx_alg_t *alg)
{
    int pkey_id;

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
    ngx_flag_t kid_matched_any = 0;

    if (kid != NULL && kid->len > 0) {
        for (i = 0; i < n; i++) {
            struct nxe_jwx_key_s *k = nxe_jwx_jwks_key_at(jwks, i);

            if (k == NULL || k->kid.len == 0) {
                continue;
            }
            if (!nxe_jwx_str_eq(kid, &k->kid)) {
                continue;
            }
            kid_matched_any = 1;
            int rc = nxe_jwx_verify_with_key(k, alg, signing_input,
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
     * Pass 2: walk all compatible keys.  Skipped when pass 1 already
     * tried at least one kid-matched key (kid-strict policy).
     */
    if (!kid_matched_any) {
        for (i = 0; i < n; i++) {
            struct nxe_jwx_key_s *k = nxe_jwx_jwks_key_at(jwks, i);

            if (k == NULL) {
                continue;
            }
            int rc = nxe_jwx_verify_with_key(k, alg, signing_input,
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
