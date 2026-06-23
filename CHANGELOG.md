# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Add `nxe_jwx_encode()` for signed JWT (JWS) issuing
  - The library could only decode and verify tokens; relying-party
    modules that mint their own session JWTs (e.g. nginx-auth-webauthn
    issuing a session JWT after assertion verification) had no shared
    issuing path and would have re-implemented JWS signing
  - The encoder is the symmetric counterpart of `nxe_jwx_jws_verify()`:
    it reuses the algorithm table, the EC curve check, and the ECDSA
    conversion (now also the inverse, DER -> fixed-width `R||S`), so the
    issuing and verifying policies cannot drift apart
  - Supports `HS*` (with `NXE_JWX_HAVE_HMAC`), `RS*`, `PS*`,
    `ES256/384/512/ES256K`, and `EdDSA`; `none` is rejected
    unconditionally, regardless of build flags
  - The payload is taken as a caller-serialised compact JSON object and
    used verbatim (nxe-json has no object-building API); the encoder
    checks it parses as an object and JSON-escapes the optional `kid` so
    it cannot inject extra header parameters
  - `out` is pool-allocated and NUL-terminated, matching the
    token-string contract; because issuing is operator-driven, every
    failure collapses to `NGX_ERROR` (no oracle)

### Fixed

- Enforce decode size limits on `nxe_jwx_encode()` output
  - The claims guard only bounded the raw `claims->len`, so a large
    `kid`, base64url expansion, and the appended signature could push the
    encoded header past `NXE_JWX_MAX_JWT_HEADER` or the final compact
    token past `NXE_JWX_MAX_JWT_SIZE`, making `nxe_jwx_encode()` emit a
    token that `nxe_jwx_decode()` rejects (asymmetric limits)
  - The encoder now mirrors the decoder: it checks the encoded header
    segment before signing and the assembled token length before
    allocation, both failing with `NGX_ERROR`

## [0.2.0] - 2026-06-01

### Added

- Add `nxe_jwx_jwks_free()` for explicit keyset release
  - Keysets previously freed their `EVP_PKEY` objects only via a pool
    cleanup handler, so a keyset on a long-lived pool that is not torn
    down on a predictable schedule (e.g. an nginx master-process pool
    surviving config reloads) leaked the key material on every reload
  - The new entry point releases the OpenSSL key material immediately
    and disarms the registered cleanup (`cln->handler = NULL`) so the
    eventual pool teardown does not double-free; the cleanup body is
    idempotent, so redundant calls and `NULL` are harmless

### Changed

- Document that `nxe_jwx_token_alg()` / `nxe_jwx_token_kid()` return
  NUL-terminated `data` as a public contract (no implementation change)
  - The returned `ngx_str_t` is retained verbatim from
    `nxe_json_string()`, so `data[len] == '\0'` is now an explicit,
    inherited guarantee from nxe-json 0.5.0's string contract
  - Callers may pass `data` directly to C string APIs (`strlen`,
    `ngx_strcmp`) when the claim has no embedded NUL bytes, removing
    the prior undefined-behavior risk in upstream consumers that cast
    `data` to `const char *`

## [0.1.0] - 2026-05-11

Initial release. The public API surface and the four subsystems
(decode / JWKS parse / JWS verify / claims) landed together.

### Added

#### Public API and internal declarations

- `nxe_jwx.h` aggregates the four subsystem headers, declares the
  opaque token / jwks types, and pins the DoS limits shared with the
  upstream modules (16 KiB JWT, 256 KiB JWKS, 64 keys, 2048-bit RSA
  minimum). All accessors return `ngx_int_t` with `NGX_OK` /
  `NGX_DECLINED` / `NGX_ERROR` semantics so callers can collapse the
  auth-failure family into one branch
- `nxe_jwx_internal.h` exposes the cross-TU pieces (log helper,
  signing-input / signature accessors on the token, the kty enum and
  key struct walked by the verifier) without leaking any of it through
  the public surface

#### JWT decoding

- `nxe_jwx_decode` splits the token on the two `.` separators
  (rejecting JWE-shaped four-segment inputs; header and payload must be
  non-empty), base64url-decodes header and payload through
  `ngx_decode_base64url`, parses both as JSON via
  `nxe_json_parse_untrusted`, and stashes the raw signature plus the
  verbatim `header_b64.payload_b64` signing input on the returned token
- An empty signature segment is accepted so callers can extract claims
  from unsigned (`alg=none`) tokens that originate from a trusted
  upstream that has already verified them; `nxe_jwx_jws_verify()`
  refuses such tokens up front with `NGX_DECLINED`, so the relaxation
  never weakens signature-based authentication (required by
  nginx-auth-gate's `auth_gate_jwt` directive)
- `alg` and `kid` are extracted from the parsed header and exposed
  through dedicated accessors so callers can drive policy without
  re-walking the JSON
- The token structure is allocated on the caller's pool and a cleanup
  handler runs `nxe_json_free` on the JSON nodes and `OPENSSL_cleanse`
  on the signing input / signature buffers when the pool is destroyed.
  The cleanup is registered before any of the b64url / parse work so
  that partial state is reclaimed deterministically on failure
- Tokens above `NXE_JWX_MAX_JWT_SIZE` and headers above
  `NXE_JWX_MAX_JWT_HEADER` are rejected before decoding starts

#### JWKS parsing

- `nxe_jwx_jwks_parse` walks `{"keys":[...]}` via
  `nxe_json_parse_untrusted` and turns each JWK into an `EVP_PKEY`
  through one of three builders:
  - RSA: `BN_bin2bn` on `n` / `e`, then `EVP_PKEY_fromdata` (3.0+) or
    `EVP_PKEY_assign_RSA` (1.1.x). The modulus is range-checked with
    `BN_num_bits` against `NXE_JWX_MIN_RSA_BITS` /
    `NXE_JWX_MAX_RSA_BITS` (default 2048..16384 bits) so an over-large
    modulus cannot mount a slow-verify DoS bounded only by the document
    size limit
  - EC: looks up the curve in a static table (P-256/P-384/P-521,
    secp256k1), validates `x`/`y` lengths, assembles the SEC1
    uncompressed point, and feeds it to either `OSSL_PARAM_BLD` or
    `EC_KEY_oct2key` depending on the OpenSSL version
  - OKP: relies on `EVP_PKEY_new_raw_public_key`, available on both
    1.1.1+ and 3.0+ so no version split is needed
- `oct` keys (HMAC) are gated behind `NXE_JWX_HAVE_HMAC` so the default
  build does not pull in symmetric-secret handling
- The whole keyset is bounded by `NXE_JWX_MAX_JWKS_SIZE` / `KEYS`.
  Per-JWK failures split into two policies:
  - Skipped with a warning (the whole document still parses):
    unsupported `kty`, unsupported `crv`, missing or wrong-length
    fields, explicit empty `kid`, `use="enc"`
  - Hard error that aborts the document (returns NULL): base64url
    decoding failure, allocation failure, or any other internal
    OpenSSL error inside a JWK. A document that yields zero usable keys
    after the skip pass is also rejected outright
- Fail-closed key-selection policy, hardened against key-confusion:
  - `use="enc"` entries are skipped at parse time — encryption keys are
    not eligible for signature verification, so a JWKS that contains
    only encryption keys yields zero usable signing keys
  - `alg` pinning: when a JWK supplies an `alg` parameter, the verifier
    requires the token's `alg` to match it byte-for-byte. An RS256
    token never validates against a JWK declaring `alg=RS384` even
    though the underlying RSA key could sign either
  - kid-strict verification: if at least one key in the JWKS carries
    the token's `kid`, only those keys are tried and failure on all of
    them returns `NGX_DECLINED`; the verifier never falls through to
    other-kid keys. The walk-all-compatible pass runs only when the
    token has no `kid` or the `kid` is absent from the JWKS, preserving
    the kid-less fallback for keysets that mix labelled and unlabelled
    keys
  - A JWK that declares an explicitly empty `kid` is rejected (WARN +
    `NGX_DECLINED`) rather than registering as a kid-less key; omitting
    `kid` entirely (RFC 7517 leaves it optional) is still accepted
- A pool cleanup handler frees every `EVP_PKEY` (and
  `OPENSSL_cleanse`-s each `oct` secret) when the pool is destroyed, so
  the caller never needs an explicit `jwks_free`
- `nxe_jwx_jwks_parse_keyval` covers nginx-auth-jwt's `auth_jwt_keyval`
  shape: it walks the document with `nxe_json_object_iter*` and
  produces one key per kid. Each value is interpreted in this order:
  - PEM-encoded public key (RSA / EC / OKP); the key type is taken from
    the underlying `EVP_PKEY`
  - With `NXE_JWX_HAVE_HMAC`, an opaque `oct` (HMAC) secret stored
    verbatim and cleansed via `OPENSSL_cleanse` at pool teardown — no
    base64url decoding is performed; the bytes are the secret
  - Otherwise the entry is skipped with a warning. A non-PEM value is
    skipped regardless of `NXE_JWX_HAVE_HMAC`, closing a PEM/HMAC
    algorithm-confusion vector: because public PEM text is itself
    public, allowing it to be stored as an HMAC secret would let an
    attacker forge a token via `HMAC(<PEM text>, "<header>.<payload>")`.
    Entries whose JSON key is the empty string are skipped with a
    warning. The canonical `{"<kid>": "<secret>"}` fixture and the
    single `{"k": "<PEM>"}` form are both expressed as multi-kid
    documents
- `nxe_jwx_jwks_has_kid(jwks, kid)` lets callers disambiguate "kid not
  in JWKS" from "kid in JWKS but signature failed" when
  `nxe_jwx_jws_verify()` returns `NGX_DECLINED`. The verifier itself
  never reveals the distinction (oracle-resistant); callers that log
  audit messages can pre-check this helper to decide whether to mention
  the kid by name. Required by nginx-auth-jwt's audit-log message

#### JWS verification

- `nxe_jwx_jws_verify` reads `alg` / `kid` from the decoded token,
  looks the algorithm up in a static table, and selects keys per the
  kid-strict / `alg`-pinning policy above. The first key that produces
  a verified signature wins
- Per-family handling:
  - RSA / RSA-PSS use `EVP_DigestVerifyInit` with the RSA padding,
    `saltlen=DIGEST`, and `MGF1=hash` configured on the PKEY context
  - ECDSA converts the JWT R||S signature into DER through
    `ECDSA_SIG_set0` + `i2d_ECDSA_SIG` so `EVP_DigestVerify` accepts
    it, and confirms the key uses the curve named by the alg
    (`EVP_PKEY_get_group_name` on 3.0+, `OBJ_nid2sn` on 1.1.x)
  - EdDSA uses `EVP_DigestVerify` with a NULL md
  - HMAC (`NXE_JWX_HAVE_HMAC` only) computes the MAC and compares with
    `CRYPTO_memcmp` for a constant-time check
- Algorithm policy is fail-closed: `none` is rejected unconditionally,
  unknown algorithms (including HS* in default builds) collapse into
  `NGX_DECLINED` so the caller cannot distinguish "policy rejection"
  from "signature did not verify." An internal failure (allocation,
  OpenSSL setup) is also returned as `NGX_DECLINED` at the API boundary
  but logged at `NGX_LOG_ERR` so operators can see it

#### Claims accessors

- Five typed claim accessors (string / integer / boolean / array /
  object) collapsing the look-up + type-check + extract dance into a
  single `ngx_int_t` return:
  - `NGX_OK` — the claim is present and of the requested type; `*out`
    has been populated
  - `NGX_DECLINED` — the claim is missing
  - `NGX_ERROR` — the claim is present but of the wrong type, or an
    argument is NULL
- Strings come back as zero-copy views into the parsed JSON; arrays and
  objects come back as borrowed `nxe_json_t` references so the caller
  can drill further with `nxe_json_object_get` / `array_get` without an
  extra copy
- Intentionally narrow: registered-claim validation
  (`iss` / `aud` / `exp` / `iat` / `nbf`) is left to the upstream
  modules because each one tolerates clock skew and multi-aud
  differently
