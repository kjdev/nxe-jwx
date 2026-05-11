# Changelog

## [9c041dc](../../commit/9c041dc) - 2026-05-11

### Fixed

- Drop the PEM -> HMAC fallback from
  `nxe_jwx_jwks_parse_keyval()` to close a PEM/HMAC
  algorithm-confusion vector
  - Until now, a value that failed PEM parsing was silently
    stored as a raw oct/HMAC secret when `NXE_JWX_HAVE_HMAC`
    was enabled. Because public PEM text is itself public,
    any typo in the operator's configured PEM would let an
    attacker compute
    `HMAC(<PEM text>, "<header_b64>.<payload_b64>")` and
    forge a JWT that verifies against the silently generated
    oct key -- a configuration-time variant of the classic
    RSA/EC -> HS* algorithm-confusion attack
  - keyval is now restricted to PEM public keys
    (RSA / EC / OKP). A non-PEM value logs a warning and is
    skipped, regardless of `NXE_JWX_HAVE_HMAC`
  - HMAC (oct) secrets must be supplied via a proper JWKS
    document with `kty: "oct"` entries; that path already
    validates the secret as a JWK field rather than as
    opaque bytes

## [ac6d2b3](../../commit/ac6d2b3) - 2026-05-11

### Changed

- Reject JWKS entries that declare `"kid"` with an empty string
  - Mirror the keyval-side guard inside `nxe_jwx_parse_one_jwk`: a
    JWK with an explicitly empty `kid` now logs a WARN and returns
    `NGX_DECLINED` instead of registering as a kid-less key
  - Omitting `kid` entirely (RFC 7517 leaves it optional) is still
    accepted as a kid-less key, so the change only fires when the
    field is present but empty -- the case that would otherwise
    silently slip into the kid-less fallback candidates at
    verification time

## [0a508d6](../../commit/0a508d6) - 2026-05-11

### Changed

- Replace byte-length-based RSA modulus check with a
  `BN_num_bits`-based range check gated by `NXE_JWX_MIN_RSA_BITS` /
  `NXE_JWX_MAX_RSA_BITS` (default 2048..16384 bits)
  - An over-large modulus would otherwise bound the cost of
    subsequent `EVP_DigestVerify` calls only via the document size
    limit, leaving room for a slow-verify DoS within a single JWKS
    payload
- Skip keyval entries whose JSON key is the empty string with a
  warning
  - Such entries are almost always a configuration mistake and
    would otherwise become silent kid-less fallback candidates at
    verification time

## [c4004a9](../../commit/c4004a9) - 2026-05-11

### Changed

- Three independent fail-closed tightenings, all driven by an
  existing test from nginx-auth-gate that the looser semantics
  could not satisfy without re-introducing key-confusion vectors:
  - JWK `use="enc"` entries are skipped at parse time. Encryption
    keys are not eligible for signature verification, full stop;
    a JWKS that contains only encryption keys yields zero usable
    signing keys and `parse()` returns NULL
  - JWK `alg` pinning. When a JWK supplies an `alg` parameter, the
    verifier requires the token's `alg` to match that value
    byte-for-byte. An RS256 token never validates against a JWK
    declaring `alg=RS384` even though the underlying RSA key could
    sign either
  - Tighter kid-strict. When the token names a `kid` and the
    keyset contains other kid-labelled keys but no matching one,
    the verifier no longer falls through to those other-kid keys;
    the second pass is restricted to kid-less keys. This blocks
    "token claims kid A, key labelled kid B happens to verify"
    attacks
- The kid-less fallback is preserved for keysets that mix labelled
  and unlabelled keys; that is the legitimate "operator hasn't
  labelled their JWKS" use case

## [82602d0](../../commit/82602d0) - 2026-05-11

### Added

- `nxe_jwx_jwks_has_kid(jwks, kid)` membership check
  - Lets callers disambiguate between "kid not in JWKS" and "kid
    in JWKS but signature failed" when `nxe_jwx_jws_verify()`
    returns `NGX_DECLINED`. Both cases collapse into the same
    return value (oracle-resistant) so the verifier itself never
    reveals the distinction; callers that log audit messages can
    pre-check this helper to decide whether to mention the kid by
    name
  - Required by nginx-auth-jwt's audit-log message which only
    names the kid when a kid-matched key was actually attempted

## [68f5d83](../../commit/68f5d83) - 2026-05-11

### Changed

- Enforce kid-strict signature verification
  - Verification was previously a two-pass walk: pass 1 tried any
    kid-matched keys, and pass 2 then tried every other compatible
    key. A signature failure on a kid-matched key fell through to
    pass 2, which lets a forged token signed with a different (but
    compatible) key in the same JWKS verify successfully -- a
    key-confusion failure mode that operators rarely intend when
    they label keys with kids
  - The verifier now treats a kid match as authoritative. If at
    least one key in the JWKS carries the token's `kid`, only those
    keys are tried; failure on all of them returns `NGX_DECLINED`.
    Pass 2 (walk-all-compatible) still runs when the kid is absent
    from the JWKS or when the token has no kid, preserving
    compatibility with keysets that don't label keys
  - Public behaviour change: tokens that previously verified by
    accident against a non-kid-matched key are now rejected.
    Callers that genuinely need the looser semantics should issue
    tokens without a kid

## [e5815df](../../commit/e5815df) - 2026-05-11

### Changed

- Accept tokens with an empty signature segment in the decoder
  - The decoder previously rejected any token whose third
    (signature) segment was empty, which prevented callers from
    extracting claims from unsigned (`alg=none`) tokens that
    originate from a trusted upstream that has already done the
    verification. Header and payload must still be non-empty
  - The verifier now refuses such tokens up front with
    `NGX_DECLINED` before walking the keyset, so the relaxation
    does not weaken signature-based authentication: `alg=none` was
    already rejected unconditionally, and an empty signature can
    never match any key
  - Required by nginx-auth-gate's `auth_gate_jwt` directive, which
    extracts claims from upstream-issued tokens without
    re-verifying them

## [00a121d](../../commit/00a121d) - 2026-05-11

### Changed

- `nxe_jwx_jwks_parse_keyval()` now walks the document with the
  new `nxe_json_object_iter*` API and produces one key per kid.
  Each value is interpreted in this order:
  - PEM-encoded public key (RSA / EC / OKP). The key type is taken
    from the underlying `EVP_PKEY`
  - With `NXE_JWX_HAVE_HMAC`, an opaque `oct` (HMAC) secret stored
    verbatim and cleansed via `OPENSSL_cleanse` at pool teardown.
    No base64url decoding is performed; the bytes are the secret
  - Otherwise the entry is skipped with a warning
- Drops the v1 single-key shortcut that only accepted
  `{"k": "<PEM>"}`. The same shape now works as a one-entry
  multi-kid document with `kid="k"`, so existing operators see no
  behavioural change
- Required by nginx-auth-jwt's `auth_jwt_keyval` directive, where
  the canonical fixture `{"<kid>": "<secret>"}` could not be
  expressed in the v1 shape

## [650fdc6](../../commit/650fdc6) - 2026-05-11

### Added

- `nxe_jwx_jws_verify` reads `alg` / `kid` from the decoded token,
  looks the algorithm up in a static table, and walks the keyset
  twice: once for keys whose `kid` matches the token (when the
  token has a kid) and once for every kty/alg-compatible key. The
  first key that produces a verified signature wins
- Per-family handling:
  - RSA / RSA-PSS use `EVP_DigestVerifyInit` with the RSA padding,
    `saltlen=DIGEST`, and `MGF1=hash` configured on the PKEY
    context
  - ECDSA converts the JWT R||S signature into DER through
    `ECDSA_SIG_set0` + `i2d_ECDSA_SIG` so `EVP_DigestVerify`
    accepts it, and confirms the key uses the curve named by the
    alg (`EVP_PKEY_get_group_name` on 3.0+, `OBJ_nid2sn` on 1.1.x)
  - EdDSA uses `EVP_DigestVerify` with a NULL md
  - HMAC (`NXE_JWX_HAVE_HMAC` only) computes the MAC and compares
    with `CRYPTO_memcmp` for a constant-time check
- Algorithm policy is fail-closed: `none` is rejected
  unconditionally, unknown algorithms (including HS* in default
  builds) collapse into `NGX_DECLINED` so the caller cannot
  distinguish "policy rejection" from "signature did not verify."
  An internal failure (allocation, OpenSSL setup) is also returned
  as `NGX_DECLINED` at the API boundary but logged at
  `NGX_LOG_ERR` so operators can see it

## [5a35b06](../../commit/5a35b06) - 2026-05-11

### Added

- `nxe_jwx_jwks_parse` walks `{"keys":[...]}` via
  `nxe_json_parse_untrusted` and turns each JWK into an `EVP_PKEY`
  through one of three builders:
  - RSA: `BN_bin2bn` on `n` / `e`, then `EVP_PKEY_fromdata` (3.0+)
    or `EVP_PKEY_assign_RSA` (1.1.x). Modulus shorter than
    `NXE_JWX_MIN_RSA_BITS` is rejected
  - EC: looks up the curve in a static table (P-256/P-384/P-521,
    secp256k1), validates `x`/`y` lengths, assembles the SEC1
    uncompressed point, and feeds it to either `OSSL_PARAM_BLD` or
    `EC_KEY_oct2key` depending on the OpenSSL version
  - OKP: relies on `EVP_PKEY_new_raw_public_key`, which is
    available on both 1.1.1+ and 3.0+ so no version split is
    needed
- `oct` keys (HMAC) are gated behind `NXE_JWX_HAVE_HMAC` so the
  default build does not pull in symmetric-secret handling
- The whole keyset is bounded by `NXE_JWX_MAX_JWKS_SIZE` / `KEYS`.
  Per-JWK failures split into two policies:
  - Skipped with a warning (the whole document still parses):
    unsupported `kty`, unsupported `crv`, missing or wrong-length
    fields, explicit empty `kid`, `use="enc"`
  - Hard error that aborts the document (returns NULL): base64url
    decoding failure, allocation failure, or any other internal
    OpenSSL error inside a JWK. A document that yields zero usable
    keys after the skip pass is also rejected outright
- A pool cleanup handler frees every `EVP_PKEY` (and
  `OPENSSL_cleanse`-s each `oct` secret) when the pool is
  destroyed, so the caller never needs an explicit `jwks_free`
- `nxe_jwx_jwks_parse_keyval` covers nginx-auth-jwt's
  `auth_jwt_keyval` shape. The current cut handles the common
  single-key form `{"k": "<PEM>"}` only; multi-kid keyval needs an
  object iterator on the nxe-json side and is intentionally
  deferred

## [8ccb583](../../commit/8ccb583) - 2026-04-27

### Added

- Five typed claim accessors (string / integer / boolean / array /
  object) collapsing the look-up + type-check + extract dance into
  a single `ngx_int_t` return:
  - `NGX_OK` -- the claim is present and of the requested type;
    `*out` has been populated
  - `NGX_DECLINED` -- the claim is missing
  - `NGX_ERROR` -- the claim is present but of the wrong type, or
    an argument is NULL
- Strings come back as zero-copy views into the parsed JSON;
  arrays and objects come back as borrowed `nxe_json_t` references
  so the caller can drill further with `nxe_json_object_get` /
  `array_get` without an extra copy
- Intentionally narrow: registered-claim validation
  (`iss` / `aud` / `exp` / `iat` / `nbf`) is left to the upstream
  modules because each one tolerates clock skew and multi-aud
  differently

## [8e644c6](../../commit/8e644c6) - 2026-04-27

### Added

- `nxe_jwx_decode` splits the token on the two `.` separators
  (rejecting JWE-shaped four-segment inputs and any empty
  segment), base64url-decodes header and payload through
  `ngx_decode_base64url`, parses both as JSON via
  `nxe_json_parse_untrusted`, and stashes the raw signature plus
  the verbatim `header_b64.payload_b64` signing input on the
  returned token
- `alg` and `kid` are extracted from the parsed header and exposed
  through dedicated accessors so callers can drive policy without
  re-walking the JSON
- The token structure is allocated on the caller's pool and a
  cleanup handler runs `nxe_json_free` on the JSON nodes and
  `OPENSSL_cleanse` on the signing input / signature buffers when
  the pool is destroyed. The cleanup is registered before any of
  the b64url / parse work so that partial state is reclaimed
  deterministically on failure
- Tokens above `NXE_JWX_MAX_JWT_SIZE` and headers above
  `NXE_JWX_MAX_JWT_HEADER` are rejected before decoding starts

## [0109e11](../../commit/0109e11) - 2026-04-27

### Added

- Initial public API surface and shared internal declarations,
  landed up front so each subsystem implementation that follows
  can be reviewed in isolation
  - `nxe_jwx.h` aggregates the four subsystem headers, declares
    the opaque token / jwks types, and pins the DoS limits shared
    with the upstream modules (16 KiB JWT, 256 KiB JWKS, 64 keys,
    2048-bit RSA minimum)
  - `nxe_jwx_decode.h`, `nxe_jwx_jwks.h`, `nxe_jwx_jws.h`,
    `nxe_jwx_claims.h` cover decoding, key-set parsing, signature
    verification, and typed claim accessors respectively. All
    accessors return `ngx_int_t` with `NGX_OK` / `NGX_DECLINED` /
    `NGX_ERROR` semantics so callers can collapse the
    auth-failure family into one branch
  - `nxe_jwx_internal.h` exposes the cross-TU pieces (log helper,
    signing-input / signature accessors on the token, the kty
    enum and key struct walked by the verifier) without leaking
    any of it through the public surface
