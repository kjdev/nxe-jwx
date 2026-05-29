# nxe-jwx

JWT / JWS / JWKS library for nginx modules
(NginX Extension JWX Library), distributed as a git submodule.

## Features

- JWT decode (header / payload / signature) with DoS guards
- JWS signature verification:
  - RSA: `RS256` / `RS384` / `RS512`
  - RSA-PSS: `PS256` / `PS384` / `PS512`
  - ECDSA: `ES256` / `ES384` / `ES512` / `ES256K`
  - EdDSA: `Ed25519`, `Ed448`
  - HMAC: `HS256` / `HS384` / `HS512` (optional, `NXE_JWX_HAVE_HMAC`)
  - `none` is always rejected
- JWKS parsing (RSA / EC / OKP / `oct` optional) for both
  OpenSSL 1.1.x and 3.0+
- Keyval shortcut (multi-kid) for compatibility with nginx-auth-jwt
- Typed claim accessors (string / integer / boolean / array / object)

## Public API

| Function | Description |
|----------|-------------|
| `nxe_jwx_decode` | Decode a JWT into an opaque token |
| `nxe_jwx_token_header` | Get the parsed header |
| `nxe_jwx_token_payload` | Get the parsed payload |
| `nxe_jwx_token_alg` | Get the `alg` header value |
| `nxe_jwx_token_kid` | Get the `kid` header value |
| `nxe_jwx_jwks_parse` | Parse a JWKS document |
| `nxe_jwx_jwks_parse_keyval` | Parse a keyval-style JSON map (`{"kid": "<PEM>", ...}`; PEM public keys only) |
| `nxe_jwx_jwks_count` | Number of usable keys in a keyset |
| `nxe_jwx_jws_verify` | Verify a token against a keyset |
| `nxe_jwx_claims_get_*` | Typed accessors for top-level claims |

`nxe_jwx_token_alg` / `nxe_jwx_token_kid` return a pointer whose
`data` is NUL-terminated (`data[len] == '\0'`, inherited from
nxe-json's `nxe_json_string` contract); `len` excludes the terminator.
Callers may pass `data` directly to C string APIs (`strlen`,
`ngx_strcmp`) when the claim has no embedded NUL bytes.

The library does **not** validate registered claims (`iss` / `aud` /
`exp` / `iat` / `nbf` / `jti`); each upstream module enforces its own
policy.

## Verification policy

`nxe_jwx_jws_verify` is fail-closed by design:

- `none` is always rejected, regardless of build flags.
- An empty signature is rejected before any key lookup.
- `kid` is honored strictly.  If the token carries a `kid`, only
  matching keys are tried; verification never falls through to keys
  with a different `kid`, even when `kty` / `alg` would otherwise be
  compatible.  When no key matches the `kid`, the second pass is
  restricted to keys that have no `kid` of their own.
- A JWK that declares `alg` is pinned to that algorithm — if the
  token's `alg` does not match, the key is skipped.  This prevents
  key-confusion across algorithm families.
- JWKS entries with `use="enc"` are dropped at parse time so that
  encryption keys cannot be used for signature verification.
- RSA keys whose modulus falls outside `[NXE_JWX_MIN_RSA_BITS,
  NXE_JWX_MAX_RSA_BITS]` (default 2048…16384 bits) are rejected at
  parse time: too small to be secure, too large to bound the cost of
  subsequent signature verifications.
- Entries that declare an empty `kid` are rejected at parse time on
  both ingest paths: a JWK with `"kid": ""` in a JWKS document and a
  keyval map whose key is the empty string `""`.  An empty `kid` is
  almost always a configuration mistake and would otherwise become a
  silent kid-less fallback candidate at verification time.  Omitting
  the `kid` field entirely is still permitted (RFC 7517 leaves it
  optional) and produces a kid-less key as before.
- All failures (no usable key, signature mismatch, `alg` mismatch,
  `kid` miss, ...) collapse to `NGX_DECLINED`; callers cannot tell
  which check rejected the token, denying an oracle to attackers.

## Known limitations

- JWT header / payload claim strings (e.g. `sub`, `email`) survive
  inside the JSON parser's internal buffers until the surrounding
  `ngx_pool_t` is destroyed.  The raw segment buffers and the keyset
  itself are explicitly cleansed via `OPENSSL_cleanse`, but the
  jansson-internal copy is released by `nxe_json_free` without a
  cleanse step.  This is a deliberate design boundary: callers
  handling sensitive PII are expected to keep the JWT pool
  short-lived so the entire allocation goes away with it.

## Integration

In the consumer module's `config`, source `nxe-json` first, then
`nxe-jwx`:

```sh
nxe_json_dir="$ngx_addon_dir/nxe-json"
. "$nxe_json_dir/config.ngx"

nxe_jwx_dir="$ngx_addon_dir/nxe-jwx"
. "$nxe_jwx_dir/config.ngx"

ngx_module_deps="\
  $nxe_json_module_deps \
  $nxe_jwx_module_deps \
  ...
"
ngx_module_srcs="\
  $nxe_json_module_srcs \
  $nxe_jwx_module_srcs \
  ...
"
ngx_module_libs="$nxe_json_module_libs $nxe_jwx_module_libs ..."
ngx_module_incs="$nxe_jwx_module_incs ..."
```

`nxe-jwx` does not re-concatenate `$nxe_json_module_srcs` / `_libs`,
so they appear in the link line exactly once.

### Optional features

`HMAC` / `oct` keys are off by default.  To enable, define
`NXE_JWX_HAVE_HMAC=1` in the parent module's `CFLAGS`.

## Dependencies

| Library  | Required version | Notes |
|----------|------------------|-------|
| nxe-json | >= 0.3.0         | Provided by the parent module as a sibling submodule; the object iteration API (`nxe_json_object_size` / `nxe_json_object_iter*`) used by the multi-kid keyval parser landed in 0.3.0 |
| OpenSSL  | >= 1.1.1         | Both 1.1.x and 3.0+ are supported |
| jansson  | >= 2.14          | Transitive via nxe-json (`json_object_iter_key_len` requires 2.14) |

## Building and testing

nxe-jwx is not built standalone; it is compiled as part of the host
nginx module.  The unit test suite uses `tests/ngx_compat/` —
malloc-backed stubs of the nginx core types — so no nginx source tree
is required.  It does, however, need the `nxe-json` sources at
`tests/vendor/nxe-json`, which come from a test-only submodule pinned
to the supported minimum version (v0.3.0).  Initialise the submodule
once after cloning:

```sh
git submodule update --init --recursive
```

Then build and run the tests:

```sh
cd tests
make test                          # default build + run
make test-asan                     # AddressSanitizer
make test-cov                      # gcov summary over src/
NXE_JWX_TEST_VERBOSE=1 make test   # show stub log output
```

Production builds use the parent module's own `nxe-json` submodule;
the nested `tests/vendor/nxe-json` is consulted only by the unit
tests.

## License

See `LICENSE`.
