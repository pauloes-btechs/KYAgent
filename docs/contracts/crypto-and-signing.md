# Cryptography & Signing Contract

All encodings are exact. Implementations (server, `src/sdk/agentSigner.ts`,
tests, third-party agents) MUST produce identical bytes.

Notation: `b64u(x)` = base64url **without padding** (RFC 4648 §5).
`sha256hex(x)` = lowercase hex SHA-256 of bytes `x`. Strings are UTF-8.
`\n` is a single LF (0x0A); no trailing newline.

## 1. Agent keys (Ed25519)

- Algorithm: Ed25519 (RFC 8032), pure (no pre-hash).
- `publicKey` on the wire: `b64u(raw 32-byte public key)` → exactly 43 chars,
  regex `^[A-Za-z0-9_-]{43}$`. Anything else ⇒ `VALIDATION_ERROR`.
- The server **never** receives or stores agent private keys.
- **Key thumbprint** (`keyThumbprint`, `cnf.jkt`): RFC 7638 thumbprint of the
  OKP JWK, i.e. `b64u(SHA-256(UTF8('{"crv":"Ed25519","kty":"OKP","x":"' + publicKey + '"}')))`.
- A public key may be registered to at most one agent ever (unique index), even
  after revocation.

In Node: `crypto.createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: publicKey }, format: 'jwk' })`
and `crypto.verify(null, data, publicKey, signatureBytes)`.

## 2. Proof of possession (agent registration)

```
message = "KYA-REGISTER-V1" + "\n" + operatorId + "\n" + publicKey
proofOfPossession = b64u(Ed25519.sign(agentPrivateKey, UTF8(message)))
```

`operatorId` is the id of the operator making the call (from its API key).
Invalid proof ⇒ `400 VALIDATION_ERROR` with `details[0].path = "/proofOfPossession"`.

## 3. Signed agent requests (`KYA-SIG-V1`)

### 3.1 Canonical context JSON

`canonicalJson(value)`:
- objects: keys sorted by UTF-16 code unit order (JS default `sort()`), emitted as
  `{"k":v,...}` with no whitespace;
- arrays: `[v,...]` in order, no whitespace;
- strings: `JSON.stringify` escaping;
- numbers: **integers only**, safe range `|n| <= 2^53-1`, decimal without exponent;
  non-integer numbers ⇒ `MALFORMED_REQUEST`;
- `true`, `false`, `null` literals.

`contextSha256 = sha256hex(UTF8(canonicalJson(context ?? {})))`.
Example: `{"currency":"USD","amount":1500}` → canonical `{"amount":1500,"currency":"USD"}`.

Python equivalent: `json.dumps(ctx, sort_keys=True, separators=(",", ":"), ensure_ascii=False)` (integers only).

### 3.2 Signing string

```
signingString =
  "KYA-SIG-V1"     + "\n" +
  agentId          + "\n" +
  audience         + "\n" +
  action           + "\n" +
  resource         + "\n" +     // "" if none
  contextSha256    + "\n" +
  String(timestamp)+ "\n" +     // unix seconds, base-10 integer
  nonce
signature = b64u(Ed25519.sign(agentPrivateKey, UTF8(signingString)))
```

No field may contain `\n` (enforced by schema regexes; `resource` pattern
`^[^\n\r]{0,256}$`).

### 3.3 Server verification of a signed request

1. Recompute `contextSha256` from `VerifyRequest.context`; it MUST equal
   `signedRequest.contextSha256`, and `VerifyRequest.agentId/action/resource`
   MUST equal the signed values (`resource` absent ≡ `""`). Mismatch ⇒ `MALFORMED_REQUEST`.
2. Timestamp window: `|nowSeconds - timestamp| <= KYA_SIGNATURE_MAX_SKEW_SECONDS` else `TIMESTAMP_OUT_OF_WINDOW`.
3. Rebuild the signing string from the **signed** fields and verify with the
   agent's registered key. Signature must decode to exactly 64 bytes. Failure ⇒ `SIGNATURE_INVALID`.
4. Nonce: `^[A-Za-z0-9_-]{16,128}$`. After the signature passes, atomically
   insert `{agentId, nonce, expiresAt: (timestamp + 2*skew)}` into `nonces`
   (unique on `agentId+nonce`). Duplicate ⇒ `NONCE_REPLAYED`. Nonces are never
   recorded for requests with invalid signatures (prevents nonce poisoning).

### 3.4 Test vector procedure

`test/vectors/sig-v1.json` (created by the implementation worker) MUST contain
at least one fixed seed/key, context, signing string, and expected signature,
and a test MUST assert both the SDK and the server reproduce it. Ed25519 is
deterministic, so fixed seeds give fixed signatures.

## 4. Server signing key and credentials (JWS)

- Server key: Ed25519, loaded from `KYA_SIGNING_PRIVATE_KEY` or
  `KYA_SIGNING_PRIVATE_KEY_FILE` (see `environment.md`). Never hardcoded,
  never logged, never returned.
- `kid` = `KYA_SIGNING_KEY_ID` if set, else the RFC 7638 thumbprint of the server public key.
- JWKS at `GET /.well-known/jwks.json`:
  `{"keys":[{"kty":"OKP","crv":"Ed25519","x":"<b64u>","kid":"<kid>","alg":"EdDSA","use":"sig"}]}`.

### 4.1 Credential format

Compact JWS (RFC 7515), header:

```json
{ "alg": "EdDSA", "typ": "kya-credential+jwt", "kid": "<kid>" }
```

Payload (`CredentialClaims` in `types.ts`):

```json
{
  "iss": "<KYA_ISSUER>",
  "sub": "agt_...",
  "aud": "biz_...",
  "iat": 1790000000,
  "nbf": 1790000000,
  "exp": 1790000900,
  "jti": "crd_...",
  "kya_operator": "op_...",
  "kya_grant": "grt_...",
  "kya_actions": ["payments:create"],
  "kya_constraints": { "maxAmount": 10000, "currency": "USD" },
  "cnf": { "jkt": "<agent keyThumbprint>" }
}
```

Issuance rules:
- Caller is the operator owning the agent; agent `active`; operator `verified`;
  grant `active`, unexpired, and `grant.agentId == agentId`. Otherwise
  `409 INVALID_STATE` (or `OPERATOR_NOT_VERIFIED`) / `404 NOT_FOUND`.
- `exp = min(iat + ttlSeconds, floor(grant.expiresAt))`.
  `ttlSeconds ∈ [60, KYA_CREDENTIAL_MAX_TTL_SECONDS]`, default `KYA_CREDENTIAL_DEFAULT_TTL_SECONDS`.
- `kya_actions` and `kya_constraints` are copied from the grant at issue time.
- A `credentials` record (status `active`) is persisted by `jti`; the JWS string itself is **not** persisted.

Verification rules (server): algorithm allow-list is exactly `["EdDSA"]`;
`typ` must match; `kid` must be the current server key; `iss` must equal
`KYA_ISSUER`. Use `jose.compactVerify` / `jwtVerify` with explicit
`algorithms`, `issuer`, `audience`, `typ`. Step order and reason codes per
ARCHITECTURE.md §3.

## 5. API keys

- Plaintext format: `"kya_" + keyId + "_" + secret` where `keyId` is the
  `key_...` id (30 chars) and `secret = b64u(32 random bytes)` (43 chars).
  Total length 78. Parse by fixed offsets, not by splitting on `_`.
- Stored: `secretHash = hex(HMAC-SHA256(key = pepper, msg = UTF8(secret)))`,
  where pepper comes from `KYA_API_KEY_PEPPER[_FILE]`. Plaintext never stored or logged.
- Authentication: parse → look up by `keyId` → `crypto.timingSafeEqual` on the
  hash → key `status == active` → owner exists and is not `suspended`/`rejected`
  (operator keys work while operator is `pending` so it can read its profile,
  but agent registration requires `verified`). Any failure ⇒ `401 UNAUTHENTICATED`
  with the same message (no oracle).
- `displayPrefix` = `"kya_" + keyId` (non-secret).
- Bootstrap: if `KYA_BOOTSTRAP_ADMIN_API_KEY` is set and well-formed at startup
  and no key with that `keyId` exists, insert it as an active `admin` key
  (hash only). Generate one with `npm run gen:admin-key`.

## 6. Randomness and IDs

- All secrets, nonces generated by the SDK, and IDs use `crypto.randomBytes` /
  `crypto.randomUUID`-grade CSPRNG.
- IDs: `<prefix>_<ULID>` (26 chars Crockford base32), e.g. `agt_01J8ZQ4Y5N3V6K2M7P9R0S1T2U`.
