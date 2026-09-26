# Environment Configuration

All configuration is read once in `src/config.ts` (`loadConfig(env = process.env)`),
validated, and passed down explicitly. No other module reads `process.env`.
**Secret values are never logged, printed, echoed in errors, or committed.**
Startup logs may print variable *names* and whether a secret was "set / file / ephemeral".

Secrets support a `*_FILE` variant (path to a file, e.g. Docker/K8s secret mount).
If both are set ⇒ config error. File contents are trimmed of trailing whitespace.

## Variables

| Name | Secret | Default | Description |
|---|---|---|---|
| `NODE_ENV` | no | `development` | `production` \| `development` \| `test`. Production enables fail-fast for secrets. |
| `PORT` | no | `8080` | HTTP listen port |
| `HOST` | no | `0.0.0.0` | Listen address |
| `LOG_LEVEL` | no | `info` | `fatal`..`trace`; `silent` in tests |
| `MONGODB_URI` | **yes** (may embed credentials) | unset | If unset ⇒ `MemoryStore` (not allowed when `NODE_ENV=production`). Never log it. |
| `MONGODB_DB` | no | `kyagent` | Database name |
| `KYA_ISSUER` | no | `kyagent` | Credential `iss` |
| `KYA_SIGNING_PRIVATE_KEY` / `_FILE` | **yes** | — | Server Ed25519 private key: PKCS#8 PEM (`-----BEGIN PRIVATE KEY-----`; in env, `\n` escapes are accepted) **or** base64/base64url of PKCS#8 DER. Non-Ed25519 keys ⇒ config error. |
| `KYA_SIGNING_KEY_ID` | no | RFC 7638 thumbprint | JWS `kid` |
| `KYA_API_KEY_PEPPER` / `_FILE` | **yes** | — | ≥ 32 bytes of entropy (e.g. 43+ char base64url). Used for HMAC of API key secrets. |
| `KYA_BOOTSTRAP_ADMIN_API_KEY` / `_FILE` | **yes** | unset | Optional plaintext admin key (format in crypto-and-signing.md §5) whose **hash** is inserted at startup if absent. |
| `KYA_SIGNATURE_MAX_SKEW_SECONDS` | no | `300` | Replay window, integer 30..900 |
| `KYA_CREDENTIAL_DEFAULT_TTL_SECONDS` | no | `900` | Integer ≥ 60 and ≤ max |
| `KYA_CREDENTIAL_MAX_TTL_SECONDS` | no | `3600` | Integer 60..86400 |
| `KYA_MAX_BODY_BYTES` | no | `65536` | Request body limit |
| `SANCTIONS_MODE` | no | `mock` | `mock` \| `off`. Any other value (e.g. `live`) ⇒ treated as `mock` with a startup warning (no live provider in MVP; fail safe, never silently `off`). |
| `CHAIN_MODE` | no | unset | Read and ignored; blockchain registry is a non-goal. Logged at startup as "ignored". |
| `LLM_MODE` | no | unset | Read and ignored; no LLM features in MVP. |

## Missing secret behaviour

| Secret | `production` | `development` / `test` |
|---|---|---|
| `KYA_SIGNING_PRIVATE_KEY` | refuse to start (exit 1, message names the variable) | generate **ephemeral** in-memory key, warn "credentials will not survive restart" |
| `KYA_API_KEY_PEPPER` | refuse to start | generate ephemeral random pepper, warn |
| `MONGODB_URI` | refuse to start | use `MemoryStore`, warn |

Invalid values (bad integers, wrong key type, malformed PEM) are **always** a
config error regardless of `NODE_ENV`.

## Generating secrets

Implementation provides scripts (they print to stdout only; users put output in
their secret store or an untracked `.env`):

- `npm run gen:signing-key` → base64 PKCS#8 DER Ed25519 key for `KYA_SIGNING_PRIVATE_KEY`
- `npm run gen:pepper` → 32 random bytes base64url
- `npm run gen:admin-key` → a fresh admin API key in the correct format

## Repository hygiene

- `.env`, `.env.*` (except `.env.example`), `*.pem`, `*.key`, `secrets/` are git-ignored.
- `.env.example` contains names and placeholders only.
- Tests generate keys at runtime; no fixed private keys in the repo except the
  public, clearly-labelled **test vector seed** in `test/vectors/` (never usable as server key:
  `loadConfig` rejects it when `NODE_ENV=production`).
