# KYAgent — Architecture (MVP)

KYAgent ("Know Your Agent") is to autonomous AI agents what KYC is to people:
businesses (relying parties) can **verify who an agent is**, **who is accountable
for it** (its operator), and **whether it is authorized** to perform a specific
action — and get back a machine-readable `ALLOW` / `DENY` decision.

This document plus `docs/contracts/*` is the binding contract for all
implementation workers. Do not diverge from it without an architecture change.

| Contract | File |
|---|---|
| HTTP API (OpenAPI 3.1) | [`docs/contracts/openapi.yaml`](docs/contracts/openapi.yaml) |
| Shared TypeScript types, reason codes, error codes | [`docs/contracts/types.ts`](docs/contracts/types.ts) |
| Data schema (MongoDB collections + indexes) | [`docs/contracts/data-schema.md`](docs/contracts/data-schema.md) |
| Error model + verification reason codes | [`docs/contracts/error-model.md`](docs/contracts/error-model.md) |
| Cryptography: request signing, credentials, API keys | [`docs/contracts/crypto-and-signing.md`](docs/contracts/crypto-and-signing.md) |
| Environment configuration | [`docs/contracts/environment.md`](docs/contracts/environment.md), [`.env.example`](.env.example) |

---

## 1. Actors and roles

| Actor | Role (`Role`) | What they do |
|---|---|---|
| Platform admin | `admin` | Onboards businesses and operators, runs operator verification (mock KYC + sanctions screening), issues API keys, suspends operators, global read access. |
| Operator | `operator` | The person/org accountable for agents. Registers agents (public keys), issues credentials to its agents, revokes its agents and credentials. |
| Business | `business` | Relying party. Grants agents scoped permissions, calls `/v1/verify` on incoming agent requests, revokes grants/credentials it is the audience of. |
| Agent | *(no API key)* | Holds an Ed25519 private key. Signs every action request it sends to a business. Presents credentials. Never calls admin/management APIs. |

API clients (admin, operator, business) authenticate with **API keys** (REQ-010).
Agents authenticate **cryptographically** with their Ed25519 key (REQ-004); their
signatures are checked by the service when a business calls `/v1/verify`.

## 2. End-to-end flow

```
 Admin                Operator                 Agent                 Business              KYAgent
   | create operator      |                       |                       |                     |
   |---------------------------------------------------------------------------------------->  | operators: pending
   | run verification (mock KYC + sanctions)                                                  -> | operators: verified
   | create API keys (operator, business) ------------------------------------------------->   | api_keys (hashed)
   |                      | register agent(pubkey, proofOfPossession) -------------------------> | agents: active
   |                      |                       |                       | create grant(agent, actions, constraints, expiresAt) -> grants: active
   |                      | issue credential(agent, grant) ------------------------------------> | credentials (JWS, EdDSA)
   |                      |-- credential JWS ---->|                       |                     |
   |                      |                       |-- signed request + credential -->             |
   |                      |                       |                       |-- POST /v1/verify -> | ALLOW / DENY + reasons
   |                      | revoke agent / credential, or business revokes grant ------------->  | enforced on next verify
```

1. **Operator onboarding (REQ-003).** Admin creates an operator (`pending`), then
   triggers verification. MVP verification is a deterministic **mock KYC**
   plus a **sanctions screen** controlled by `SANCTIONS_MODE` (see
   `environment.md`). Result: `verified` or `rejected`. Real third-party KYC is a
   non-goal.
2. **Agent registration (REQ-001, REQ-003, REQ-004).** A `verified` operator
   registers an agent with its Ed25519 public key and a *proof of possession*
   signature. The agent is permanently bound to that operator.
3. **Authorization (REQ-002).** A business creates a **grant**: agent + list of
   actions (e.g. `payments:create`, `orders:*`) + optional constraints
   (`maxAmount`, `currency`, `resources`) + mandatory expiry.
4. **Credential issuance (REQ-006).** The operator requests a credential for a
   grant. The service returns a compact JWS (`alg=EdDSA`) signed with the
   server key, scoped to the grant's actions, audience = business, expiring at
   `min(now + ttl, grant.expiresAt)`, and **bound to the agent key**
   (`cnf.jkt`), so a leaked credential is useless without the agent's private key.
5. **Verification (REQ-005, REQ-009, REQ-012).** The agent sends the business a
   signed request (`signedRequest`) and optionally its credential. The business
   forwards them to `POST /v1/verify`, which returns `ALLOW` or `DENY` with
   reason codes. If no credential is presented the service evaluates the agent's
   active grants from the calling business directly.
6. **Revocation (REQ-007).** Agents, credentials, grants, operators and API
   keys can be revoked/suspended. Every verification reads current state from
   the store — **no caching of revocation state** — so revocation takes effect
   on the very next verification.

## 3. Verification algorithm (normative)

`POST /v1/verify` is **deny by default**. The decision starts as `DENY` and
becomes `ALLOW` only when every check below passes. Checks run in this exact
order and **short-circuit**: a `DENY` carries exactly one reason — the first
failed check. Any thrown exception, timeout or store error ⇒ `DENY` with
`INTERNAL_ERROR` (HTTP 500 body still contains `decision: "DENY"`).

| # | Check | Reason code on failure |
|---|---|---|
| 1 | Body is valid JSON and matches `VerifyRequest` schema; `signedRequest.agentId == agentId`; `signedRequest.action == action`; `resource`/`context` equal those signed | `MALFORMED_REQUEST` |
| 2 | `signedRequest.audience` equals the calling business's id | `AUDIENCE_MISMATCH` |
| 3 | Agent exists | `AGENT_NOT_FOUND` |
| 4 | Agent `status == active` (`revoked` / `suspended` otherwise) | `AGENT_REVOKED` / `AGENT_SUSPENDED` |
| 5 | Operator exists, `status == verified` | `OPERATOR_SUSPENDED` (if suspended) / `OPERATOR_NOT_VERIFIED` (any other status) |
| 6 | `|now - timestamp| <= KYA_SIGNATURE_MAX_SKEW_SECONDS` | `TIMESTAMP_OUT_OF_WINDOW` |
| 7 | Ed25519 signature over the canonical signing string verifies with the agent's registered key | `SIGNATURE_INVALID` |
| 8 | `(agentId, nonce)` not seen before — atomically recorded **only after** step 7 passes | `NONCE_REPLAYED` |
| 9a | *If `credential` present:* JWS header `alg=EdDSA`, `typ=kya-credential+jwt`, known `kid`, valid signature, `iss` matches | `CREDENTIAL_INVALID` |
| 9b | `nbf <= now` / `exp > now` (no leeway beyond skew for `nbf`) | `CREDENTIAL_NOT_YET_VALID` / `CREDENTIAL_EXPIRED` |
| 9c | `sub == agentId` | `CREDENTIAL_SUBJECT_MISMATCH` |
| 9d | `aud == calling business id` | `CREDENTIAL_AUDIENCE_MISMATCH` |
| 9e | `cnf.jkt` equals the agent key thumbprint | `CREDENTIAL_KEY_MISMATCH` |
| 9f | Credential record for `jti` exists (else `CREDENTIAL_INVALID`) and `status == active` | `CREDENTIAL_INVALID` / `CREDENTIAL_REVOKED` |
| 9g | Referenced grant exists, `status == active`, not expired | `GRANT_REVOKED` / `GRANT_EXPIRED` |
| 9h | `action` matched by the credential's `kya_actions` **and** the grant's actions | `ACTION_NOT_PERMITTED` |
| 9i | Grant constraints satisfied by signed `resource`/`context` | `CONSTRAINT_VIOLATION` |
| 10 | *If no credential:* at least one active, unexpired grant from the calling business to the agent exists | `NO_GRANT` |
| 10b | One of those grants matches `action` | `ACTION_NOT_PERMITTED` |
| 10c | That grant's constraints are satisfied (grants evaluated in `createdAt` ascending order; first grant that matches action and satisfies constraints wins; if some matched the action but none satisfied constraints ⇒ `CONSTRAINT_VIOLATION`) | `CONSTRAINT_VIOLATION` |

On `ALLOW`, `reasons = [{ code: "ALLOWED" }]` and `grantId` (and `credentialId`
if presented) are set. Every decision (ALLOW or DENY, except requests rejected
before business authentication) is appended to `verification_events`.

Action matching: an action is `segment(:segment)*`, segments `[a-z0-9_-]+`.
A granted pattern matches if equal, or if it ends in `:*` and the action starts
with the prefix before `*` (e.g. `orders:*` matches `orders:create`,
`orders:refund:partial`; it does **not** match `orders`). A bare `*` is **not** allowed.

Constraints (all optional, all must hold):
- `maxAmount` (integer, minor units): `context.amount` must be an integer `<= maxAmount`; missing ⇒ violation.
- `currency` (ISO 4217): `context.currency` must equal it; missing ⇒ violation.
- `resources` (string[]): `resource` must be one of them; missing ⇒ violation.

## 4. Security model

| Concern | Design |
|---|---|
| Agent identity (REQ-004) | Ed25519 key pair generated by the agent/operator; **server stores only the public key**. Registration requires proof of possession. Key fingerprint = RFC 7638 JWK thumbprint. |
| Request signing (REQ-004, REQ-009) | Canonical newline-delimited signing string `KYA-SIG-V1` covering agent, audience, action, resource, SHA-256 of canonical context JSON, timestamp, nonce. See `crypto-and-signing.md`. |
| Replay (REQ-009) | Timestamp window (default ±300 s) + nonce uniqueness per agent, stored with TTL = 2 × window via a unique index (atomic insert; duplicate-key ⇒ replay). |
| Credentials (REQ-006) | Compact JWS, `EdDSA`, server key from env/secret file, `exp` ≤ `KYA_CREDENTIAL_MAX_TTL_SECONDS` and ≤ grant expiry, holder-bound via `cnf.jkt`, persisted by `jti` for revocation. Public JWKS at `/.well-known/jwks.json`. |
| Revocation (REQ-007) | Status fields checked on every verify, no cache. Revoking an agent/grant invalidates all derived credentials implicitly. Revocation is irreversible for agents, credentials, grants and API keys. |
| API auth (REQ-010) | `Authorization: Bearer kya_<keyId>_<secret>`. Stored as `HMAC-SHA256(pepper, secret)`; plaintext returned exactly once at creation. Constant-time compare. Revoked keys rejected. |
| RBAC (REQ-010) | Role from the key; ownership (tenant) enforced in the service layer. Cross-tenant reads return `404 NOT_FOUND` (no existence oracle). Matrix in §5. |
| Secrets (REQ-011) | Server signing key and API-key pepper come only from env vars or `*_FILE` secret files. In `production`, missing secrets ⇒ refuse to start. In dev/test, an **ephemeral in-memory** key/pepper is generated with a warning. Secrets are never logged, returned, or committed (`.gitignore` covers `.env`, `*.pem`, `secrets/`). |
| Deny by default (REQ-012) | See §3. Unknown agent, malformed input, store errors, unexpected exceptions ⇒ `DENY`. Unauthenticated/unauthorized callers get `401/403`, never a decision. |
| Input limits | Body ≤ `KYA_MAX_BODY_BYTES` (default 64 KiB); strict schemas (`additionalProperties: false`); string length caps per OpenAPI. |
| Logging | Structured JSON logs with `requestId`. Never log Authorization headers, API key secrets, credentials JWS, private keys or pepper. |

## 5. RBAC matrix

`own` = resource belongs to the caller's tenant (operator owns agent; business
owns grant; credential audience/agent owner). `—` = `403 FORBIDDEN`.

| Endpoint | admin | operator | business |
|---|---|---|---|
| `GET /healthz`, `GET /.well-known/jwks.json` | public | public | public |
| `POST/GET /v1/businesses` | ✔ | — | — |
| `GET /v1/businesses/{id}` | ✔ | — | own |
| `POST /v1/operators`, `GET /v1/operators` | ✔ | — | — |
| `GET /v1/operators/{id}` | ✔ | own | ✔ (public profile) |
| `POST /v1/operators/{id}/verification`, `/suspend` | ✔ | — | — |
| `POST/GET /v1/api-keys`, `POST /v1/api-keys/{id}/revoke` | ✔ | — | — |
| `POST /v1/agents` | — | ✔ (self as operator; must be `verified`) | — |
| `GET /v1/agents` | ✔ | own | — |
| `GET /v1/agents/{id}` | ✔ | own | ✔ (public profile) |
| `POST /v1/agents/{id}/revoke`, `/suspend`, `/reactivate` | ✔ | own | — |
| `POST /v1/agents/{id}/credentials` | — | own | — |
| `GET /v1/credentials`, `GET /v1/credentials/{id}` | ✔ | own (agent owner) | own (audience) |
| `POST /v1/credentials/{id}/revoke` | ✔ | own (agent owner) | own (audience) |
| `POST /v1/grants` | — | — | ✔ (self as grantor) |
| `GET /v1/grants`, `GET /v1/grants/{id}` | ✔ | own (grants to its agents) | own |
| `POST /v1/grants/{id}/revoke` | ✔ | — | own |
| `POST /v1/verify` | — | — | ✔ |
| `GET /v1/verifications` | ✔ | — | own |

## 6. Technology and repository layout

- **Runtime:** Node.js 20 LTS, TypeScript (strict), ES modules.
- **HTTP:** Fastify 4 (JSON-schema validation, body limit). Schemas are derived from `openapi.yaml`.
- **Crypto:** `node:crypto` for Ed25519, HMAC, SHA-256, random; `jose` for JWS/JWKS (EdDSA only, algorithm allow-list).
- **Storage:** MongoDB via the official `mongodb` driver (`MONGODB_URI`, `MONGODB_DB`). A `MemoryStore` implementing the same `Store` interface is used when `MONGODB_URI` is unset (tests, local dev). PostgreSQL is not used in MVP.
- **Tests:** `vitest`; unit + HTTP integration tests via `fastify.inject` against `MemoryStore`.
- **Dashboard (later task):** Next.js app in `dashboard/` consuming the same public API with an API key; no privileged backdoors.
- **Deployment:** `Dockerfile` + `docker-compose.yml` (api + mongo); secrets via env/`*_FILE` mounts.

```
ARCHITECTURE.md
docs/contracts/             # this contract (source of truth)
src/
  contracts/types.ts        # verbatim copy of docs/contracts/types.ts (a test asserts equality)
  config.ts                 # env parsing/validation (environment.md)
  server.ts                 # process entrypoint: loadConfig -> buildApp -> listen
  app.ts                    # buildApp({ config, store, clock }) -> Fastify instance (no listen)
  errors.ts                 # ApiError class + Fastify error handler (error-model.md)
  crypto/
    ed25519.ts              # key parsing, thumbprint, sign/verify
    canonical.ts            # canonical JSON, signing-string builders
    credentials.ts          # issue/verify JWS credentials, JWKS
    apiKeys.ts              # generate/parse/hash API keys
  auth/
    authenticate.ts         # Bearer API key -> Principal
    rbac.ts                 # requireRole(...), ownership helpers
  store/
    Store.ts                # Store interface (repositories per collection)
    memory.ts               # MemoryStore
    mongo.ts                # MongoStore + index creation
  services/
    operators.ts  kyc.ts  sanctions.ts  agents.ts  grants.ts
    credentials.ts  verification.ts  apiKeys.ts  audit.ts
  routes/                   # thin HTTP adapters, one file per tag
  sdk/agentSigner.ts        # helper for agents: signRequest(), proofOfPossession()
test/
Dockerfile  docker-compose.yml  .env.example  .gitignore
```

Layering rules:
- Routes → services → store. Routes never touch the store directly.
- Services receive a `Clock` (`now(): Date`) for deterministic time in tests.
- All ownership checks live in services and take the `Principal`.
- `verification.ts` wraps the whole evaluation in `try/catch` and returns `DENY / INTERNAL_ERROR` on any throw.

## 7. Non-goals (MVP)

Real third-party KYC/document verification (mocked), blockchain identity
registry (`CHAIN_MODE` is read-only/ignored), LLM features (`LLM_MODE` ignored),
billing, multi-region deployment, compliance certification, bot detection on
unauthenticated traffic, agent key rotation (revoke and re-register instead).

## 8. Requirement traceability

| Req | Covered by |
|---|---|
| REQ-001 verify agent identity | Agent registry, `GET /v1/agents/{id}`, `/v1/verify` steps 3–7 |
| REQ-002 authorize actions | Grants (`/v1/grants`), action patterns + constraints, `/v1/verify` steps 9–10 |
| REQ-003 operators bound to agents | `operators` collection, mock KYC + sanctions, `agents.operatorId` immutable, step 5 |
| REQ-004 cryptographic identity | Ed25519 public keys, proof of possession, `KYA-SIG-V1` signing |
| REQ-005 ALLOW/DENY with reasons | `VerifyResponse`, `ReasonCode` enum |
| REQ-006 signed, expiring, scoped credentials | `POST /v1/agents/{id}/credentials`, EdDSA JWS, JWKS |
| REQ-007 immediate revocation | revoke endpoints, uncached status checks |
| REQ-009 replay protection | timestamp window + nonce store (step 6, 8) |
| REQ-010 API keys hashed + RBAC | `api_keys` (HMAC-SHA256 + pepper), §5 matrix |
| REQ-011 secrets from env/secret store | `environment.md`, `*_FILE` support, production fail-fast |
| REQ-012 deny by default | §3 algorithm, `INTERNAL_ERROR` ⇒ DENY |
