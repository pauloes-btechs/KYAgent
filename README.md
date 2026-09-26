# KYAgent — Know Your Agent

KYAgent does for autonomous AI agents what KYC does for people. A business can
check **who an agent is** (Ed25519 identity), **who is accountable for it**
(a verified operator), and **whether it may do this action right now** (scoped
grants and credentials). The answer is `ALLOW` or `DENY` with a
machine-readable reason.

The binding design is in [`ARCHITECTURE.md`](ARCHITECTURE.md) and
[`docs/contracts/`](docs/contracts/): OpenAPI, types, data schema, error model
and crypto.

| Document | For |
|---|---|
| [`docs/contracts/openapi.yaml`](docs/contracts/openapi.yaml) | OpenAPI 3.1 spec for every endpoint. A running server also serves it at `GET /openapi.yaml`. |
| [`docs/guides/business-integration.md`](docs/guides/business-integration.md) | Businesses (relying parties): grants, `POST /v1/verify`, reason codes |
| [`docs/guides/operator-integration.md`](docs/guides/operator-integration.md) | Operators: agent keys, registration, credentials, request signing, revocation |

## Quick start (about 5 minutes)

You need Node.js 20 or later. There are no dependencies to install.

```bash
npm test          # full test suite (node:test)
npm run demo      # starts the API + dashboard in memory and runs the whole flow
```

`npm run demo` prints each decision as it runs, for example:

```
  ALLOW ALLOWED                  payments:create 1500 USD with credential
  DENY  CONSTRAINT_VIOLATION     payments:create 50000 USD (over limit)
  DENY  NONCE_REPLAYED           same request replayed
  DENY  CREDENTIAL_REVOKED       credential after revocation
  DENY  AGENT_REVOKED            agent after revocation
```

It then prints the dashboard URL (`http://127.0.0.1:8080/dashboard/`) and three
**demo-only** API keys (admin, operator, business). Paste one of them into the
dashboard to see agents, grants, credentials and the verification audit log.
These keys are ephemeral. They stop working as soon as the demo process exits.

## Running the server

```bash
cp .env.example .env               # .env is git-ignored
npm run gen:signing-key            # -> KYA_SIGNING_PRIVATE_KEY
npm run gen:pepper                 # -> KYA_API_KEY_PEPPER
npm run gen:admin-key              # -> KYA_BOOTSTRAP_ADMIN_API_KEY (your first admin key)
# paste the values into .env (or use the *_FILE variants with a secret mount), then:
set -a; . ./.env; set +a; npm start
```

- If `MONGODB_URI` is unset, the server uses the in-memory store. This is for dev
  and test only: data is lost on restart and the dashboard shows a warning chip.
- To use MongoDB, run `npm install mongodb` and set `MONGODB_URI`. Schema
  migrations (`src/store/migrations.js`, recorded in `schema_migrations`) run on
  startup; `npm run migrate` applies them explicitly and `npm run seed` loads demo data.

### Docker Compose (local deployment)

```bash
npm run env:init                               # writes .env (git-ignored, mode 0600) with generated secrets
docker compose up --build -d                   # mongo -> migrate (one-shot) -> api on 127.0.0.1:8080
docker compose --profile seed run --rm seed    # optional: demo operator, business, agent, grant
docker compose down                            # add -v to wipe the database volume
```

The stack runs with `NODE_ENV=production` (secrets required, no in-memory store).
`api` starts only after `migrate` exits successfully. The seed is idempotent and
prints the demo operator/business API keys and the agent private-key seed **once**;
the database stores only hashes and the public key. Your admin key is
`KYA_BOOTSTRAP_ADMIN_API_KEY` in `.env`. MongoDB is not published on the host.
- In `production`, a missing signing key, pepper or `MONGODB_URI` makes the
  server refuse to start. In dev/test the server generates ephemeral secrets
  and logs a warning. Configuration reference:
  [`docs/contracts/environment.md`](docs/contracts/environment.md).

## The flow over HTTP

Every call sends `Authorization: Bearer kya_<keyId>_<secret>`.

| Step | Who | Call |
|---|---|---|
| 1 | admin | `POST /v1/operators`, then `POST /v1/operators/{id}/verification` (mock KYC + sanctions) |
| 2 | admin | `POST /v1/businesses`, `POST /v1/api-keys` (operator / business keys, shown once) |
| 3 | operator | `POST /v1/agents` `{name, publicKey, proofOfPossession}` |
| 4 | business | `POST /v1/grants` `{agentId, actions:["payments:create"], constraints:{maxAmount, currency}, expiresAt}` |
| 5 | operator | `POST /v1/agents/{id}/credentials` `{grantId, ttlSeconds}` → compact JWS (EdDSA) |
| 6 | agent → business | the agent signs each request with `src/sdk/agentSigner.js` |
| 7 | business | `POST /v1/verify` → `{decision, reasons:[{code,message}], …}` |
| 8 | anyone allowed | revoke with `/v1/agents/{id}/revoke`, `/v1/grants/{id}/revoke`, `/v1/credentials/{id}/revoke`, `/v1/operators/{id}/suspend` |

Agent side (the private key never leaves the agent host):

```js
import { generateAgentKey, proofOfPossession, buildVerifyRequest } from './src/sdk/agentSigner.js';
const { privateKey, publicKey } = generateAgentKey();
const pop = proofOfPossession(privateKey, operatorId, publicKey);          // for registration
const body = buildVerifyRequest(privateKey, { agentId, audience: businessId,
  action: 'payments:create', context: { amount: 1500, currency: 'USD' }, credential });
// the business forwards `body` to POST /v1/verify
```

## Security model (summary)

- **Deny by default.** Every check in ARCHITECTURE §3 must pass, in the order
  listed there. Malformed or oversized bodies return `200 DENY
  MALFORMED_REQUEST`. Any exception or store failure returns `500 DENY
  INTERNAL_ERROR`. If the audit event cannot be written, the result is
  `DENY`, so no `ALLOW` goes unaudited.
- **Replay protection.** Requests must be within ±300 s
  (`KYA_SIGNATURE_MAX_SKEW_SECONDS`), and each `(agent, nonce)` pair is
  accepted once. A nonce is recorded only after the signature verifies, so
  forged requests cannot burn real nonces.
- **Credentials.** Compact JWS signed with the server's Ed25519 key. The only
  accepted algorithm is `EdDSA`, and `typ`, `kid` and `iss` must match. Each
  credential is bound to the agent's key through `cnf.jkt` and expires by
  `min(ttl, grant expiry)`. Revocation state is read on every verification and
  is never cached.
- **API keys.** Stored as `HMAC-SHA256(pepper, secret)` and compared in
  constant time. The plaintext is returned once. Every auth failure returns
  the same 401. RBAC follows ARCHITECTURE §5. Cross-tenant reads return 404.
- **Secrets.** Loaded only from environment variables or `*_FILE` mounts, and
  never logged or returned. They are also non-enumerable on the config object.
  The repo holds no secrets. The only fixed key is the public RFC 8032 test
  seed in `test/vectors/`, and it is rejected as a server key in production.
- **Stricter than the contract** (fail closed): public keys and signatures must
  use canonical base64url, so one key cannot be registered twice under
  different spellings. Negative `amount` values fail `maxAmount`. Credential
  headers may contain only `alg`, `typ` and `kid`.
- **Dashboard.** Served with a strict CSP and no inline script. The API key is
  kept only in memory, all data is rendered as text, destructive actions need
  a typed confirmation, and the session ends after 30 minutes idle.

## Layout

```
src/
  app.js            HTTP adapter (node:http): routing, auth, RBAC role gate, body limits
  server.js         entrypoint: loadConfig -> store -> app.listen
  config.js         the only reader of process.env
  contracts.js      runtime constants mirrored from docs/contracts/types.ts (checked by tests)
  crypto/           ed25519, canonical JSON + signing strings, JWS credentials, API keys
  services/         operators/businesses, apiKeys, agents, grants, credentials, verification, kyc, authz
  store/            memory.js (default), mongo.js (optional driver), pagination
  sdk/agentSigner.js
dashboard/          static dashboard served at /dashboard/
scripts/            demo + secret generators
test/               node:test suites + test/vectors/sig-v1.json
```

## Deviations from ARCHITECTURE §6 (MVP)

The architecture names TypeScript, Fastify, `jose` and `vitest`, plus a Next.js
dashboard. This slice uses plain ESM JavaScript on Node built-ins (`node:http`,
`node:crypto`, `node:test`) and a static vanilla-JS dashboard, so it runs with
**zero dependencies**. All wire formats, reason codes, status codes and
algorithms follow the contracts. `test/contracts.test.js` checks the runtime
constants against `docs/contracts/types.ts` and `openapi.yaml`. The data
layer is behind the `Store` interface, so a later move to TypeScript/Fastify
would only replace the adapter.

Non-goals, as in the brief: no real KYC provider (mocked), no blockchain
registry (`CHAIN_MODE` is ignored), no LLM features (`LLM_MODE` is ignored),
no billing and no bot detection.

## For judges and non-engineers

- **City Gate explainer** — an interactive, kid-friendly walkthrough of how KYAgent decides which agents get in and how the harness learns. Open `docs/explainer/index.html` in any browser.
- **Pitch deck** — `docs/KYAgent_pitch.pptx`.
- **MongoDB hackathon work in progress** — branch `run/run_330acfe48e598a1f` (Atlas Search, Vector Search, Change Streams, versioned harness). See `MONGODB_HACKATHON_GAP_ANALYSIS.md` and `DELIVERY_PLAN.md` on that branch.
