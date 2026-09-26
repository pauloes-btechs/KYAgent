# Operator integration guide

This guide is for **operators**: the people or organizations accountable for
AI agents. It covers what the current KYAgent build does. The binding details
are in [`ARCHITECTURE.md`](../../ARCHITECTURE.md),
[`crypto-and-signing.md`](../contracts/crypto-and-signing.md) and
[`openapi.yaml`](../contracts/openapi.yaml). A running server also serves the
spec at `GET /openapi.yaml`.

## Responsibilities

| You (operator) | Your agent | KYAgent |
|---|---|---|
| Pass verification, register agent public keys, issue credentials, suspend or revoke agents | Hold its Ed25519 private key, sign every action request | Store public keys only, verify signatures, enforce grants and revocation |

The **private key never leaves the agent host**. KYAgent never generates,
receives or stores agent private keys, and the dashboard does not accept them.

## 1. Onboarding and verification

A platform admin creates your operator record and runs verification:

```
POST /v1/operators                    {"type": "organization", "legalName": "Acme Robotics Ltd",
                                       "contactEmail": "ops@acme.example", "country": "GB"}   -> status "pending"
POST /v1/operators/{id}/verification  -> status "verified" or "rejected"
POST /v1/api-keys                     {"name": "acme", "role": "operator", "ownerId": "op_…"}
                                      -> {"secret": "kya_<keyId>_<secret>", …}   (shown once)
```

In this MVP, verification is a **mock** KYC check plus a sanctions screen
(`SANCTIONS_MODE=mock|off`). It is not a real identity check. The result is in
`operator.verification` (`kycResult`, `sanctionsMode`, `sanctionsResult`,
`checkedAt`). You can register agents only while your status is `verified`.
Otherwise `POST /v1/agents` returns `409 OPERATOR_NOT_VERIFIED`. If an admin
suspends you (`POST /v1/operators/{id}/suspend`), every verification of your
agents returns `DENY OPERATOR_SUSPENDED` until the status changes.

Keep the API key in a secret manager. Send it on every call as
`Authorization: Bearer kya_<keyId>_<secret>`.

## 2. Generate the agent key and register it

On the agent host, using the bundled Node.js helper
[`src/sdk/agentSigner.js`](../../src/sdk/agentSigner.js):

```js
import { generateAgentKey, proofOfPossession } from './src/sdk/agentSigner.js';

const { privateKey, publicKey } = generateAgentKey();          // keep privateKey on this host
const pop = proofOfPossession(privateKey, operatorId, publicKey);
```

`publicKey` is the raw 32-byte Ed25519 key in base64url (43 characters).
`proofOfPossession` signs the string `KYA-REGISTER-V1\n{operatorId}\n{publicKey}`.
Then register:

```http
POST /v1/agents
{ "name": "Invoice Bot", "description": "Pays approved invoices", "publicKey": "…", "proofOfPossession": "…" }
```

The response is the `Agent` with `id` (`agt_…`) and `keyThumbprint` (RFC 7638
JWK thumbprint). The agent is permanently bound to your operator. A public key
can be registered only once.

## 3. Get authorized by a business

Businesses decide what your agent may do by creating **grants**
(`POST /v1/grants`, business role). You can read grants to your agents:

```
GET /v1/grants?agentId=agt_…&status=active
```

## 4. Issue a credential (optional)

A credential is a portable, holder-bound proof of a grant:

```http
POST /v1/agents/{agentId}/credentials
{ "grantId": "grt_…", "ttlSeconds": 3600 }
```

Response: `{ "credential": "<compact JWS>", "record": CredentialRecord }`.
The credential is returned once, in this response. Hand it to the agent.

- Signed by the server with `alg=EdDSA`, `typ=kya-credential+jwt`. The public key is at `GET /.well-known/jwks.json`.
- Scoped to the grant's actions, with audience = the grant's business.
- Expires at `min(now + ttlSeconds, grant.expiresAt)`. `ttlSeconds` is 60–86400 and is also capped by `KYA_CREDENTIAL_MAX_TTL_SECONDS`.
- Bound to the agent key (`cnf.jkt`), so it is useless without the agent's private key.

Without a credential, the business's `/v1/verify` call evaluates its grants to
your agent directly. Both paths enforce the same revocation and constraints.

## 5. Sign every action request

For each request to a business, the agent builds a `VerifyRequest` body:

```js
import { buildVerifyRequest } from './src/sdk/agentSigner.js';

const body = buildVerifyRequest(privateKey, {
  agentId,                      // agt_…
  audience: businessId,         // biz_… of the business you are calling
  action: 'payments:create',
  resource: 'invoice:42',       // optional
  context: { amount: 1500, currency: 'USD' },   // optional, integers only
  credential,                   // optional
});
// send `body` to the business, which forwards it to POST /v1/verify
```

`buildVerifyRequest` sets a fresh timestamp (unix seconds) and a random nonce,
and signs the `KYA-SIG-V1` string:

```
KYA-SIG-V1\n{agentId}\n{audience}\n{action}\n{resource}\n{sha256hex(canonicalJson(context))}\n{timestamp}\n{nonce}
```

To call a business over HTTP, send the signature as headers instead. The
business derives `action`/`resource`/`context` from your request and verifies
them with `src/sdk/businessVerifier.js`:

```js
import { signedHeaders, exportAgentKey, importAgentKey } from './src/sdk/agentSigner.js';

const headers = signedHeaders(privateKey, { agentId, audience: businessId, action: 'payments:create', context: { amount: 1500, currency: 'USD' }, credential });
await fetch(`${businessUrl}/payments`, { method: 'POST', headers: { ...headers, 'content-type': 'application/json' }, body: JSON.stringify({ amount: 1500, currency: 'USD' }) });

// Store the agent key at rest only encrypted (passphrase from your secret manager, >= 12 chars):
const pem = exportAgentKey(privateKey, process.env.AGENT_KEY_PASSPHRASE);
const { privateKey: loaded } = importAgentKey(pem, process.env.AGENT_KEY_PASSPHRASE);
```

`importAgentKey` rejects unencrypted PEMs. See
[`examples/sdk-quickstart.js`](../../examples/sdk-quickstart.js) for a runnable agent + business pair.

If you are not using Node.js, follow
[`crypto-and-signing.md`](../contracts/crypto-and-signing.md) §3 and check your
implementation against the test vector in
[`test/vectors/sig-v1.json`](../../test/vectors/sig-v1.json). Notes:

- Canonical context JSON sorts object keys, has no whitespace and allows only integers (no floats).
- Sign a new request for every action. A reused nonce is denied (`NONCE_REPLAYED`).
- Keep the agent clock in sync. The default accepted skew is ±300 s.

## 6. Lifecycle: suspend, reactivate, revoke

| Call | Effect |
|---|---|
| `POST /v1/agents/{id}/suspend {"reason": "…"}` | `active` → `suspended`, verifications return `AGENT_SUSPENDED` |
| `POST /v1/agents/{id}/reactivate` | `suspended` → `active` |
| `POST /v1/agents/{id}/revoke {"reason": "…"}` | Irreversible, verifications return `AGENT_REVOKED` |
| `POST /v1/credentials/{id}/revoke {"reason": "…"}` | Irreversible, verifications with it return `CREDENTIAL_REVOKED` |

Every verification reads the current state, so these changes apply to the next
`/v1/verify` call. If an agent key is compromised, **revoke the agent** and
register a new agent with a new key. Keys cannot be rotated in place.

Useful reads: `GET /v1/agents?status=active`, `GET /v1/agents/{id}`,
`GET /v1/credentials?agentId=…`, `GET /v1/operators/{yourId}`.

## 7. Try it locally

`npm run example:sdk` runs the signing and verification flow in memory.
`make demo-reset && make demo` (MongoDB Atlas required, `MONGODB_URI`) serves the
hackathon scenario and prints demo-only operator, business and admin keys for the
dashboard at `/dashboard/`.
