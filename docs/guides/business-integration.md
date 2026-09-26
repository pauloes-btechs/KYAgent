# Business integration guide

This guide is for **businesses** (relying parties): services that receive
requests from AI agents and need to decide whether to accept them. It covers
what the current KYAgent build does. The binding details are in
[`ARCHITECTURE.md`](../../ARCHITECTURE.md) and
[`openapi.yaml`](../contracts/openapi.yaml). A running server also serves the
spec at `GET /openapi.yaml`.

## What you get

For every incoming agent request you forward, `POST /v1/verify` tells you:

- **who the agent is**: the request was signed with the Ed25519 key registered for `agentId`;
- **who is accountable**: the agent's operator exists and is `verified` (mock KYC + sanctions screen in this MVP);
- **whether this action is allowed**: one of your active grants (or a credential derived from it) covers the action and its constraints.

The answer is `ALLOW` or `DENY` with exactly one reason code. Treat anything
other than `decision: "ALLOW"` as a refusal.

## 1. Get a business API key

A platform admin creates your business and a key for it:

```
POST /v1/businesses        {"name": "Globex"}                                   -> {"id": "biz_…", …}
POST /v1/api-keys          {"name": "globex-prod", "role": "business", "ownerId": "biz_…"}
                           -> {"apiKey": {…}, "secret": "kya_<keyId>_<secret>"}
```

The `secret` is returned **once**. Store it in your secret manager, never in
source control. Every call below sends:

```
Authorization: Bearer kya_<keyId>_<secret>
Content-Type: application/json
```

All authentication failures return the same `401 UNAUTHENTICATED`. Calling an
endpoint your role may not use returns `403 FORBIDDEN`. Resources that belong to
another tenant return `404 NOT_FOUND`.

## 2. Look up an agent before trusting it

```
GET /v1/agents/{agentId}          -> Agent (id, operatorId, name, publicKey, keyThumbprint, status, …)
GET /v1/operators/{operatorId}    -> OperatorPublicProfile (id, type, legalName, country, status)
```

This is informational. The decision that counts is always `/v1/verify`, which
re-reads the current state on every call.

## 3. Grant the agent scoped permissions

```http
POST /v1/grants
{
  "agentId": "agt_…",
  "actions": ["payments:create", "orders:*"],
  "constraints": { "maxAmount": 10000, "currency": "USD", "resources": ["invoice:42"] },
  "expiresAt": "2026-12-31T00:00:00Z"
}
```

- `actions` are `segment(:segment)*` with segments `[a-z0-9_-]+`. A trailing
  `:*` matches any action under that prefix: `orders:*` matches `orders:create`
  and `orders:refund:partial`, but not `orders`. A bare `*` is rejected.
- `constraints` are optional and all must hold:
  - `maxAmount`: `context.amount` must be an integer `<= maxAmount` (minor units, e.g. cents);
  - `currency`: `context.currency` must be equal;
  - `resources`: the signed `resource` must be one of the listed values.
  If a constrained field is missing from the request, the result is `CONSTRAINT_VIOLATION`.
- `expiresAt` is required, must be in the future and at most 365 days away.
- The agent must be `active` and its operator `verified`.

List your grants with `GET /v1/grants?agentId=…&status=active`. Revoke one with
`POST /v1/grants/{id}/revoke {"reason": "…"}`. Revocation cannot be undone, and
it also invalidates every credential issued for that grant.

## 4. Verify every agent request

The agent signs its request (see the [operator guide](operator-integration.md)) and
sends you a `VerifyRequest` body. You forward it unchanged:

```http
POST /v1/verify
{
  "agentId": "agt_…",
  "action": "payments:create",
  "resource": "invoice:42",
  "context": { "amount": 1500, "currency": "USD" },
  "credential": "eyJ…",                  // optional compact JWS
  "signedRequest": {
    "version": "KYA-SIG-V1", "agentId": "agt_…", "audience": "biz_…",
    "action": "payments:create", "resource": "invoice:42",
    "contextSha256": "…", "timestamp": 1790000000, "nonce": "…", "signature": "…"
  }
}
```

Response (`200` for both decisions):

```json
{
  "verificationId": "vrf_…",
  "decision": "ALLOW",
  "reasons": [{ "code": "ALLOWED", "message": "…" }],
  "agentId": "agt_…", "operatorId": "op_…", "action": "payments:create",
  "grantId": "grt_…", "credentialId": "crd_…",
  "evaluatedAt": "2026-09-26T12:00:00.000Z"
}
```

Rules for your integration:

1. **Execute the action only on `decision === "ALLOW"`.** Any other status
   code, a network error or a timeout must be handled as a denial.
2. **Act on what was signed.** The service checks that `agentId`, `action`,
   `resource` and `context` equal the signed values, so use those same values
   when you perform the action.
3. The `audience` in the signed request must be your business id. A request
   signed for another business is denied with `AUDIENCE_MISMATCH`.
4. Each `(agentId, nonce)` is accepted once, and the timestamp must be within
   ±`KYA_SIGNATURE_MAX_SKEW_SECONDS` (default 300 s). Do not retry a request that
   was already verified. The agent must sign a new one.
5. `context` may contain only integers (no floats), strings, booleans, null,
   objects and arrays, up to 8 KiB in canonical form.

### Using the Node.js SDK

[`src/sdk/businessVerifier.js`](../../src/sdk/businessVerifier.js) wraps
`POST /v1/verify` and fails closed. Network errors, timeouts, `401`/`403`,
unparseable bodies and any `ALLOW` that does not match the requested agent and
action all become a local `DENY` with `INTERNAL_ERROR` (`local: true`).
`baseUrl` must use `https` (plain `http` is accepted only for loopback), and
the API key is kept inside the verifier and never returned.

Agents send their signature as HTTP headers built with `signedHeaders` from
the agent SDK: `KYA-Signed-Request` (base64url JSON `SignedRequest`) and an
optional `KYA-Credential`. Your server derives `action`, `resource` and
`context` from the operation it is about to perform, so a request whose body
differs from what the agent signed is denied:

```js
import { createVerifier, isAllowed } from './src/sdk/businessVerifier.js';

const kya = createVerifier({ baseUrl: process.env.KYA_BASE_URL, apiKey: process.env.KYA_API_KEY });

const decision = await kya.verifyIncoming({
  headers: req.headers,                 // Node req.headers or a Fetch Headers object
  action: 'payments:create',
  context: { amount: body.amount, currency: body.currency },
});
if (!isAllowed(decision)) return res.writeHead(403).end(decision.reasons[0].code);
```

`kya.verify(body)` forwards a complete `VerifyRequest` body instead. A runnable
end-to-end example (agent client, business server, KYAgent in-process) is in
[`examples/sdk-quickstart.js`](../../examples/sdk-quickstart.js): `npm run example:sdk`.

HTTP status codes of `/v1/verify`:

| Status | Meaning |
|---|---|
| `200` | A decision (`ALLOW` or `DENY`). Malformed or oversized bodies return `200 DENY MALFORMED_REQUEST`. |
| `401` / `403` | Your API key is missing, revoked or not a business key. Error envelope, no decision. |
| `500` | Internal failure. The body still contains `decision: "DENY"` with `INTERNAL_ERROR`. |

### Credential vs. no credential

- **With `credential`**: the service checks the JWS (EdDSA, server key from
  `GET /.well-known/jwks.json`), that it was issued to this agent for your
  business, that it is bound to the agent's key (`cnf.jkt`), that neither it
  nor its grant has been revoked or has expired, and that its actions and the
  grant's constraints cover the request.
- **Without `credential`**: the service evaluates your active, unexpired grants
  to the agent directly, oldest first. The first grant that matches the action
  and satisfies its constraints wins.

### Reason codes

A `DENY` carries the first check that failed, in this order:

| Code | Meaning |
|---|---|
| `MALFORMED_REQUEST` | Body invalid, or unsigned fields differ from the signed ones |
| `AUDIENCE_MISMATCH` | Signed for a different business |
| `AGENT_NOT_FOUND` | Unknown agent |
| `AGENT_REVOKED` / `AGENT_SUSPENDED` | Agent is not active |
| `OPERATOR_SUSPENDED` / `OPERATOR_NOT_VERIFIED` | Accountable operator is not in good standing |
| `TIMESTAMP_OUT_OF_WINDOW` | Signed too long ago or in the future |
| `SIGNATURE_INVALID` | Signature does not verify with the agent's registered key |
| `NONCE_REPLAYED` | This signed request was already used |
| `CREDENTIAL_INVALID` | Credential malformed, wrong algorithm/issuer/key, or unknown |
| `CREDENTIAL_NOT_YET_VALID` / `CREDENTIAL_EXPIRED` | Outside the credential's validity period |
| `CREDENTIAL_SUBJECT_MISMATCH` | Credential issued to a different agent |
| `CREDENTIAL_AUDIENCE_MISMATCH` | Credential issued for a different business |
| `CREDENTIAL_KEY_MISMATCH` | Credential not bound to this agent's key |
| `CREDENTIAL_REVOKED` | Credential was revoked |
| `GRANT_REVOKED` / `GRANT_EXPIRED` | Underlying grant is no longer valid |
| `NO_GRANT` | You have no active grant for this agent |
| `ACTION_NOT_PERMITTED` | No grant or credential covers this action |
| `CONSTRAINT_VIOLATION` | Amount, currency or resource outside the grant's constraints |
| `INTERNAL_ERROR` | The service failed. Fail closed |
| `ALLOWED` | The only reason on an `ALLOW` |

## 5. Audit and revocation

- `GET /v1/verifications?agentId=…&decision=DENY` lists your past decisions
  (cursor-paginated with `limit` and `cursor`).
- You can revoke credentials whose audience is your business:
  `POST /v1/credentials/{id}/revoke {"reason": "…"}`.
- Revocation takes effect on the next `/v1/verify`. Nothing is cached.

## 6. Try it locally

`npm run example:sdk` starts the API in memory and runs a signed-request flow
end to end. `make demo-reset && make demo` (MongoDB Atlas required,
`MONGODB_URI`) serves the hackathon scenario. With its business key, the
dashboard at `/dashboard/` shows your grants, credentials and the
**Verifications** audit log.
