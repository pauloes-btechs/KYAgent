# Error Model

KYAgent has two distinct failure channels. Do not mix them.

1. **HTTP errors** — the request could not be processed as a management/API
   operation (bad auth, bad input, missing resource). Body = `ErrorBody`.
2. **Verification decisions** — `POST /v1/verify` evaluated (or failed to
   evaluate) an agent request. Body = `VerifyResponse` with `decision` and
   `reasons`. A failed verification is **not** an HTTP error.

## 1. HTTP error envelope

```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Request body is invalid",
    "requestId": "req_01J8...",
    "details": [{ "path": "/actions/0", "message": "must match pattern ..." }]
  }
}
```

- `code` is stable and machine-readable; `message` is human-readable, safe to show,
  and MUST NOT contain secrets, stack traces, key material or internal hostnames.
- `requestId` equals the `X-Request-Id` response header. If the client sends a
  valid `X-Request-Id` (`^[A-Za-z0-9_.-]{1,64}$`) it is echoed; otherwise the
  server generates `req_<ULID>`.
- `details` only for `VALIDATION_ERROR`; `path` is a JSON Pointer into the body
  (or `/query/<name>`, `/params/<name>`).

| Code | HTTP | When |
|---|---|---|
| `VALIDATION_ERROR` | 400 | Body/query/path fails schema, unknown fields, bad proof of possession, invalid expiry/TTL, malformed JSON |
| `UNAUTHENTICATED` | 401 | Missing/malformed/unknown/revoked API key, owner suspended. Includes `WWW-Authenticate: Bearer` header. Same message for every cause. |
| `FORBIDDEN` | 403 | Authenticated but role not allowed for the endpoint (RBAC matrix) |
| `NOT_FOUND` | 404 | Resource doesn't exist **or belongs to another tenant** |
| `CONFLICT` | 409 | Uniqueness violation (e.g. public key already registered) |
| `INVALID_STATE` | 409 | Operation not allowed in current state (revoke already-revoked item, issue credential for revoked grant/agent, verify an operator that is suspended) |
| `OPERATOR_NOT_VERIFIED` | 409 | Operator is not `verified` and tries to register an agent or issue a credential |
| `PAYLOAD_TOO_LARGE` | 413 | Body > `KYA_MAX_BODY_BYTES` |
| `UNSUPPORTED_MEDIA_TYPE` | 415 | Non-JSON body on a JSON endpoint |
| `INTERNAL_ERROR` | 500 | Unexpected error. Logged with stack server-side; generic message to client |
| `SERVICE_UNAVAILABLE` | 503 | Store unreachable at request time |

Revocation endpoints are **not idempotent-silent**: revoking an already revoked
object returns `409 INVALID_STATE`. (Clients can treat 409 on revoke as success.)

Unknown routes ⇒ `404 NOT_FOUND` in the same envelope. Unsupported method ⇒ `404`.

## 2. `/v1/verify` semantics

Authentication and authorization of the **calling business** happen first and
use HTTP errors (`401`, `403`) — no decision is produced and no event is recorded.

Everything after that yields a decision:

| Situation | HTTP | Body |
|---|---|---|
| Evaluation completed (ALLOW or DENY) | 200 | `VerifyResponse` |
| Malformed JSON / schema-invalid body / oversized body | 200 | `VerifyResponse` with `DENY` + `MALFORMED_REQUEST` (fields that could not be parsed are `null`) |
| Any exception / store failure during evaluation | 500 | `VerifyResponse` with `DENY` + `INTERNAL_ERROR` |

Clients MUST treat anything other than HTTP 200 with `decision == "ALLOW"` as a denial.

Note: for `/v1/verify` specifically, body-parse and schema errors do **not**
produce `400 VALIDATION_ERROR`; they produce a `DENY` decision so that naive
callers fail closed. Oversized bodies (413 at the framework level) MUST also be
mapped to a 200 `DENY`/`MALFORMED_REQUEST` decision on this route.

## 3. Verification reason codes

Evaluated in the order of ARCHITECTURE.md §3. `DENY` responses carry exactly one reason.

| Code | Decision | Meaning |
|---|---|---|
| `ALLOWED` | ALLOW | All checks passed |
| `MALFORMED_REQUEST` | DENY | Body invalid, or unsigned fields disagree with signed fields |
| `AUDIENCE_MISMATCH` | DENY | `signedRequest.audience` ≠ calling business |
| `AGENT_NOT_FOUND` | DENY | Unknown `agentId` |
| `AGENT_REVOKED` | DENY | Agent permanently revoked |
| `AGENT_SUSPENDED` | DENY | Agent suspended |
| `OPERATOR_NOT_VERIFIED` | DENY | Operator `pending` or `rejected` |
| `OPERATOR_SUSPENDED` | DENY | Operator suspended by admin |
| `TIMESTAMP_OUT_OF_WINDOW` | DENY | Signed timestamp outside allowed skew |
| `SIGNATURE_INVALID` | DENY | Signature does not verify with the agent's key |
| `NONCE_REPLAYED` | DENY | Nonce already used by this agent |
| `CREDENTIAL_INVALID` | DENY | Credential unparsable, bad signature/alg/typ/kid/iss, or unknown `jti` |
| `CREDENTIAL_NOT_YET_VALID` | DENY | `nbf` in the future |
| `CREDENTIAL_EXPIRED` | DENY | `exp` passed |
| `CREDENTIAL_SUBJECT_MISMATCH` | DENY | `sub` ≠ agent |
| `CREDENTIAL_AUDIENCE_MISMATCH` | DENY | `aud` ≠ calling business |
| `CREDENTIAL_KEY_MISMATCH` | DENY | `cnf.jkt` ≠ agent key thumbprint |
| `CREDENTIAL_REVOKED` | DENY | Credential revoked |
| `GRANT_REVOKED` | DENY | Underlying grant revoked |
| `GRANT_EXPIRED` | DENY | Underlying grant expired |
| `NO_GRANT` | DENY | No credential presented and no active grant from this business |
| `ACTION_NOT_PERMITTED` | DENY | Action outside granted scope |
| `CONSTRAINT_VIOLATION` | DENY | Amount/currency/resource constraint not met |
| `INTERNAL_ERROR` | DENY | Evaluation error; fail closed |

Reason `message` strings are informational; they MUST NOT reveal key material,
other tenants' data, or whether an agent exists beyond what the code conveys.
