# Data Schema (MongoDB)

Database: `MONGODB_DB` (default `kyagent`). Connection: `MONGODB_URI`.
When `MONGODB_URI` is unset the service uses `MemoryStore`, which MUST enforce
the same uniqueness constraints and semantics (including nonce TTL by
comparing `expiresAt` to the clock on insert/lookup).

Conventions:
- `_id` is the prefixed string id (`agt_...`); the API exposes it as `id`.
- Timestamps stored as BSON `Date`; API serializes as ISO 8601 UTC.
- Documents never contain plaintext secrets or private keys.
- Collections are created and indexes ensured by `MongoStore.init()` at startup (idempotent).
- Status changes are single-document atomic `updateOne` with a status precondition
  (e.g. `{ _id, status: 'active' }` → `revoked`); `matchedCount == 0` ⇒ `INVALID_STATE`/`NOT_FOUND`.

## `api_keys`

| Field | Type | Notes |
|---|---|---|
| `_id` | string | `key_...` |
| `name` | string | 1..100 |
| `role` | `'admin' \| 'operator' \| 'business'` | |
| `ownerId` | string \| null | `op_...` / `biz_...` / null for admin |
| `secretHash` | string | hex HMAC-SHA256(pepper, secret). **Never returned by API.** |
| `status` | `'active' \| 'revoked'` | |
| `createdAt`, `lastUsedAt`, `revokedAt` | Date \| null | `lastUsedAt` updated best-effort (may be throttled to once/min) |

Indexes: `{ role: 1, ownerId: 1 }`.

## `businesses`

| Field | Type | Notes |
|---|---|---|
| `_id` | string | `biz_...` |
| `name` | string | 1..200 |
| `status` | `'active' \| 'suspended'` | |
| `createdAt` | Date | |

## `operators`

| Field | Type | Notes |
|---|---|---|
| `_id` | string | `op_...` |
| `type` | `'individual' \| 'organization'` | |
| `legalName` | string | 1..200 |
| `contactEmail` | string | lowercased, ≤ 254 |
| `country` | string | ISO 3166-1 alpha-2 |
| `status` | `'pending' \| 'verified' \| 'rejected' \| 'suspended'` | |
| `verification` | object \| null | `OperatorVerification` |
| `statusReason` | string \| null | |
| `createdAt`, `updatedAt` | Date | |

Indexes: `{ status: 1 }`, `{ contactEmail: 1 }` (non-unique).

State machine: `pending → verified | rejected` (via verification);
`rejected → verified | rejected` (re-run verification allowed);
`verified → suspended` (admin); `suspended` is terminal in MVP.
Verification on `verified` or `suspended` ⇒ `409 INVALID_STATE`.

Mock KYC/sanctions (deterministic):
- `kycResult = 'fail'` iff `legalName` contains `FAIL_KYC` (case-insensitive), else `'pass'`.
- `SANCTIONS_MODE=mock`: `sanctionsResult = 'hit'` iff `legalName` contains `SANCTIONED` (case-insensitive), else `'clear'`.
- `SANCTIONS_MODE=off`: `sanctionsResult = 'skipped'`.
- `status = 'verified'` iff `kycResult == 'pass'` and `sanctionsResult != 'hit'`, else `'rejected'`.

## `agents`

| Field | Type | Notes |
|---|---|---|
| `_id` | string | `agt_...` |
| `operatorId` | string | immutable after creation |
| `name` | string | 1..100 |
| `description` | string \| null | ≤ 1000 |
| `publicKey` | string | b64u raw Ed25519 key (43 chars) |
| `keyThumbprint` | string | RFC 7638 thumbprint |
| `status` | `'active' \| 'suspended' \| 'revoked'` | `revoked` terminal |
| `statusReason` | string \| null | |
| `createdAt`, `updatedAt`, `revokedAt` | Date \| null | |

Indexes: `{ publicKey: 1 }` **unique**, `{ keyThumbprint: 1 }` **unique**, `{ operatorId: 1, createdAt: -1 }`.

## `grants`

| Field | Type | Notes |
|---|---|---|
| `_id` | string | `grt_...` |
| `businessId` | string | grantor |
| `agentId` | string | |
| `operatorId` | string | denormalized from agent |
| `actions` | string[] | 1..50 action patterns, deduplicated |
| `constraints` | object | `GrantConstraints`, `{}` if none |
| `status` | `'active' \| 'revoked'` | `revoked` terminal |
| `expiresAt` | Date | |
| `createdAt`, `revokedAt` | Date \| null | |
| `statusReason` | string \| null | |

Indexes: `{ agentId: 1, businessId: 1, status: 1, createdAt: 1 }`, `{ businessId: 1, createdAt: -1 }`, `{ operatorId: 1, createdAt: -1 }`.

Grant creation requires the agent to exist and be `active` (else `404`/`409 INVALID_STATE`).

## `credentials`

| Field | Type | Notes |
|---|---|---|
| `_id` | string | `crd_...` = JWS `jti` |
| `agentId`, `operatorId`, `businessId`, `grantId` | string | |
| `actions` | string[] | copy of grant actions at issue |
| `status` | `'active' \| 'revoked'` | |
| `issuedAt`, `expiresAt`, `revokedAt` | Date \| null | |
| `statusReason` | string \| null | |

The JWS string is **not** stored. Indexes: `{ agentId: 1, issuedAt: -1 }`, `{ businessId: 1, issuedAt: -1 }`, `{ grantId: 1 }`.

## `nonces` (replay protection)

| Field | Type | Notes |
|---|---|---|
| `_id` | string | `${agentId}:${nonce}` — uniqueness via primary key |
| `agentId` | string | |
| `expiresAt` | Date | `timestamp + 2 × KYA_SIGNATURE_MAX_SKEW_SECONDS` |

Indexes: TTL `{ expiresAt: 1 }, { expireAfterSeconds: 0 }`.
Insert with `insertOne`; duplicate key error (11000) ⇒ `NONCE_REPLAYED`.
Because the TTL is ≥ the acceptance window, a nonce cannot be reused while its
timestamp is still acceptable.

## `verification_events` (audit)

| Field | Type | Notes |
|---|---|---|
| `_id` | string | `vrf_...` |
| `businessId` | string | caller |
| `requestId` | string | |
| `agentId`, `operatorId`, `action`, `grantId`, `credentialId` | string \| null | |
| `decision` | `'ALLOW' \| 'DENY'` | |
| `reasons` | `{code, message}[]` | |
| `evaluatedAt` | Date | |

Indexes: `{ businessId: 1, evaluatedAt: -1 }`, `{ agentId: 1, evaluatedAt: -1 }`.
Append-only; never updated or deleted by the API. Never stores signatures,
credentials or context values (only the ids above).

## Store interface (implementation contract)

`src/store/Store.ts` exposes per-collection repositories with methods used by
services only, e.g.:

```ts
interface Store {
  init(): Promise<void>;
  close(): Promise<void>;
  kind: 'memory' | 'mongo';
  apiKeys: { insert; findById; list; revoke; touch };
  businesses: { insert; findById; list };
  operators: { insert; findById; list; update };
  agents: { insert; findById; list; setStatus };          // insert throws ConflictError on dup key
  grants: { insert; findById; list; findActiveFor(agentId, businessId, now); revoke };
  credentials: { insert; findById; list; revoke };
  nonces: { insertOnce(agentId, nonce, expiresAt): Promise<boolean> }; // false => replay
  verificationEvents: { insert; list };
}
```

List methods accept `{ filter, limit (1..100, default 50), cursor }` and return
`Page<T>` sorted by creation time descending (cursor = opaque base64url of last `_id` + time).
