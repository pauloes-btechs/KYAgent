# MongoDB Collections — Investigation Harness (binding)

Status: **frozen by T01**. Extends [`data-schema.md`](data-schema.md), which stays
authoritative for the existing collections. Companion contracts:
[`search-indexes.json`](search-indexes.json), [`investigation-pipeline.md`](investigation-pipeline.md),
[`harness.md`](harness.md), [`passport.md`](passport.md), [`receipt.schema.json`](receipt.schema.json).

Database: `MONGODB_DB` (default `kyagent`) on the cluster at `MONGODB_URI` (never logged).
Atlas acceptance tests use `ATLAS_TEST_URI` with a unique per-run database name.

## 0. Rules

1. **Atlas is the operational store.** Every collection below lives in Atlas in the demo.
   `SANCTIONS_MODE|CHAIN_MODE|LLM_MODE|EMBEDDINGS_MODE=fixture` change only the *data source*
   (fixture files loaded into Atlas), never the store. `MemoryStore` keeps plain CRUD doubles of
   the new repositories for unit tests only; `$search`, `$vectorSearch` and `watch()` on
   `MemoryStore` throw `AtlasRequiredError`.
2. **No renames.** `operators`, `grants`, `credentials` keep their names, ids and API. The new
   vocabulary is an alias layer (§1).
3. Conventions from `data-schema.md` apply: `_id` is a string id (except `harness_versions`,
   whose `_id` is the integer version), timestamps are BSON `Date`, no secrets in documents.
   Seeded demo documents carry `demo: true` and fixed ids (e.g. `agt_TREASURYBOT`); runtime ids
   are `prefix_` + ULID (prefixes in `types.ts` `INVESTIGATION_ID_PREFIXES`).
4. **Money** is an integer in the asset's minor units. USDC has 6 decimals:
   `25 000 USDC = 25000000000`. EVM addresses are stored **lowercased** (`^0x[0-9a-f]{40}$`).
5. **Hashed documents are integer-only.** `canonicalJson` (crypto-and-signing.md §3.1)
   rejects non-integers, so any fraction that is hashed (receipts, harness policies, harness
   events) is encoded as parts-per-million integers in fields suffixed `Ppm`
   (`0.78 → 780000`). API responses may additionally expose the float as `score`.
6. Validators are `$jsonSchema` with `validationLevel: "strict"`, `validationAction: "error"`,
   created by migrations `004`–`008` (T03). Regular indexes are created by those migrations and
   must stay `fakeDb`-compatible; Search/Vector indexes are created only by
   `ensureSearchIndexes()` from `search-indexes.json`.
7. Status changes use the existing conditional-update discipline (`updateIf` with a status
   precondition; `matchedCount == 0` ⇒ `INVALID_STATE`).

## 1. Alias mapping (new vocabulary → existing entities)

| Harness term | Stored in | Id | Mapping |
|---|---|---|---|
| **principal** | `operators` (+ read-only view `principals`) | `op_…` | principal := operator, the accountable owner of the agent. `principalId ≡ operatorId`. |
| **delegation** | `grants` | `grt_…` | delegation := grant. `delegationId ≡ grantId`. `constraints` stays authoritative for `/v1/verify`; new delegation fields are additive. |
| **passport** | `passports` + `credentials` | `pp_…` | The credential (JWS) is the cryptographic carrier; the `passports` document is the authoritative trust state. |
| **relying party** | `businesses` | `biz_…` | unchanged |
| **wallet** | `agents.wallets[]` | address | embedded |
| **counterparty** | `transactions.counterparty` | address | embedded, screened against `sanctions` |

API wire objects of the new endpoints use `principalId` / `delegationId`; they always carry the
same value as `operatorId` / `grantId`.

## 2. Existing collections — additive fields only

### `operators` (principal)
No new required fields. Seeded principals may use `verification.method: 'fixture'`
(stored directly by the seed, the public API still only produces `mock`).

### `principals` (VIEW, read-only)
```js
db.createView('principals', 'operators', [
  { $project: { _id: 1, principalId: '$_id', type: 1, legalName: 1, country: 1, status: 1,
                verification: 1, createdAt: 1, updatedAt: 1 } } ])
```
`contactEmail` is deliberately not projected. Owner: migration `004`. Nothing writes to it.

### `agents` — new optional fields
| Field | Type | Notes |
|---|---|---|
| `wallets` | `{ chain: 'evm', address: string, addedAt: Date }[]` | lowercased address; ≤ 10 |
| `signingKeyHistory` | `{ thumbprint: string, from: Date, to: Date \| null }[]` | appended when the registered key changes; the current key has `to: null` |

New index: `{ 'wallets.address': 1 }` (multikey). Owner: `src/services/agents.js`.

### `grants` (delegation) — new optional fields
| Field | Type | Notes |
|---|---|---|
| `asset` | `'USDC'` | asset of the delegation |
| `approvedWallet` | string | lowercased source wallet the agent may pay from |
| `maxTxAmount` | int | per-transaction max, minor units; **must equal `constraints.maxAmount`** when both set |
| `dailyLimit` | int | rolling-24 h total, minor units |
| `permittedTools` | string[] | e.g. `['usdc.transfer']` |
| `validFrom` | Date | not valid before |
| `version` | int ≥ 1 | bumps by 1 on every change to the fields above; recorded in passports and receipts |

Known deviation: the API pattern `GrantConstraints.currency` is ISO-4217 (3 letters) and is
**not** widened. Seeded USDC delegations store `constraints.currency: 'USDC'` directly
(the evaluator compares strings), so the existing `/v1/verify` constraint check still applies.
Owner: `src/services/grants.js`.

### `audit_events`
Unchanged shape. The closed type set is extended (by the implementing tasks, together with
`audit.test.js`) with the types listed in `types.ts` `HARNESS_AUDIT_EVENT_TYPES`.

## 3. New collections

### `transactions` (USDC history; `CHAIN_MODE=fixture` ⇒ loaded from `fixtures/transactions/*.json`)
| Field | Type | Notes |
|---|---|---|
| `_id` | string | `txn_…` |
| `agentId`, `principalId`, `delegationId` | string | |
| `wallet` | string | source wallet (lowercased) |
| `asset` | `'USDC'` | |
| `amount` | int > 0 | minor units |
| `counterparty` | `{ address: string, name: string \| null }` | lowercased address |
| `signingKeyThumbprint` | string | key that signed the action |
| `status` | `'settled' \| 'blocked' \| 'review'` | only `settled` counts for history and daily limit |
| `investigationId` | string \| null | set for transactions created by the pipeline |
| `at` | Date | |
| `source` | `'fixture' \| 'pipeline' \| 'chain'` | |

Indexes: `{ agentId: 1, at: -1 }`, `{ 'counterparty.address': 1 }`, `{ agentId: 1, 'counterparty.address': 1 }`, `{ delegationId: 1, status: 1, at: -1 }`.
Validator: required `_id, agentId, wallet, asset, amount, counterparty, signingKeyThumbprint, status, at`; `amount` `long|int` ≥ 1.
Owner: `src/investigation/signals.js` (read), `src/services/investigations.js` (insert on decision), seed (fixture).

### `sanctions`
| Field | Type | Notes |
|---|---|---|
| `_id` | string | `sdn_…` (stable per listed entity) |
| `name` | string | primary name |
| `aliases` | string[] | |
| `type` | `'entity' \| 'individual'` | |
| `programs` | string[] | e.g. `['CYBER2']` |
| `wallets` | `{ chain: 'evm', address: string }[]` | lowercased |
| `datasetVersion` | string | `YYYY-MM-DD` of the dataset that last wrote this document |
| `source` | `'fixture' \| 'ofac'` | |
| `updatedAt` | Date | |

Indexes: `{ 'wallets.address': 1 }` (**the exact-match invariant index**), `{ datasetVersion: 1 }`.
Search index: `sanctions_search` (search-indexes.json).
Validator: required `_id, name, aliases, type, wallets, datasetVersion`; `wallets.address` pattern `^0x[0-9a-f]{40}$`.
Owner: `src/sanctions/screen.js` (read), `scripts/apply-sanctions-update.js` (write via upsert — a real write, so the change stream fires).

### `sanctions_updates` (staged dataset deltas)
| Field | Type | Notes |
|---|---|---|
| `_id` | string | `upd_<datasetVersion>` |
| `datasetVersion` | string | |
| `upserts` | sanctions documents (without `datasetVersion`) | |
| `status` | `'staged' \| 'applied'` | |
| `stagedAt`, `appliedAt` | Date \| null | |

Indexes: `{ status: 1, datasetVersion: 1 }`. Owner: `scripts/apply-sanctions-update.js`
(`staged → applied` via `updateIf`, then upserts each entry into `sanctions` with the new `datasetVersion`).

### `investigations`
| Field | Type | Notes |
|---|---|---|
| `_id` | string | `inv_…` |
| `trigger` | `'api' \| 'sanctions_change' \| 'manual'` | |
| `triggerRef` | object \| null | e.g. `{ sanctionsId, datasetVersion, changeEventId }` |
| `initiatedBy` | `{ role: Role \| 'system', apiKeyId, ownerId }` | used by `INV_NO_SELF_APPROVAL` |
| `agentId`, `principalId`, `businessId`, `delegationId`, `delegationVersion` | string / int \| null | |
| `action` | string \| null | |
| `transaction` | `{ asset, amount, wallet, counterparty: { address, name } }` \| null | from the **signed** context |
| `harnessVersion` | int | active version at start |
| `stages` | `StageResult[]` | shape in investigation-pipeline.md §3 |
| `signals` | `Signal[]` | |
| `memory` | `{ engine: '$vectorSearch', k, minScorePpm, hits: MemoryHit[] }` | |
| `decision` | `'ALLOW' \| 'DENY'` | identity-layer verdict (same vocabulary as `/v1/verify`) |
| `riskDecision` | `'ALLOW' \| 'REVIEW' \| 'BLOCK'` | |
| `reasons` | `RiskReason[]` | first element is the primary reason |
| `status` | `'DECIDED' \| 'AWAITING_REVIEW' \| 'CONFIRMED'` | REVIEW ⇒ `AWAITING_REVIEW` |
| `outcome` | `'CLEAN' \| 'CONFIRMED_ACCOUNT_TAKEOVER' \| 'FALSE_POSITIVE' \| 'SANCTIONS_MATCH'` \| null | set by confirm |
| `confirmedBy`, `confirmedAt` | actor / Date \| null | |
| `passport` | `{ id, before, after }` \| null | passport status transition caused, if any |
| `receipt` | `Receipt` (embedded copy) | see receipt.schema.json |
| `receiptId` | string | |
| `requestId` | string \| null | trace id |
| `createdAt`, `decidedAt` | Date | |

Indexes: `{ agentId: 1, createdAt: -1 }`, `{ businessId: 1, createdAt: -1 }`, `{ status: 1, createdAt: -1 }`, `{ trigger: 1, createdAt: -1 }`.
Validator: required `_id, trigger, agentId, harnessVersion, stages, riskDecision, reasons, status, createdAt`; `riskDecision` enum; `trigger` enum.
Owner: `src/services/investigations.js` (the only writer). Stages/receipt are immutable after `decidedAt`; only `status, outcome, confirmedBy, confirmedAt` change (via confirm).

### `security_memories`
| Field | Type | Notes |
|---|---|---|
| `_id` | string | `mem_<sourceInvestigationId>` (e.g. `mem_INV-1042`, `mem_inv_01J…`) |
| `title` | string | |
| `status` | `'UNVERIFIED' \| 'VERIFIED' \| 'REJECTED'` | only `VERIFIED` is retrievable |
| `outcome` | Outcome \| null | set at verification |
| `signals` | `Signal[]` | |
| `signalsText` | string | deterministic text built from signals (`src/memory/signalsText.js`) |
| `embedding` | double[1024] | model output for `signalsText` |
| `embeddingModel` | string | e.g. `voyage-3.5-lite` |
| `embeddingTextSha256` | string | sha256 hex of `signalsText` (fixture lookup key) |
| `recommendedSteps` | string[] | adaptive step ids (harness.md §3.3) |
| `sourceInvestigationId` | string | |
| `agentId`, `principalId` | string \| null | |
| `verifiedBy` | actor \| null | never the case's agent/principal/initiator (`INV_NO_SELF_APPROVAL`) |
| `verifiedAt`, `createdAt` | Date | |

Indexes: `{ status: 1, createdAt: -1 }`, `{ sourceInvestigationId: 1 }` unique.
Vector index: `memory_vector` (search-indexes.json).
Validator: required `_id, title, status, signals, signalsText, embedding, embeddingModel, createdAt`; `embedding` array of exactly 1024 numbers (`minItems`/`maxItems` 1024); if `status == 'VERIFIED'` then `verifiedBy`, `verifiedAt`, `outcome` required (`oneOf`).
Owner: `src/services/investigations.js` (insert UNVERIFIED candidate on REVIEW; promote on confirm), `src/memory/retrieve.js` (read).

### `passports`
Full contract in [`passport.md`](passport.md). Indexes: `{ agentId: 1 }` **unique**, `{ status: 1 }`, `{ 'wallet': 1 }`.
Validator: required `_id, agentId, principalId, delegationId, delegationVersion, status, harnessVersion, statusHistory, issuedAt`; `status` enum.
Owner: `src/services/passports.js` (the only writer; `transition()`).

### `receipts`
One document per investigation: the receipt object of [`receipt.schema.json`](receipt.schema.json)
stored with `_id = receiptId` (`rcp_…`). Indexes: `{ investigationId: 1 }` **unique**, `{ agentId: 1, issuedAt: -1 }`, `{ receiptHash: 1 }`.
Validator: required `_id, investigationId, riskDecision, receiptHash, issuedAt`. Insert-only.
Owner: `src/services/receipts.js`. Anchored by an `audit_events` entry of type `receipt.issued` (`data.receiptHash`).

### `harness_versions`
Full contract in [`harness.md`](harness.md) §4. `_id` = integer `version`.
Indexes: `{ status: 1 }` **unique partial** `{ partialFilterExpression: { status: 'active' } }` (at most one active version).
Validator: required `_id, version, status, invariantsHash, policy, policyHash, createdAt, approvedBy`; top-level and `policy` `additionalProperties: false`, which rejects `invariants`, `skipInvariants` or any other invariant-touching key.
Owner: `src/harness/policy.js` (read), `src/services/investigations.js#confirm` (insert vN+1, supersede vN).

### `harness_events`
Full contract in [`harness.md`](harness.md) §5. Indexes: `{ at: -1 }`, `{ toVersion: 1 }`. Insert-only.
Owner: `src/harness/adaptation.js`.

### `watcher_state`
| Field | Type | Notes |
|---|---|---|
| `_id` | string | watcher name, e.g. `sanctions` |
| `resumeToken` | object \| null | last processed change-stream `_id` |
| `lastEventAt` | Date \| null | |
| `lastDatasetVersion` | string \| null | |
| `updatedAt` | Date | |

Written **after** an event is fully processed (at-least-once; handlers are idempotent via
passport `updateIf` preconditions). Owner: `src/watchers/sanctionsWatcher.js`.

## 4. Reset scope (`make demo-reset`)

Drops documents with `demo: true` and the collections `investigations, harness_events,
watcher_state, passports, receipts`; restores `harness_versions` to v1 only; re-seeds; re-runs
migrations and `ensureSearchIndexes()` until both indexes are `queryable`. `audit_events` is
never deleted by reset in production databases; the demo database may be dropped as a whole.
