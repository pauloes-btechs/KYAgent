# Investigation Pipeline (binding)

Status: **frozen by T01**. Implementation: `src/investigation/pipeline.js` (T07 skeleton, T14
final). Collections: [`mongo-collections.md`](mongo-collections.md). Decision values:
[`decision-vocabulary.md`](decision-vocabulary.md). Policy and invariants: [`harness.md`](harness.md).

## 1. Stage order

```
identity -> delegation -> sanctions -> signals -> memory -> [adaptive steps] -> policy -> decision
```

- `harness_versions.policy.steps` lists every stage **except** `decision`, which is always
  appended. v1 = `['identity','delegation','sanctions','signals','memory','policy']`
  (6 steps, 7 stages in the output). Adaptive steps (e.g. `signing_key_history_check`) are
  inserted between `memory` and `policy`.
- The six core stages are mandatory and their relative order is fixed by code; a policy that
  omits or reorders them fails `validatePolicy()`.
- After `decision` the service (not a stage) persists: receipt → `receipts` + `audit_events`
  `receipt.issued` → `investigations` → passport transition (if any) → `transactions` row.

## 2. Triggers

| `trigger` | Started by | Input | Identity stage mode |
|---|---|---|---|
| `api` | `POST /v1/investigations` (admin, business) | `InvestigationRequest` = `VerifyRequest` whose signed `context` is a `PaymentContext` | `signed`: the full `/v1/verify` evaluation (ARCHITECTURE §3 steps 1–8; consumes the nonce) |
| `sanctions_change` | `src/watchers/sanctionsWatcher.js` (system actor) | `{ agentId, triggerRef: { sanctionsId, datasetVersion, changeEventId } }` | `state`: agent `active`, operator `verified`; signature/nonce steps recorded `not_applicable` |
| `manual` | `POST /v1/demo/{id}/run` (dev only) or admin tooling | as `api` or as `sanctions_change` | as above |

`PaymentContext` (inside the signed `context`, integers only):
`{ amount: int (minor units), currency: 'USDC', counterparty: '0x…', counterpartyName?: string, wallet?: '0x…' }`.
`wallet` defaults to the agent's first wallet. Because the values are signed, the pipeline
never takes transaction data from unsigned fields.

For `sanctions_change` the transaction under test is synthetic: the agent's wallet plus every
distinct counterparty of its last 90 days of `transactions`; `amount` is absent and amount
signals/invariants are recorded `not_applicable`.

## 3. Stage result shape (every stage, including adaptive steps)

```ts
interface StageResult {
  name: string;               // PipelineStageName or adaptive step id
  engine: StageEngine;        // how MongoDB/code produced it (table below)
  status: 'passed' | 'failed' | 'flagged' | 'skipped' | 'error';
  startedAt: IsoDateTime;
  durationMs: number;         // integer
  result: object;             // stage-specific, below
  evidence: EvidenceItem[];
  reasons: RiskReason[];      // reasons this stage contributed (decision-vocabulary.md §5)
}
interface EvidenceItem {
  id: string;                 // stable within the investigation, e.g. "sanctions:sdn_123"
  kind: 'identity' | 'delegation' | 'sanctions_exact' | 'sanctions_fuzzy' | 'signal'
      | 'memory' | 'invariant' | 'policy' | 'passport' | 'step';
  source: string;             // collection or module, e.g. "sanctions", "security_memories"
  ref: string | null;         // document id
  summary: string;            // one line, non-secret
  data: object;               // integers only when hashed (scores as *Ppm)
}
```

`failed` = the stage fired a BLOCK reason; `flagged` = REVIEW reason or signals present;
`skipped` = short-circuited; `error` = threw (⇒ fail closed, §5).

## 4. Stages

| # | Stage | Engine | `result` | Evidence |
|---|---|---|---|---|
| 1 | `identity` | `code` (verification.js `identityStage()`, extracted from `evaluate()`) | `{ mode: 'signed'\|'state', decision: 'ALLOW'\|'DENY', reasonCode: ReasonCode, agentId, principalId, keyThumbprint }` | `identity`: agent status, operator status, signature/nonce/credential outcome. **DENY ⇒ short-circuit**: stages 2–N `skipped`, decision `BLOCK IDENTITY_DENIED`. |
| 2 | `delegation` | `find` (`grants`) + `code` (`authz.js`) | `{ delegationId, delegationVersion, asset, approvedWallet, maxTxAmount, dailyLimit, spent24h, amount, withinMax, withinDaily, walletApproved, assetPermitted, reasonCode }` | `delegation` + `invariant` items for `INV_DELEGATION_MAX` / `INV_DAILY_LIMIT` (`spent24h` = sum of `settled` `transactions` for the delegation in the last 24 h, aggregation). Failures add BLOCK reasons but **do not short-circuit** (evidence completeness). |
| 3 | `sanctions` | `find` (exact) **then** `$search` (`sanctions_search`) | `{ datasetVersion, screened: [{ role: 'wallet'\|'counterparty', address, name }], exactHits: [{ sanctionsId, address, name, programs }], fuzzyHits: [{ sanctionsId, name, matched, scorePpm }] }` | (a) `find({ 'wallets.address': { $in: [wallet, counterparty] } })` on the B-tree index — any hit ⇒ `INV_SANCTIONS_EXACT_BLOCK` ⇒ BLOCK `SANCTIONS_EXACT_MATCH`, deterministic, never dependent on `$search`. (b) `$search` `compound.should` over `text { path: ['name','aliases'], fuzzy: { maxEdits: 2 } }` + `text` on the `phonetic` multi paths for `counterpartyName`; top 5 with `$meta: 'searchScore'`; hits ≥ the policy's fuzzy threshold ⇒ `SANCTIONS_FUZZY_MATCH` (REVIEW-grade evidence). `datasetVersion` = max `datasetVersion` in `sanctions`. |
| 4 | `signals` | `aggregate` (`transactions`: `$group` + `$percentile` p50/p95, velocity window, first-seen) | `{ signals: Signal[], stats: { txCount, p50, p95, velocity1h, knownCounterparty, knownWallet, historicalThumbprints } }` | one `signal` item per signal with the inputs that produced it. Closed set: `NEW_WALLET`, `NEW_COUNTERPARTY`, `SIGNING_KEY_CHANGED`, `AMOUNT_ANOMALY` (> p95), `VELOCITY`, `NEAR_CEILING` (≥ 90 % of `maxTxAmount` or of the remaining daily limit). |
| 5 | `memory` | `$vectorSearch` (`memory_vector`) | `{ engine: '$vectorSearch', queryTextSha256, embeddingModel, k, numCandidates, minScorePpm, hits: MemoryHit[], droppedBelowScore: int, droppedUnverified: int }` | `{ index: 'memory_vector', path: 'embedding', queryVector: embed(signalsText(signals)), numCandidates, limit: k, filter: { status: 'VERIFIED' } }` + `$project { score: { $meta: 'vectorSearchScore' } }`. Hits `< minScore` are dropped (never context, never precedent). Any non-`VERIFIED` hit is dropped and recorded (`INV_UNVERIFIED_MEMORY_NOT_PRECEDENT`). Kept hits become `memory` evidence. |
| 5+ | adaptive steps | `code` / `find` / `aggregate` | step-specific (harness.md §3.3) | `step` items. Adaptive steps add evidence only; they cannot set a decision. |
| 6 | `policy` | `code` (`src/harness/invariants.js` + active `harness_versions`) | `{ harnessVersion, invariantsHash, policyHash, invariants: [{ id, held: boolean }], passportStatus, escalationsFired: [ruleId] }` | Evaluates all invariants over stage results, passport status, and the adaptive `escalation` rules (REVIEW only). Verifies active `invariantsHash == INVARIANTS_HASH` else BLOCK `HARNESS_INVARIANTS_MISMATCH`. |
| 7 | `decision` | `code` | `{ decision: 'ALLOW'\|'DENY', riskDecision, reasons: RiskReason[] }` | Combines all stage reasons by precedence `BLOCK > REVIEW > ALLOW` (decision-vocabulary.md). |

`MemoryHit = { memoryId, title, status: 'VERIFIED', outcome, score (float, API only), scorePpm, signals: Signal[], recommendedSteps: string[] }`.

Passport status in the policy stage: `SUSPENDED`/`REVOKED` ⇒ BLOCK; `REVIEW` ⇒ REVIEW;
`RE_SCREENING` ⇒ REVIEW only when `trigger == 'api'` (for `sanctions_change` it is the state
under evaluation and is ignored).

## 5. Failure semantics (fail closed)

Mirrors `verification.js` `verify()`: the whole run is wrapped in `try/catch`.
- Any stage throwing, a MongoDB error, `AtlasRequiredError`, an embedding failure, a missing
  or non-queryable search index, or a run exceeding its timeout ⇒ that stage `status: 'error'`,
  `riskDecision: 'BLOCK'`, reason `INTERNAL_ERROR`; the response is HTTP 500 with the
  investigation body when it could be persisted, else the standard error envelope.
- An empty `$search`/`$vectorSearch` result caused by a non-queryable index is an **error**,
  not a clean result (`ensureSearchIndexes()` must have reported `queryable`).
- If the receipt or its `receipt.issued` audit event cannot be written, the investigation is
  recorded `BLOCK / INTERNAL_ERROR` (same rule as `verification.decided`).
- The LLM (`LLM_MODE=live`) is never called inside a run; it only proposes policy diffs at
  confirmation time (harness.md §6).

## 6. Persistence and outputs

- `investigations` document (mongo-collections.md) with `stages[]` in execution order.
- `receipts` document + `audit_events` `receipt.issued` (`data: { receiptId, investigationId, receiptHash }`), and `investigation.decided`.
- REVIEW ⇒ an `UNVERIFIED` candidate in `security_memories` (`mem_<investigationId>`) with the
  case's signals and embedding; it is never retrievable until a human verifies it.
- Passport effects (passport.md §3): `api`: exact sanctions hit ⇒ `→ SUSPENDED`; REVIEW ⇒
  `ACTIVE → REVIEW`; delegation BLOCKs change nothing. `sanctions_change`: `RE_SCREENING →
  SUSPENDED | REVIEW | ACTIVE` by riskDecision `BLOCK | REVIEW | ALLOW`.
- `transactions` row: `status` = `settled` (ALLOW), `review`, or `blocked`.
- SSE (`GET /v1/events/stream`) emits `investigation.decided` and `passport.status_changed`.

## 7. Sanctions watcher (Change Streams)

`db.collection('sanctions').watch([{ $match: { operationType: { $in: ['insert','update','replace'] } } }], { fullDocument: 'updateLookup', resumeAfter: watcher_state.resumeToken })`.
Per event: affected agents = `agents.wallets.address ∈ doc.wallets.address` ∪
`transactions.counterparty.address ∈ doc.wallets.address` (distinct `agentId`) → for each:
passport `→ RE_SCREENING` (system) → run pipeline with `trigger: 'sanctions_change'` →
passport per §6 → then store the resume token in `watcher_state`. Started by `src/server.js`
only when `store.capabilities.changeStreams`.
