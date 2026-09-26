# KYAgent — MongoDB Hackathon Gap Analysis

Repo: `/tmp/ky` at `origin/run/run_e9845867bea8ab13` (= `origin/main` after PR #2), HEAD `7a5177b`.
Baseline: `node --test` → **131 tests, 131 pass, 0 fail** (Node 22.22, ~6.5 s). All tests run on `MemoryStore`.
Target: MongoDB "Harness Engineering & Model Wrangling", challenge "Recursive Harnessing".

---

## 1. Executive summary

KYAgent today is a clean, well-tested, **database-agnostic** agent identity and authorization service. It has Ed25519 agent identity with proof of possession, scoped expiring grants, key-bound JWS credentials, a deny-by-default `POST /v1/verify` (10 ordered check steps, 24 reason codes in `src/contracts.js:19`), revocation, a SHA-256 hash-chained append-only audit log, rate limiting, a vanilla-JS dashboard, an SDK and a Docker/Compose stack. MongoDB only appears as an **optional persistence adapter** (`src/store/mongo.js`). That adapter does plain `find`/`insertOne`/`findOneAndUpdate`: no `$search`, no `$vectorSearch`, no `watch()`, no aggregation pipelines. None of the five hackathon P0s exist: no sanctions dataset or MongoDB Search, no security memory or Vector Search, no change streams, no investigation or harness model. There are also no REVIEW/BLOCK decisions, no passports, no receipts, no behavioral signals and no evaluation. Sanctions screening is a regex over the operator's legal name (`src/services/kyc.js:10`, `/SANCTIONED/i`). **`npm run demo` hard-codes `new MemoryStore()` (`scripts/demo.js:26`), and the `mongodb` driver is not a dependency** (`package.json` has no `dependencies`, there is no lockfile or `node_modules`, and the Dockerfile runs `npm install mongodb@6` ad hoc). The single biggest risk: **MongoDB is not the mechanism anywhere**. Every demo-blocking P0 depends on Atlas-only features (Search, Vector Search, change streams on a replica set) that the in-memory store cannot emulate. The test suite, demo and CI are all built around that in-memory store, so the new core has to be built and verified against a live Atlas cluster that the repo has never touched.

**Scorecard:** 5 P0s → **4 MISSING, 1 PARTIAL** (P0-1 Atlas operational state is PARTIAL: a working Mongo adapter and migrations exist, but none of the required domain collections do, and the demo does not use Mongo).

---

## 2. Foundation to preserve

| Component | Files | Why it stays | Changes needed to fit the new design |
|---|---|---|---|
| Deterministic verification engine | `src/services/verification.js` (`checkWellFormed` l.26, `evaluate` l.51–129, `verify` l.137–211) | Audience, signature, nonce, credential and grant checks are a correct, tested **identity + delegation invariant stage**; 34 tests (`verify.test.js`, `verification.unit.test.js`) | Becomes **stage 1 (identity) + stage 5 (deterministic policy)** of a longer investigation pipeline. Extract `evaluate()` into `identityStage()` plus `delegationStage()`, which return structured results instead of throwing `Deny`. Keep `verify()` as the backwards-compatible ALLOW/DENY façade. |
| Constraint evaluator | `src/services/authz.js` (`constraintsSatisfied` l.15–27, `actionMatches` l.5) | Already enforces `maxAmount` / `currency` / `resources`: the "delegation max" invariant | Move the call into `src/harness/invariants.js` as `INV_DELEGATION_MAX`. Add `dailyLimit`, `approvedWallet`, `asset` constraints. |
| Hash-chained audit log | `src/services/audit.js` (`AUDIT_EVENT_TYPES` l.17, `auditHash` l.50, `record` l.108, `verifyChain` l.149); collection `audit_events`; migration `002_audit_events_indexes` | Tamper-evident, fail-closed, tested (`audit.test.js`, 7 tests) | **Feeds compliance receipts**: every receipt is anchored by an `audit_events` entry (`receipt.issued`), and the receipt stores `auditSeq` and `auditHash`. Add event types `investigation.*`, `passport.*`, `memory.promoted`, `harness.adapted`, `sanctions.updated` to the closed set (keep `test 'event types are a closed set'` green by updating the list). |
| Trust scoring | `src/services/trust.js` (`scoreAgent` l.133, `levelFor` l.39, `TRUST_RULES_VERSION` l.9); `dashboard/trust.js` | Explainable factor model; 6 + 5 tests | Maps to the **passport status projection**. `levelFor()` gates (`untrusted`) become inputs to `ACTIVE/REVIEW/SUSPENDED/REVOKED`. Add a `sanctions_exposure` factor fed by the investigation result. Stays advisory; the passport is the authoritative trust state. |
| Credentials (JWS) | `src/services/credentials.js` (`issue` l.19–86), `src/crypto/credentials.js` | Short-lived, key-bound (`cnf.jkt`), revocable, uncached status check | **Is the passport's cryptographic carrier.** A passport = credential + `passports` document with status and investigation link. Add claims `kya_passport`, `kya_delegation_v`, `kya_harness_v`. |
| Agents / operators / grants services | `src/services/agents.js`, `operators.js`, `grants.js` | State machines with conditional `updateIf` transitions and audit compensation | Alias: operator → **principal**, grant → **delegation** (§3 domain model). Add wallet fields to agents and delegation fields to grants. |
| Mongo adapter + migrations | `src/store/mongo.js` (lazy import l.63–71, `repo()` l.19), `src/store/migrations.js` (`MIGRATIONS` l.9, `runMigrations` l.60) | Versioned, idempotent, append-only migrations; tested with `fakeDb()` (`deploy.test.js:18`) | Add migrations `004`–`008` for new collections, and a **separate** `searchIndexes` step (`createSearchIndex` cannot run on `fakeDb`/community `mongo:7`). Expose `store.db` for aggregation stages. |
| Nonce/replay, rate limit, config, errors | `src/rateLimit.js`, `src/config.js`, `src/errors.js` | Security hygiene the judges will not see but which must not regress | `config.js:148–155` already recognises `SANCTIONS_MODE`, `CHAIN_MODE` and `LLM_MODE` (the last two ignored with warnings). Extend them to `live|fixture`. |
| SDK | `src/sdk/agentSigner.js`, `src/sdk/businessVerifier.js` | Signs demo agent actions; `isAllowed()` fails closed | `businessVerifier.js:146` accepts only `ALLOW|DENY`, so a REVIEW/BLOCK body is treated as garbage → `localDeny`. That is safe, but it must be updated to pass REVIEW/BLOCK through. |
| Dashboard shell | `dashboard/app.js` (658 lines, `api()` l.51, Verifications view l.559), `index.html`, `styles.css` | CSP-safe (no `innerHTML`: `dashboard.test.js:120`), auth flow | Add an **Investigation** view with evidence panels and an SSE/poll feed of passport changes. Keep the existing views. |
| Docker/Compose | `Dockerfile`, `docker-compose.yml` | Works for the local stack | Local `mongo:7` has **no Search/Vector Search and no replica set**. The demo must point at Atlas (or `mongodb/mongodb-atlas-local`). |

---

## 3. Requirement-by-requirement classification

### P0-1 Atlas operational state — **PARTIAL** · Effort M
- **Evidence:**
  - Existing collections: `api_keys, businesses, operators, agents, grants, credentials, nonces, verification_events, audit_events, schema_migrations` (`src/store/mongo.js:80–134`, `src/store/migrations.js:10–53`).
  - None of `principals, delegations, transactions, sanctions, investigations, security_memories, passports, harness_versions, harness_events` exists. `grep -rniE "investigat|passport|delegation|wallet|counterpart|harness"` over `src/` returns 0 hits.
  - **`npm run demo` → `scripts/demo.js`**, which imports `MemoryStore` (l.9) and calls `buildApp({ config, store: new MemoryStore() })` (l.26). It prints "in-memory; data is lost when this process exits" (l.91). **The live demo does not use MongoDB at all.**
  - `src/server.js:23` falls back to `MemoryStore` when `MONGODB_URI` is unset, and `config.js:144` only warns.
  - `scripts/seed.js` does require Mongo (l.25, l.33), but it seeds the old world (operator, business, "Invoice Bot (seed)" and a grant: `src/seed.js:10–21`).
  - Tests: `test/helpers.js:12` and `verification.unit.test.js:23` use `MemoryStore`; migrations are tested against `fakeDb()` (`deploy.test.js:18`). **Zero tests touch a real mongod.**
- **Gap:** new collections plus JSON-schema validators; `npm run demo` must use `MongoStore` against Atlas and refuse to start without `MONGODB_URI` (no silent in-memory substitution); fixture data loaded into Atlas, not into memory.
- **Reuse:** `repo()` pattern, `runMigrations`, `scripts/seed.js` Mongo guardrails (l.25–31).

### P0-2 MongoDB Search for sanctions — **MISSING** · Effort M
- **Evidence:**
  - Sanctions logic is `sanctionsScreen(legalName, mode)` → `/SANCTIONED/i.test(legalName)` (`src/services/kyc.js:8–11`). It runs only at operator onboarding (`operators.js` `verify`), never at `/v1/verify` time.
  - There is no sanctions collection, no `$search`, no `createSearchIndex`, and no wallet screening.
  - Test coverage is `api.test.js` 'operator onboarding: mock KYC and sanctions screening' and 'SANCTIONS_MODE=off skips screening…', both regex-based.
- **Gap:**
  - `sanctions` collection (entities, aliases, wallets, programme, `datasetVersion`).
  - Atlas Search index with `lucene.standard` plus a phonetic/`autocomplete` sub-field on `names` and a `token` mapping on `wallets.address`.
  - A deterministic exact-wallet stage (`find({ 'wallets.address': lower(addr) })`, index-backed) that runs **before** the fuzzy `$search` and constitutes an invariant hit.
  - Called from the investigation pipeline for the agent wallet and the counterparty. Results (score, matched alias, `datasetVersion`) go into evidence and the receipt.
  - Acceptance test against Atlas.
- **Reuse:** the `SANCTIONS_MODE` plumbing (`config.js:148`), the `trust.js` `operatorFactor` sanctions input, and the `api.test.js` onboarding tests (the regex stays as `SANCTIONS_MODE=fixture` for operator names only).

### P0-3 Vector Search + verified security memory — **MISSING** · Effort L
- **Evidence:** 0 hits for `vectorSearch|embedding|voyage|memor(y|ies)` in `src/`. `LLM_MODE` is explicitly ignored (`config.js:155`). There is no incident, outcome or memory concept, and no embeddings provider.
- **Gap:**
  - `security_memories` collection with `status ∈ {UNVERIFIED, VERIFIED, REJECTED}`, `signalsText`, `embedding[]`, `embeddingModel`, `outcome`, `sourceInvestigationId` and `verifiedBy`.
  - Vector index with a `filter` path on `status`.
  - Embedding provider: Voyage `voyage-3.5-lite` (1024-d) or Atlas automated embeddings; fixture fallback with precomputed vectors.
  - Seeded verified takeover incident `INV-1042`.
  - Retrieval stage using `$vectorSearch` with `filter: { status: 'VERIFIED' }` plus a score threshold.
  - A negative case: an irrelevant incident must fall below the threshold or rank below it.
  - Persistence across process restart (inherent to Atlas, but never exercised: the demo is in-memory).
- **Reuse:** none directly. The canonical JSON (`src/crypto/canonical.js`) can build a deterministic `signalsText`.

### P0-4 Change Streams / continuous KYA — **MISSING** · Effort M
- **Evidence:**
  - 0 hits for `.watch(` or `changeStream`. `dashboard/app.js` has no polling or SSE; its only timers are the toast (l.35) and the idle sign-out (l.111).
  - Agent statuses are `active|suspended|revoked` (`app.js:42`). There is no `RE-SCREENING` state.
  - Suspension is manual only (`agents.js:91–93`).
  - The local compose runs `mongo:7` standalone (no replica set), so change streams are impossible there.
- **Gap:**
  - `src/watchers/sanctionsWatcher.js`: `db.collection('sanctions').watch([{ $match: { operationType: { $in: ['insert','update','replace'] } } }], { fullDocument: 'updateLookup' })`, with the resume token persisted in `watcher_state`.
  - Affected-agent lookup by wallet or counterparty: `agents.wallets.address ∈ doc.wallets`, and `transactions.counterparty.address ∈ doc.wallets`.
  - Passport transition `ACTIVE → RE_SCREENING → SUSPENDED` via `updateIf`.
  - An investigation document with `trigger: 'sanctions_change'`.
  - A `GET /v1/events/stream` (SSE) endpoint the dashboard subscribes to.
  - Acceptance test on Atlas.
- **Reuse:** the `agents.setStatus` conditional transition (`mongo.js:90`), `audit.record`, and the `agents.suspend` state machine.

### P0-5 Adaptive harness (immutable invariants + versioned adaptive policy) — **MISSING** · Effort L
- **Evidence:** 0 hits for `harness|invariant|policy_version|adapt`. The only versioned rule sets are `TRUST_RULES_VERSION = 'kya-trust-v1'` (`trust.js:9`) and the migrations. Deterministic checks are hard-coded inline in `evaluate()` (`verification.js:51–129`).
- **Gap:**
  - `src/harness/invariants.js`, a frozen module with no DB-loaded config: `INV_SANCTIONS_EXACT_BLOCK`, `INV_DELEGATION_MAX`, `INV_NO_SELF_APPROVAL` (the memory verifier ≠ the investigation's agent/principal actor), `INV_NO_SELF_PASSPORT_MODIFICATION` (an agent API key cannot move its own passport), `INV_UNVERIFIED_MEMORY_NOT_PRECEDENT`. It carries an `INVARIANTS_HASH` constant asserted in tests.
  - `harness_versions` documents holding adaptive policy only: `memoryRetrieval {k, minScore, filters}`, `steps[]`, `contextAssembly`, `evidenceRequests[]`, `escalation` rules.
  - A **schema validator** that rejects any policy key that touches invariants.
  - `POST /v1/investigations/:id/confirm` (human, admin role): outcome `CONFIRMED_ACCOUNT_TAKEOVER` → memory `VERIFIED`, then `harnessAdaptation.propose()` → `harness_versions` v2 plus a `harness_events` entry `{fromVersion, toVersion, diff, evidence:[investigationId, memoryId], approvedBy, at}`. v2 adds the step `signing_key_history_check` and raises memory `k`.
  - The next case shows the extra step. The LLM (optional, `LLM_MODE`) may only propose a policy diff, validated against the schema.
- **Reuse:** the `migrations.js` append-only versioning discipline, `audit.recordOrCompensate`, and the `auditHash` pattern to hash each harness version.

### New vertical slice — **MISSING** · Effort L
- **Evidence:**
  - The current slice (`verify.test.js:17` 'vertical slice: registered agent signed request is ALLOWed and audited') is signed request → identity/grant checks → ALLOW/DENY → `verification_events` + `audit_events`.
  - Nothing after "deterministic policy" exists: no Search, signals, memory, receipt or investigation persistence. The data change → re-eval → trust state change path does not exist either.
- **Gap:**
  - `src/investigation/pipeline.js` with stages `identity → delegation → sanctions($search) → signals → memory($vectorSearch) → policy(invariants + harness) → decision → receipt → persist`.
  - The watcher path.
- **Reuse:** the `verify()` envelope (fail-closed audit, `verification.js:176–206`).

### Behavioral signals — **MISSING** · Effort M
- **Evidence:** there is no transactions collection. Transaction history is not stored; `verification_events` stores only ids and the decision (`verification.js:162–175`), deliberately **not** context values (`audit.js` header, "never … verification context values"). The only related signals are in `dashboard/trust.js` (deny-reason counts) and `trust.js` `ageFactor`.
- **Gap:**
  - `transactions` collection (USDC amount, wallet, counterparty, `signingKeyThumbprint`, `at`).
  - `src/investigation/signals.js` computing `NEW_WALLET`, `NEW_COUNTERPARTY`, `SIGNING_KEY_CHANGED`, `AMOUNT_ANOMALY` (vs median/p95 via a `$group` + `$percentile` aggregation, MongoDB 7.0+), `VELOCITY` (count in window), `NEAR_CEILING` (≥ 90 % of `maxTxAmount` or daily limit).
- **Reuse:** `keyThumbprint` on agents (`agents.js`); `constraints.maxAmount` on grants.

### Domain model — **PARTIAL** · Effort M
| Required | Existing | Recommendation |
|---|---|---|
| principal | `operators` (legal entity, KYC/sanctions verification) + `businesses` (relying party) | **Alias** principal := operator (the accountable owner). Add a `principals` **view** (`db.createView('principals','operators',…)`) or an API alias. Do not rename. |
| delegation | `grants` (`actions`, `constraints.maxAmount/currency/resources`, `expiresAt`, `status`) | **Alias** delegation := grant. Add fields `permittedTools[]`, `asset` ('USDC'), `approvedWallet`, `maxTxAmount` (= `constraints.maxAmount`), `dailyLimit`, `validFrom`, `version` (int, bumps on change), keeping `constraints` authoritative. |
| agent | `agents` (Ed25519 key, thumbprint, status) | Add `wallets[{chain:'evm', address, addedAt}]`, `signingKeyHistory[]`. |
| wallet (EVM) | none | Embedded in agents; index `wallets.address`. |
| transaction (USDC) | none | New `transactions` collection. |
| counterparty | none | Embedded in the transaction (`counterparty.address`, `counterparty.name`), screened via Search. |
| outcome | none | `investigations.outcome` ∈ `{CLEAN, CONFIRMED_ACCOUNT_TAKEOVER, FALSE_POSITIVE, SANCTIONS_MATCH}`. |
| verified memory | none | `security_memories`. |

### Decision vocabulary — **BROKEN vs requirement** (ALLOW/DENY only) · Effort S–M
- **Evidence:**
  - `types.ts:351` `type Decision = 'ALLOW' | 'DENY'`, `openapi.yaml:1081` `Decision: enum [ALLOW, DENY]`, `app.js:44` query enum.
  - `verification.js:161` `decision = code === 'ALLOWED' ? 'ALLOW' : 'DENY'`.
  - `businessVerifier.js:146` rejects anything else; `dashboard/app.js:559–570` counts DENY.
  - 85 assertions mention `decision`; `'DENY'` is asserted in 7 test files (`audit, dashboard, errors, sdk, security-negative, verification.unit, verify`).
- **How to extend without breaking tests:** keep `/v1/verify` returning `decision: ALLOW|DENY` exactly as-is (an identity-layer verdict). Add a **new** field `riskDecision: ALLOW|REVIEW|BLOCK` produced by the investigation endpoint `POST /v1/investigations` (and optionally echoed on `/v1/verify` behind `?investigate=1`). Mapping: identity DENY ⇒ `BLOCK`; identity ALLOW + invariant breach ⇒ `BLOCK`; identity ALLOW + escalation ⇒ `REVIEW`; else `ALLOW`. Add the new reason codes (`SANCTIONS_EXACT_MATCH`, `DELEGATION_MAX_EXCEEDED`, `MEMORY_PRECEDENT_TAKEOVER`, `PASSPORT_SUSPENDED`, …) to a **separate** `RISK_REASON_CODES` list, so `contracts.test.js` 'REASON_CODES match docs/contracts/types.ts and openapi.yaml' and `docs.test.js` 'business guide lists every verification reason code' stay unchanged.

### Passport — **PARTIAL** (credential exists, passport status model does not) · Effort M
- **Evidence:** the credential record (`credentials.js:40–52`) has `agentId, operatorId, businessId, grantId, actions, status(active|revoked), issuedAt, expiresAt`. The JWS claims (l.53–66) include `cnf.jkt`. It is short-lived (TTL capped by `credentialMaxTtlSeconds` and grant expiry). The only statuses are `active|revoked`.
- **Gap:** a `passports` collection `{_id, agentId, principalId, delegationId, delegationVersion, wallet, status: ACTIVE|REVIEW|SUSPENDED|REVOKED (+ transient RE_SCREENING), credentialId, lastInvestigationId, sanctionsDatasetVersion, harnessVersion, issuedAt, expiresAt, statusHistory[]}`. Status changes are made only by the pipeline or watcher (system actor), never by the agent itself (`INV_NO_SELF_PASSPORT_MODIFICATION`). The credential stays the signed carrier.

### Compliance receipt — **PARTIAL** · Effort M
- **Evidence:** `audit_events` fields are `id, seq, type, occurredAt, actor, subjectType, subjectId, requestId, data, prevHash, hash` (`audit.js:50–64`). `verification.decided` data = `decision, reasonCode, businessId, agentId, operatorId, action, grantId, credentialId` (`verification.js:184–193`). Present: decision, agent, principal (operatorId), timestamp, identity result (reasonCode), delegation id, trace id (`requestId`), plus tamper evidence.
- **Missing:** delegation-check detail and `delegationVersion`, sanctions results plus `sanctionsDatasetVersion`, behavior signals, retrieved memory (ids, scores, status), `policyVersion`, `harnessVersion`, an evidence array.
- **Plan:** a `receipts` collection (or `investigations.receipt` subdocument) whose `receiptHash` is recorded in a `receipt.issued` audit event, so the existing chain notarises it.

### P1 Demo 1 ALLOW / Demo 2 BLOCK (over delegation max) — **PARTIAL** · Effort S
- **Evidence:** `scripts/demo.js:74` 'payments:create 1500 USD with credential' → ALLOW; `:76` '50000 USD (over limit)' → `DENY CONSTRAINT_VIOLATION`. Tests: `verify.test.js:122` 'DENY: out-of-scope action and constraint violations' (l.127 amount 10001 → `CONSTRAINT_VIOLATION`), `verification.unit.test.js:292`, `deploy.test.js:121`, `sdk.test.js:178` (`/403 +CONSTRAINT_VIOLATION/`).
- **Gap:** USD not USDC, generic "Invoice Bot" not TreasuryBot, DENY not BLOCK, no receipt or evidence panel, and runs on MemoryStore.

### Demo seed data + make demo / make demo-reset — **MISSING** · Effort M
- **Evidence:** there is no `Makefile`. `src/seed.js` creates operator "Acme Robotics Ltd (seed)", business "Globex Payments (seed)", agent "Invoice Bot (seed)" and a grant for `payments:create, orders:*` up to 10000 USD for 30 days. There is no reset (`seedDemo` is insert-only and idempotent via a business-name check, l.28–29).
- **Gap (all absent):** 1 principal (Northwind Treasury Ltd), TreasuryBot, USDC delegation (max 25 000, daily 100 000, approved wallet), EVM wallet, ~30 clean historical transactions, verified takeover memory `INV-1042`, irrelevant memory (e.g. `INV-0977` rate-limit misconfiguration), baseline sanctions (~50 entities with aliases/wallets, `datasetVersion: 2026-09-01`), a pending sanctions update adding TreasuryBot's counterparty wallet (`datasetVersion: 2026-09-26`); `make demo` / `make demo-reset`.

### Required UI evidence panels — **MISSING** · Effort M
- **Evidence:** dashboard views are Operators, Agents, Agent lookup (trust), Grants, Credentials and Verifications (`dashboard/app.js:389–570`). Only the ALLOW/DENY table and deny-reason counts exist. `dashboard.test.js:120` restricts code to "only contract endpoints", so new endpoints must be added to the openapi contract first.
- **Gap:** an Investigation view with four panels (Current signals / MongoDB security memory retrieved via Vector Search, with score and VERIFIED badge / Harness version + extra step / Decision + receipt), plus a live Continuous-KYA strip (change detected → affected agent → re-screen → SUSPENDED) fed by SSE.

### Evaluation — **MISSING** · Effort M
- **Evidence:** there is no `eval/` directory and no metrics. Tests are pass/fail unit/integration only.
- **Gap:** golden-case fixtures plus a runner computing Recall@3, relevant-vs-irrelevant retrieval separation, golden decision correctness, cross-session persistence, change-stream re-screen success, and harness v1 vs v2 step diff. Results are produced by running, never hand-written.

### Fallback modes — **PARTIAL** · Effort S
- **Evidence:** `config.js:148–152` `SANCTIONS_MODE ∈ {mock, off}`; `CHAIN_MODE` and `LLM_MODE` produce "set but ignored" warnings (`config.js:154–155`); `config.test.js` covers warnings.
- **Gap:** `SANCTIONS_MODE=live|fixture` (live = OFAC SDN import, P4; fixture = seeded collection, still queried via `$search`), `CHAIN_MODE=live|fixture` (fixture = seeded transactions), `LLM_MODE=live|fixture` (fixture = deterministic template adaptation proposal), `EMBEDDINGS_MODE=live|fixture`. **Fixture ≠ in-memory**: every fixture mode still reads from Atlas.

### Tests that will break, and how to keep them green
| Change | Tests at risk | Mitigation |
|---|---|---|
| New decision values | `contracts.test.js` (REASON_CODES sync), `docs.test.js` 'business guide lists every verification reason code', `sdk.test.js` 'verifier fails closed…forged ALLOW', `errors.test.js:188`, `verify.test.js` (19) | Do not change `/v1/verify`'s `Decision`; add `riskDecision` + `RISK_REASON_CODES` in a new contract section with its own sync test. |
| New endpoints | `docs.test.js:38` 'openapi.yaml documents exactly the implemented endpoints'; `dashboard.test.js:120` 'only contract endpoints' | Add every route to `openapi.yaml` in the same PR (T01 freezes it). |
| New audit event types | `audit.test.js:189` 'event types are a closed set' | Extend `AUDIT_EVENT_TYPES` and the test list together. |
| New migrations | `deploy.test.js:42/49/64/75` (use `fakeDb()`) | Keep regular index migrations `fakeDb`-compatible. Put `createSearchIndex` in a separate `ensureSearchIndexes()` that runs only when `store.capabilities.atlasSearch`. |
| New store collections | `test/helpers.js` uses `MemoryStore` | Add the new repos to `MemoryStore` as **unit-test doubles only** (plain CRUD). Search/vector/watch methods throw `AtlasRequiredError` in memory, and Atlas-dependent tests live in `test/atlas/*.test.js`, gated by `ATLAS_TEST_URI` (skipped, and reported as skipped, when absent). |
| Demo script switch to Mongo | `sdk.test.js:172` runs `examples/sdk-quickstart.js` (memory), unaffected | Leave `examples/` on memory. Only `scripts/demo.js` changes. |
| Seed rewrite | `deploy.test.js:87` 'seed: creates a working demo world…' | Keep `seedDemo()` and add `seedHackathon()` in `src/seed/hackathon.js`. |

---

## 4. Risks and unknowns specific to Atlas

1. **Driver not present.** `package.json` has no `dependencies`; there is no lockfile or `node_modules`. `src/store/mongo.js:1–3,63–69` does `await import('mongodb')` lazily and throws "the 'mongodb' package is not installed" otherwise. Only the Dockerfile installs `mongodb@6` (unpinned minor, `--no-save`). **Action:** add `"mongodb": "^6.10"` (for `createSearchIndex` with `type: 'vectorSearch'`, supported since driver 6.6) as a real dependency and commit a lockfile. This breaks the "zero dependencies" claim in the Dockerfile comment and README. `deploy.test.js:185–192` asserts only `COPY scripts`, `USER node`, `.dockerignore` entries and the `env:init/migrate/seed` scripts, so switching the Dockerfile to `npm ci` is test-safe.
2. **Search / Vector Search indexes need Atlas** (or the `atlas-local` Docker image). Community `mongo:7` in `docker-compose.yml` cannot run `$search`/`$vectorSearch`. Index builds are asynchronous: after `createSearchIndex` you must poll `listSearchIndexes()` until `queryable: true`, typically seconds to minutes. `make demo` must wait, or the first query returns empty (a silent false negative, which is dangerous for sanctions).
3. **M0 free tier limit: 3 search indexes in total** (Search and Vector combined). Budget: (1) `sanctions_search`, (2) `memory_vector`, (3) spare (`counterparty`/`transactions` search or a second vector index). Use M10+ or Flex if more are needed. Rate limits on M0 also apply.
4. **Change streams require a replica set.** Atlas is fine. The local compose standalone is not. `MemoryStore` cannot emulate `watch()` faithfully (resume tokens, `fullDocument: 'updateLookup'`). Tests need Atlas (or `atlas-local`, which runs a single-node replica set). A documented `EventEmitter` double is acceptable for pure unit tests of the re-screen handler only, not as acceptance.
5. **Embeddings provider and dimension.** Voyage `voyage-3.5-lite` gives 1024-d (configurable 256/512/2048) and needs `VOYAGE_API_KEY`. Atlas automated embedding (auto-embed on Vector Search indexes) availability depends on tier/region: verify on the target cluster first. The index `numDimensions` must match exactly; switching providers means re-embedding and rebuilding the index. Fixture fallback: commit precomputed vectors for the seed memories plus the golden-case query texts, all produced by the same model.
6. **Determinism of Search for sanctions.** Fuzzy `$search` scores are not stable across index rebuilds. The **exact wallet hit must not depend on `$search`**: use a regular unique-ish index on `wallets.address` (lowercased), and treat `$search` output only as REVIEW-grade evidence.
7. **Resume-token persistence** for the sanctions watcher across restarts (store it in `watcher_state`); otherwise updates made while the process is down are missed (a Continuous-KYA gap).
8. **`$percentile` requires MongoDB 7.0+.** Atlas M0 runs 8.x, so this is fine, but the `fakeDb`/memory doubles need a JS fallback.
9. **Secrets/network:** Atlas IP allow-list and the SRV URI in `.env`; `config.js` treats `MONGODB_URI` as non-enumerable (l.181), which is good.

---

## 5. Verdict

The repo is a solid **identity and authorization foundation (~30 % of the new vertical slice by stage count: identity + delegation-max + audit)**, but it is **far from DEMO_READY** under the new definition. **0 of 5 P0s pass**: P0-1 is partial and P0-2 through P0-5 are entirely missing. The demo does not use MongoDB, there is no driver dependency, and no code path touches an Atlas-only feature. Nothing needs to be thrown away. `verification.js`, `authz.js`, `audit.js`, `credentials.js` and the migration framework slot in directly as the invariant stage, receipt notarisation and passport carrier. But the entire MongoDB-native loop (sanctions `$search`, verified memory `$vectorSearch`, change-stream re-screening, versioned harness adaptation), the seed world, the investigation UI and the evaluation have to be built. That is roughly 18–20 focused tasks, 60–70 % of them net-new code, gated on a working Atlas cluster with two search indexes on day 1.
