# Security review: the invariant boundary (T20)

Scope: the boundary between the immutable invariants (`src/harness/invariants.js`) and everything
that can change at runtime: the adaptive policy (`harness_versions`), adaptation proposals
(template or LLM), memory promotion, the investigation confirm endpoint, the sanctions watcher's
database identity and the logging of `MONGODB_URI`. Requirement REQ-P0-5; contract
`docs/contracts/harness.md`.

Each item below is checked only because a test in `test/security-harness.test.js` exercises it. The
`§n.m` tag on an item is the prefix of the test's name. `npm test` runs all of them offline
(MemoryStore, fixture modes). The Atlas end-to-end counterparts are in `test/atlas/` and are
skipped unless `ATLAS_TEST_URI` is set.

## Checklist

### 1. No policy path bypasses the invariants

- [x] **§1.1** The invariants are frozen code. `invariants.js` reads no environment variable, store
  or collection. The array, every element and every check are `Object.freeze`d. Unknown ids throw.
  Checks fail closed on missing input. The two delegation limits are the exception: they hold when
  no limit is configured (as `/v1/verify` steps 9i/10c), but a configured limit with a missing or
  malformed amount fails.
- [x] **§1.2** Only `investigations#confirm` (`src/services/investigations.js`) writes
  `harness_versions` or promotes a `security_memories` document. No HTTP write route touches
  harness versions or memories directly.
- [x] **§1.3** A stored policy that names an invariant key (`invariants`, `skipInvariants`,
  `overrides`, `allow`, `block`, at any depth), escalates to anything but `REVIEW`, reads
  unverified memory, or drops or reorders a core stage fails `validatePolicy()`. When that policy
  is the active version, `loadActiveHarness()` throws, so investigations fail closed.
- [x] **§1.4** The most permissive valid adaptive policy still BLOCKs an exact sanctions hit
  (`SANCTIONS_EXACT_MATCH`, `INV_SANCTIONS_EXACT_BLOCK`, case-insensitive) and a delegation
  breach (`DELEGATION_MAX_EXCEEDED`). Adaptive rules can only add `REVIEW` (`pipeline.js`
  `policyStage`), and `decide()` ranks BLOCK above everything else.
- [x] Self-passport modification: only the `system` actor or an admin may transition a passport,
  and no HTTP route transitions passports (see `test/passports.test.js`; the route list is
  asserted in §1.2).
- [x] If an active version's `invariantsHash` differs from the runtime `INVARIANTS_HASH`, the result
  is BLOCK `HARNESS_INVARIANTS_MISMATCH`, and no adaptation can be applied on top of it (see
  `test/harness.policy.test.js`).

### 2. LLM output is schema-validated and cannot reference invariants

- [x] **§2.1** An LLM diff goes through the same `evaluateProposal()` as the template. It is
  rejected if it adds `/invariants` or `/skipInvariants`, changes `/memoryRetrieval/filter` or
  `/sanctionsFuzzy`, lowers `minScorePpm`, removes a core stage, adds an `ALLOW` escalation or one
  carrying `overrides`, adds an unregistered step, uses `__proto__`, or replaces the document root.
  Prototype pollution does not occur.
- [x] **§2.2** Output that is not JSON, has no diff, or comes from an LLM call that threw or is not
  configured becomes a proposal with an `error`. `confirm` records that as `adaptation.rejected`;
  it never becomes a policy.
- [x] **§2.3** The LLM prompt contains the adaptive policy and case evidence only, never an
  invariant id or the word "invariant". The LLM is never called unless the promoted memory is
  `VERIFIED`. A valid diff is only a proposal: it still needs `approveAdaptation: true` from an
  approver who satisfies `INV_NO_SELF_APPROVAL`.

### 3. The watcher runs as a least-privilege DB user

- [x] **§3.1** `checkDbPrivileges(db, dbName)` (`src/store/mongo.js`) reads `connectionStatus`.
  It returns `ok` only when the user holds `readWrite` on the app database and nothing else. Any
  `atlasAdmin`, `*AnyDatabase`, `dbAdmin` role, any role on another database, or an
  unauthenticated connection is reported as excess.
- [x] **§3.2** `src/server.js` runs this check before it constructs the `SanctionsWatcher`. When
  `NODE_ENV=production`, an over-privileged user makes the process log a fatal line (role names
  only) and exit 1. In other environments it logs a warning. This works with a `readWrite`-only
  user at runtime because migrations that need `collMod` run from `make demo-reset` or
  `npm run migrate`, where an administrative URI is used once and not kept.

### 4. `MONGODB_URI` is never logged

- [x] **§4.1** Static grep: no `logger.*`, `console.*`, `process.stdout/stderr.write` or `fail()`
  call in `src/`, `scripts/` or `test/` refers to a URI value (`*.MONGODB_URI`,
  `*.ATLAS_TEST_URI`, `mongoUri`, `_uri`, `uri`). Mentioning the variable name inside a string
  literal is allowed. The grep's self-checks prove it sees template-literal interpolations. It
  cannot see a value that was first copied into an alias, so it is one layer, not the proof; the
  runtime checks below cover that case.
- [x] **§4.2** Runtime redaction: `createLogger` serialises through a `JSON.stringify` replacer
  that replaces every `mongodb://` / `mongodb+srv://` string (message, fields, nested values,
  driver error text) with `mongodb://[REDACTED]`. A replacer sees values after `toJSON()`, so
  Dates, ObjectIds and other existing field formats are unchanged.
- [x] **§4.3** `config.mongoUri` and `MongoStore._uri` are non-enumerable, so `JSON.stringify` of
  the config or the store never contains the URI.
- [x] **§4.4** End to end: `src/server.js` is started with a credentialed `MONGODB_URI` pointing
  at an unreachable host, at `LOG_LEVEL=trace`. It exits 1 with `store initialisation failed`,
  and neither stdout nor stderr contains the password or the user name.

### 5. Self-approval is impossible

The approver must be an admin whose API-key **lineage** is disjoint from every key the case's
initiator or parties control. The lineage is the key plus every admin key that minted it, taken
from `api_keys.createdBy`; older keys fall back to the actor of their hash-chained
`api_key.created` audit event. Anyone holding a key received the secret of every key minted
below it, so a shared ancestor means a possibly shared holder. Keys provisioned out-of-band are
lineage roots: the `KYA_BOOTSTRAP_ADMIN_API_KEY`, `scripts/seed.js`, and `scripts/demo.js`
`installKey`. An independent approver must be such a root.

- [x] **§5.1** (review F-1) Sibling admin keys minted by the same admin cannot approve each
  other's cases. Neither can cousins, the initiator's parent, or the initiator itself. Every
  refusal is `403 FORBIDDEN INV_NO_SELF_APPROVAL`, with no state, harness version or audit event
  written.
- [x] **§5.2** (review F-2) An admin cannot confirm a case opened with a business or operator
  key that it (or its lineage) minted. Neither can an admin key it minted.
- [x] **§5.3** An admin that minted a key owned by a case party (`principalId` or `businessId`)
  cannot confirm that case, even when an unrelated key initiated it.
- [x] **§5.4** An independent out-of-band admin can confirm. Harness v2 records it as `approvedBy`.
  A second confirmation gets `409`: exactly one promotion.
- [x] **§5.5** Lineage resolution covers `createdBy` chains and the audit fallback for keys stored
  before the field existed. A cycle (possible only by tampering with the DB) throws, and confirm
  then refuses. `createdBy` is set server-side (`POST /v1/api-keys` rejects it as a body field),
  and it is not added to the `ApiKey` response.
- [x] **§5.6** `INV_NO_SELF_APPROVAL` fails closed when the approver's lineage is missing or does
  not start with its own key, or when the case's conflict set is missing or omits the initiator.

## Findings

| Id | Severity | Finding | Status |
|---|---|---|---|
| F-1 | HIGH | Sibling admin keys: A mints B and C and receives both secrets; B initiates and C confirms, including `approveAdaptation`. | **Fixed.** `INV_NO_SELF_APPROVAL` v2 compares full key lineages (§5.1). |
| F-2 | HIGH | An admin mints a tenant key, initiates with it, then confirms as itself. | **Fixed.** Lineage covers tenant keys; party-owned keys are included too (§5.2, §5.3). |
| F-3 | MEDIUM | `MongoStore._uri` was an enumerable property, so logging or serialising the store leaked `MONGODB_URI`. | **Fixed.** Non-enumerable (§4.3). |
| F-4 | MEDIUM | Nothing stopped the watcher from running with an over-privileged DB user. The previous review pass reported that the configured Atlas user holds `atlasAdmin` / `readWriteAnyDatabase`; this pass did not re-inspect Atlas. | **Code control fixed:** checked at startup and refused in production (§3.1, §3.2). **Provisioning escalated to an operator** (below). |
| F-5 | LOW | The logger had no defence in depth against a URI reaching a field. | **Fixed.** A replacer-based redaction keeps `toJSON` output (§4.2). |
| F-6 | INFO | The §4.1 grep is static and misses aliased values. | **Accepted.** It is documented as one layer; §4.2 to §4.4 are the runtime proof. |
| F-7 | INFO | `INV_DELEGATION_MAX` / `INV_DAILY_LIMIT` hold when no limit is configured. | **By contract.** Grant constraints are optional (ARCHITECTURE section 3); a configured limit fails closed (§1.1). |

## Operator actions (escalated: outside an agent's permissions)

These need a human with Atlas project access. Agents may not mutate cloud infrastructure. None of
them weakens a check above: until they are done, the code fails safe.

1. **Create the least-privilege Atlas user** for the running service and watcher, with the single
   role `readWrite@kyagent`, and point `MONGODB_URI` at it. Keep the administrative user only for
   `make demo-reset` / `npm run migrate` (search indexes, validators). Until then, a production
   start refuses to run the watcher and a dev start logs
   `sanctions watcher: the MongoDB user is not least-privilege`.
2. **Run `make demo-reset` once after deploying this change.** The `INV_NO_SELF_APPROVAL` rule
   text changed (version 2), so `INVARIANTS_HASH` changed from `b2642f0b…` to `f88ecf79…`. A
   harness v1 seeded under the old hash makes investigations BLOCK with
   `HARNESS_INVARIANTS_MISMATCH` until it is re-seeded. This is the designed behaviour for an
   invariant change.
3. **Provision the reviewer admin key out-of-band.** For example, use a second
   `KYA_BOOTSTRAP_ADMIN_API_KEY` deployment or the `scripts/demo.js` `installKey` path. It must
   not be minted through `POST /v1/api-keys` by the admin that onboards tenants, or it cannot
   approve their cases.
