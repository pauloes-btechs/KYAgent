# Agent Passport (binding)

Status: **frozen by T01**. Implementation: `src/services/passports.js` (T10).

A passport is the **authoritative, continuously re-evaluated trust state** of one agent under
one delegation. The existing credential (compact JWS, `credentials` collection) stays the
cryptographic carrier and is unchanged for `/v1/verify`; the passport adds status, provenance
and the link to the last investigation. `/v1/verify` does **not** read passports (byte
compatibility); the investigation pipeline does (policy stage).

## 1. Document (`passports`)

| Field | Type | Notes |
|---|---|---|
| `_id` | string | `pp_…` (seed: `pp_TREASURYBOT`) |
| `agentId` | string | **unique** — one passport per agent |
| `principalId` | string | = agent `operatorId` |
| `delegationId` | string | = `grantId` |
| `delegationVersion` | int | `grants.version` at issue / last re-evaluation |
| `wallet` | string | agent source wallet (lowercased) |
| `status` | `PassportStatus` | §2 |
| `statusReason` | string \| null | latest `RiskReasonCode` or admin text |
| `credentialId` | string \| null | latest credential carrying `kya_passport` |
| `lastInvestigationId` | string \| null | |
| `sanctionsDatasetVersion` | string | dataset the last screen ran against |
| `harnessVersion` | int | harness version of the last investigation |
| `issuedAt` | Date | |
| `expiresAt` | Date | = delegation `expiresAt` |
| `updatedAt` | Date | |
| `statusHistory` | `{ status, at, actor: { role, apiKeyId, ownerId }, reason, investigationId }[]` | append-only (`$push` in the same `updateIf`) |

## 2. Statuses

| Status | Meaning | Pipeline effect |
|---|---|---|
| `ACTIVE` | trusted within its delegation | none |
| `REVIEW` | human review pending | investigations ⇒ `REVIEW` (`PASSPORT_UNDER_REVIEW`) |
| `RE_SCREENING` | transient: watcher is re-evaluating after a data change | `api` investigations ⇒ `REVIEW` (`PASSPORT_RE_SCREENING`) |
| `SUSPENDED` | blocked | investigations ⇒ `BLOCK` (`PASSPORT_SUSPENDED`) |
| `REVOKED` | terminal | investigations ⇒ `BLOCK` (`PASSPORT_REVOKED`) |

## 3. Legal transitions

Anything not listed is illegal ⇒ `409 INVALID_STATE` (no write). Every transition is one
conditional `updateIf({ _id, status: from }, { $set: { status: to, … }, $push: { statusHistory } })`
plus an audit event `passport.status_changed`.

| From | To | Allowed actor | Cause |
|---|---|---|---|
| — | `ACTIVE` | system, admin | issuance (seed, first credential for a delegation) — audit `passport.issued` |
| `ACTIVE` | `REVIEW` | system, admin | `api` investigation ⇒ `REVIEW`; admin hold |
| `REVIEW` | `ACTIVE` | admin | human clears the review |
| `ACTIVE` | `RE_SCREENING` | system | sanctions watcher (change stream) |
| `REVIEW` | `RE_SCREENING` | system | sanctions watcher |
| `RE_SCREENING` | `ACTIVE` | system | re-screen investigation ⇒ `ALLOW` |
| `RE_SCREENING` | `REVIEW` | system | re-screen investigation ⇒ `REVIEW` |
| `RE_SCREENING` | `SUSPENDED` | system | re-screen investigation ⇒ `BLOCK` |
| `ACTIVE` | `SUSPENDED` | system, admin | `api` investigation with `SANCTIONS_EXACT_MATCH`; admin |
| `REVIEW` | `SUSPENDED` | system, admin | as above; human confirms a bad outcome |
| `SUSPENDED` | `REVOKED` | admin | terminal decision |
| `ACTIVE`, `REVIEW`, `RE_SCREENING` | `REVOKED` | system | cascade when the agent, delegation or principal is revoked/suspended |

State machine (summary): `ACTIVE ⇄ REVIEW → SUSPENDED → REVOKED`,
`ACTIVE|REVIEW → RE_SCREENING → {ACTIVE | REVIEW | SUSPENDED}`.

Demo 4 acceptance: `statusHistory.map(h => h.status)` = `['ACTIVE', 'RE_SCREENING', 'SUSPENDED']`.

## 4. Actor rules

- `INV_NO_SELF_PASSPORT_MODIFICATION`: `operator` and `business` API keys can never transition
  a passport (`403 FORBIDDEN`), including their own agents'. Agents have no API key.
- `system` transitions happen only inside the pipeline/watcher process (no HTTP route accepts
  `role: system`). Admin transitions go through `POST /v1/passports/{id}/transitions` and require
  a `reason`.
- Reads: admin (all), operator (own agents), business (agents it has delegations to; public
  fields only: `agentId, principalId, status, harnessVersion, sanctionsDatasetVersion, updatedAt`).

## 5. Credential claim additions (optional, additive)

Credentials issued for a delegation that has a passport carry three extra JWS claims. Existing
claims and `/v1/verify` checks are unchanged; verifiers that do not know them ignore them.

| Claim | Type | Value |
|---|---|---|
| `kya_passport` | string | passport `_id` |
| `kya_delegation_v` | int | `delegationVersion` at issue |
| `kya_harness_v` | int | active harness version at issue |
