# Decision Vocabulary (binding)

Status: **frozen by T01**. Two vocabularies coexist; neither replaces the other.

## 1. `Decision` — identity layer (UNCHANGED)

`Decision = 'ALLOW' | 'DENY'` with `REASON_CODES` (types.ts, openapi `ReasonCode`,
`src/contracts.js`). It is produced by `POST /v1/verify` exactly as described in
ARCHITECTURE.md §3. **`/v1/verify` stays byte-compatible:** no new fields, no new values, no new
reason codes. `REASON_CODES` must not be extended for harness purposes (the sync tests in
`contracts.test.js` and `docs.test.js` guard this).

## 2. `RiskDecision` — investigation layer (NEW)

`RiskDecision = 'ALLOW' | 'REVIEW' | 'BLOCK'`, produced only by the investigation pipeline
(`POST /v1/investigations`, the sanctions watcher, manual re-runs) and recorded in
`investigations.riskDecision` and the receipt.

| Value | Meaning | Who may produce it |
|---|---|---|
| `ALLOW` | Identity passed, no invariant breached, no escalation rule fired | decision stage |
| `REVIEW` | A human must look before the action proceeds | adaptive escalation rules, passport `REVIEW`/`RE_SCREENING`, fuzzy sanctions hit |
| `BLOCK` | The action must not proceed | identity DENY, an immutable invariant, passport `SUSPENDED`/`REVOKED`, any stage failure (fail closed) |

Precedence: `BLOCK > REVIEW > ALLOW`. The adaptive policy (harness.md) can only **add**
`REVIEW`; it can never produce `ALLOW` from `REVIEW`/`BLOCK`, nor `BLOCK`. Memory precedent can
only produce `REVIEW` (precedent, never proof). An exact sanctioned-wallet hit is always `BLOCK`.

## 3. Mapping from the identity verdict

| Identity stage (`/v1/verify` evaluation) | Pipeline result | `riskDecision` | Primary risk reason |
|---|---|---|---|
| `DENY` with `CONSTRAINT_VIOLATION` because `context.amount > maxAmount` | invariant `INV_DELEGATION_MAX` | `BLOCK` | `DELEGATION_MAX_EXCEEDED` |
| `DENY` with `NO_GRANT`, `ACTION_NOT_PERMITTED`, `GRANT_REVOKED`, `GRANT_EXPIRED`, other `CONSTRAINT_VIOLATION` | delegation failed | `BLOCK` | `DELEGATION_DENIED` |
| `DENY` with any other reason code | identity failed (short-circuit) | `BLOCK` | `IDENTITY_DENIED` |
| `ALLOW` + any invariant breach | | `BLOCK` | the invariant's code |
| `ALLOW` + passport `SUSPENDED` / `REVOKED` | | `BLOCK` | `PASSPORT_SUSPENDED` / `PASSPORT_REVOKED` |
| `ALLOW` + escalation rule / passport `REVIEW` / `RE_SCREENING` / fuzzy sanctions | | `REVIEW` | the rule's `reasonCode` |
| `ALLOW` + nothing fired | | `ALLOW` | `CLEAR` |
| any stage throws / times out / Atlas unavailable | fail closed | `BLOCK` | `INTERNAL_ERROR` |

Every `RiskReason` carrying an identity cause also carries `identityReasonCode` (a
`REASON_CODES` value), so integrators can correlate with `/v1/verify`.

## 4. `RISK_REASON_CODES`

Defined in `types.ts` (`RISK_REASON_CODES`) and openapi (`RiskReasonCode`); T14 mirrors them in
`src/contracts.js` with a sync test. Order is significant (it is the documented order).

| Code | riskDecision | Source |
|---|---|---|
| `CLEAR` | ALLOW | decision stage, nothing fired |
| `IDENTITY_DENIED` | BLOCK | identity stage (`identityReasonCode` set) |
| `DELEGATION_DENIED` | BLOCK | delegation stage (`identityReasonCode` set) |
| `DELEGATION_MAX_EXCEEDED` | BLOCK | `INV_DELEGATION_MAX` |
| `DAILY_LIMIT_EXCEEDED` | BLOCK | `INV_DAILY_LIMIT` |
| `WALLET_NOT_APPROVED` | BLOCK | delegation stage: source wallet ≠ `approvedWallet` |
| `ASSET_NOT_PERMITTED` | BLOCK | delegation stage: asset ≠ delegation `asset` |
| `SANCTIONS_EXACT_MATCH` | BLOCK | `INV_SANCTIONS_EXACT_BLOCK` |
| `SANCTIONS_FUZZY_MATCH` | REVIEW | sanctions stage `$search` hit ≥ threshold (evidence-grade only) |
| `PASSPORT_SUSPENDED` | BLOCK | policy stage |
| `PASSPORT_REVOKED` | BLOCK | policy stage |
| `PASSPORT_UNDER_REVIEW` | REVIEW | policy stage (passport `REVIEW`) |
| `PASSPORT_RE_SCREENING` | REVIEW | policy stage (passport `RE_SCREENING`, `trigger: api` only) |
| `MEMORY_PRECEDENT_TAKEOVER` | REVIEW | escalation rule on a VERIFIED `CONFIRMED_ACCOUNT_TAKEOVER` precedent |
| `BEHAVIOR_ESCALATION` | REVIEW | escalation rule on signals |
| `HARNESS_INVARIANTS_MISMATCH` | BLOCK | active `harness_versions.invariantsHash` ≠ runtime `INVARIANTS_HASH` |
| `INTERNAL_ERROR` | BLOCK | any stage failure (fail closed) |

`INV_NO_SELF_APPROVAL` and `INV_NO_SELF_PASSPORT_MODIFICATION` guard administrative actions,
not payments: they surface as HTTP `403 FORBIDDEN` (error-model.md), not as risk reasons.
`INV_UNVERIFIED_MEMORY_NOT_PRECEDENT` drops the offending hit (recorded as stage evidence) and
cannot relax a decision.

## 5. Wire shape

```ts
interface RiskReason {
  code: RiskReasonCode;
  riskDecision: RiskDecision;      // the verdict this reason alone implies
  message: string;                 // human-readable; branch on `code`
  stage: PipelineStageName | string;  // stage that produced it (adaptive step ids allowed)
  invariantId?: InvariantId;       // set when an immutable invariant fired
  identityReasonCode?: ReasonCode; // set for IDENTITY_DENIED / DELEGATION_DENIED / DELEGATION_MAX_EXCEEDED
  evidenceRefs?: string[];         // ids of evidence items (sanctions ids, memory ids, …)
}
```

`reasons` contains every reason that fired, sorted by precedence (BLOCK first, then REVIEW)
and, within one verdict, by stage order; `reasons[0]` is the primary reason. `ALLOW` ⇒
exactly `[{ code: 'CLEAR', … }]`.

## 6. SDK

`src/sdk/businessVerifier.js` keeps accepting only `ALLOW|DENY` in `decision` (fail closed on
anything else). T14 lets it pass through an optional `riskDecision` field untouched; it never
converts `REVIEW` into `ALLOW`.
