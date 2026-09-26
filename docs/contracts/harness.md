# Investigation Harness: Immutable Invariants + Adaptive Policy (binding)

Status: **frozen by T01**. Implementation: `src/harness/invariants.js` (T12),
`src/harness/policy.js` + `src/harness/adaptation.js` (T13). Pipeline:
[`investigation-pipeline.md`](investigation-pipeline.md).

The harness has two layers with a hard boundary between them:

| Layer | Lives in | Changed by | Can produce |
|---|---|---|---|
| **Immutable invariants** | code: `src/harness/invariants.js` (frozen) | a reviewed code change + test change + this document. **Never** by a DB write, an API call, an adaptation or an LLM | `BLOCK`, drop of a memory hit, `403` |
| **Adaptive policy** | MongoDB: `harness_versions.policy` | `POST /v1/investigations/{id}/confirm` with human approval only | extra steps, retrieval size, context assembly, evidence requests, `REVIEW` escalations |

## 1. Immutable invariants

`INVARIANTS` is a frozen array (`Object.freeze` on the array and every element). No
configuration, environment variable or document is read to decide whether an invariant applies.

| Id | Rule | Enforced at | On breach |
|---|---|---|---|
| `INV_SANCTIONS_EXACT_BLOCK` | If the agent's source wallet or the counterparty address equals (lowercased) any `sanctions.wallets.address`, the action is blocked. Evaluated with `find()` on the `{ 'wallets.address': 1 }` index, never with `$search`. | `sanctions` stage | `BLOCK SANCTIONS_EXACT_MATCH` |
| `INV_DELEGATION_MAX` | `amount ≤ delegation.maxTxAmount` (= `constraints.maxAmount`), via `authz.constraintsSatisfied`. `/v1/verify` step 9i/10c calls the same function (behaviour unchanged). | `delegation` stage | `BLOCK DELEGATION_MAX_EXCEEDED` |
| `INV_DAILY_LIMIT` | `spent24h + amount ≤ delegation.dailyLimit` (rolling 24 h, `settled` transactions). Part of the delegation-maximum family. | `delegation` stage | `BLOCK DAILY_LIMIT_EXCEEDED` |
| `INV_NO_SELF_APPROVAL` | The confirmer of an investigation / verifier of a memory has role `admin`, and its `apiKeyId` ≠ `investigation.initiatedBy.apiKeyId`, and its `ownerId` ∉ {`agentId`, `principalId`, `businessId`} of the case. Also required as `approvedBy` for every harness adaptation. | confirm endpoint | `403 FORBIDDEN`, nothing written |
| `INV_NO_SELF_PASSPORT_MODIFICATION` | Only the `system` actor (pipeline/watcher) or an `admin` may transition a passport; `operator` / `business` roles (the passport's own principal or relying party) may not, and agents have no API key. | `passports.transition()` | `403 FORBIDDEN` |
| `INV_UNVERIFIED_MEMORY_NOT_PRECEDENT` | Only `status == 'VERIFIED'` memories may enter context or fire an escalation. Enforced twice: `$vectorSearch` `filter: { status: 'VERIFIED' }` **and** a post-filter on every hit. | `memory` + `policy` stages | hit dropped, evidence recorded |

Non-invariant but fixed-in-code pipeline rules (not adaptable either): memory hits below
`minScorePpm` are dropped before context assembly (irrelevant memory is never proof); memory can
only escalate to `REVIEW`; fail closed on any stage error.

### `INVARIANTS_HASH`

```
INVARIANTS_HASH = sha256hex(canonicalJson(INVARIANTS.map(i => ({
  id: i.id, version: i.version, rule: i.rule, reasonCode: i.reasonCode, enforcedAt: i.enforcedAt,
}))))
```

Computed at module load (64 lowercase hex). T12 pins the literal value in
`test/harness.invariants.test.js`; T01 does not pre-fill it. Every `harness_versions` document
stores the `invariantsHash` it was created under; the policy stage BLOCKs with
`HARNESS_INVARIANTS_MISMATCH` if the active version's hash differs from the runtime constant.
An adaptation must produce a version with the **same** `invariantsHash` as its parent.

## 2. What the adaptive policy may and may not do

May: add registered adaptive steps; change `memoryRetrieval.k` / `numCandidates`; raise
`memoryRetrieval.minScorePpm`; change `contextAssembly`; add `evidenceRequests`; add `REVIEW`
escalation rules. May not: remove or reorder core stages; change `memoryRetrieval.filter`
(it is the constant `{ status: 'VERIFIED' }`); lower `minScorePpm` below the parent version's
value; emit `ALLOW` or `BLOCK`; reference invariants in any way. Keys such as `invariants`,
`skipInvariants`, `overrides`, `allow`, `block` are rejected by `additionalProperties: false`.

## 3. Adaptive policy schema

### 3.1 JSON Schema (`validatePolicy()` MUST implement exactly this; also used as the `$jsonSchema` of `harness_versions.policy`)

```json
{
  "$id": "https://kyagent.dev/contracts/harness-policy.schema.json",
  "type": "object",
  "additionalProperties": false,
  "required": ["steps", "memoryRetrieval", "contextAssembly", "evidenceRequests", "escalation"],
  "properties": {
    "steps": {
      "type": "array", "minItems": 6, "maxItems": 12, "uniqueItems": true,
      "items": { "enum": ["identity", "delegation", "sanctions", "signals", "memory", "policy",
                          "signing_key_history_check"] },
      "description": "Core stages in fixed order; adaptive steps only between 'memory' and 'policy'; 'decision' is implicit."
    },
    "memoryRetrieval": {
      "type": "object", "additionalProperties": false,
      "required": ["k", "numCandidates", "minScorePpm", "filter"],
      "properties": {
        "k": { "type": "integer", "minimum": 1, "maximum": 10 },
        "numCandidates": { "type": "integer", "minimum": 10, "maximum": 200 },
        "minScorePpm": { "type": "integer", "minimum": 1, "maximum": 1000000 },
        "filter": { "type": "object", "additionalProperties": false, "required": ["status"],
                    "properties": { "status": { "const": "VERIFIED" } } }
      }
    },
    "sanctionsFuzzy": {
      "type": "object", "additionalProperties": false, "required": ["minScorePpm", "limit"],
      "properties": {
        "minScorePpm": { "type": "integer", "minimum": 1 },
        "limit": { "type": "integer", "minimum": 1, "maximum": 10 }
      },
      "description": "Optional. Absent => fuzzy hits are evidence only and never escalate. Value calibrated by T09 on the fixture dataset."
    },
    "contextAssembly": {
      "type": "object", "additionalProperties": false,
      "required": ["maxMemories", "includeSignalStats", "includeSanctionsEvidence"],
      "properties": {
        "maxMemories": { "type": "integer", "minimum": 0, "maximum": 10 },
        "includeSignalStats": { "type": "boolean" },
        "includeSanctionsEvidence": { "type": "boolean" }
      }
    },
    "evidenceRequests": {
      "type": "array", "maxItems": 10,
      "items": { "type": "object", "additionalProperties": false, "required": ["id", "stage", "description"],
                 "properties": { "id": { "type": "string", "pattern": "^[a-z0-9_]{1,64}$" },
                                 "stage": { "type": "string", "pattern": "^[a-z0-9_]{1,64}$" },
                                 "description": { "type": "string", "maxLength": 300 } } }
    },
    "escalation": {
      "type": "array", "maxItems": 20,
      "items": {
        "type": "object", "additionalProperties": false, "required": ["id", "when", "then"],
        "properties": {
          "id": { "type": "string", "pattern": "^[a-z0-9_]{1,64}$" },
          "when": {
            "type": "object", "additionalProperties": false, "minProperties": 1,
            "properties": {
              "precedentOutcomeIn": { "type": "array", "minItems": 1, "uniqueItems": true,
                "items": { "enum": ["CONFIRMED_ACCOUNT_TAKEOVER", "SANCTIONS_MATCH", "FALSE_POSITIVE", "CLEAN"] } },
              "signalsAll": { "type": "array", "minItems": 1, "uniqueItems": true, "items": { "$ref": "#/$defs/signal" } },
              "signalsAnyMin": { "type": "object", "additionalProperties": false, "required": ["of", "min"],
                "properties": { "of": { "type": "array", "minItems": 1, "uniqueItems": true, "items": { "$ref": "#/$defs/signal" } },
                                "min": { "type": "integer", "minimum": 1 } } },
              "sanctionsFuzzyHit": { "const": true }
            }
          },
          "then": {
            "type": "object", "additionalProperties": false, "required": ["riskDecision", "reasonCode"],
            "properties": {
              "riskDecision": { "const": "REVIEW" },
              "reasonCode": { "enum": ["MEMORY_PRECEDENT_TAKEOVER", "BEHAVIOR_ESCALATION", "SANCTIONS_FUZZY_MATCH"] }
            }
          }
        }
      }
    }
  },
  "$defs": {
    "signal": { "enum": ["NEW_WALLET", "NEW_COUNTERPARTY", "SIGNING_KEY_CHANGED", "AMOUNT_ANOMALY", "VELOCITY", "NEAR_CEILING"] }
  }
}
```

All keys of `when` must hold (AND). `precedentOutcomeIn` matches only kept (VERIFIED, ≥
`minScorePpm`) memory hits. Additional code-level checks in `validatePolicy()`: the six core
stages appear in the canonical order; adaptive steps appear only between `memory` and `policy`;
every step id is in the registry (§3.3).

### 3.2 Seed v1 policy (DELIVERY_PLAN §5 item 12)

```json
{
  "steps": ["identity", "delegation", "sanctions", "signals", "memory", "policy"],
  "memoryRetrieval": { "k": 3, "numCandidates": 100, "minScorePpm": 780000, "filter": { "status": "VERIFIED" } },
  "contextAssembly": { "maxMemories": 3, "includeSignalStats": true, "includeSanctionsEvidence": true },
  "evidenceRequests": [],
  "escalation": [
    { "id": "precedent_takeover",
      "when": { "precedentOutcomeIn": ["CONFIRMED_ACCOUNT_TAKEOVER"] },
      "then": { "riskDecision": "REVIEW", "reasonCode": "MEMORY_PRECEDENT_TAKEOVER" } }
  ]
}
```

`minScore: 0.78` in the delivery plan is encoded as `minScorePpm: 780000` (integer-only
canonical JSON). `numCandidates: 100` is from T07.

### 3.3 Adaptive step registry (closed; extending it is a code change)

| Step id | Engine | `result` | Added by |
|---|---|---|---|
| `signing_key_history_check` | `find` (`agents.signingKeyHistory`) + `aggregate` (`transactions` by `signingKeyThumbprint`) | `{ currentThumbprint, previousThumbprint, rotatedAt, rotatedWithinHours, settledTxWithCurrentKey }` | fixture adaptation template for `CONFIRMED_ACCOUNT_TAKEOVER` |

## 4. `harness_versions` document

```ts
interface HarnessVersionDoc {
  _id: number;                 // == version
  version: number;             // 1, 2, 3 … contiguous
  status: 'active' | 'superseded';   // exactly one active (unique partial index)
  parentVersion: number | null;
  invariantsHash: string;      // INVARIANTS_HASH at creation; equal to parent's
  policy: HarnessPolicy;       // §3.1
  policyHash: string;          // sha256hex(canonicalJson(policy))
  createdAt: Date;
  approvedBy: { role: 'admin' | 'system'; apiKeyId: string | null; ownerId: string | null; label?: 'seed' };
  sourceEventId: string | null; // harness_events _id that created it (null for v1)
  demo?: true;
}
```

Superseding is `updateIf({ _id: n, status: 'active' }, { status: 'superseded' })` followed by
insert of `n+1` as `active`; on failure the insert is rolled back (single active version always).
Old versions are never deleted or edited (except the `status` flag).

## 5. `harness_events` document

```ts
interface HarnessEventDoc {
  _id: string;                        // hev_…
  type: 'adaptation.applied' | 'adaptation.rejected';
  fromVersion: number;
  toVersion: number | null;           // null when rejected
  diff: JsonPatchOp[];                // RFC 6902, paths restricted to §2 "May"
  oldPolicy: HarnessPolicy;           // full snapshot of fromVersion.policy
  newPolicy: HarnessPolicy | null;    // full snapshot (null when rejected)
  oldPolicyHash: string; newPolicyHash: string | null;
  invariantsHash: string;             // identical for old and new
  evidence: { type: 'investigation' | 'memory'; id: string }[];  // ≥ 1 investigation + the promoted memory
  proposer: { kind: 'template' | 'llm'; llmMode: 'fixture' | 'live'; model: string | null };
  approvedBy: { role: 'admin'; apiKeyId: string; ownerId: string | null };
  approvedAt: Date;
  at: Date;
  auditEventId: string;               // audit_events harness.adapted / harness.adaptation_rejected
}
```

This satisfies "old version, new version, evidence, timestamp and approval" in one document
plus the two `harness_versions` documents and the hash-chained audit event.

## 6. Adaptation flow and approval rules

1. `POST /v1/investigations/{id}/confirm` `{ outcome, note?, approveAdaptation }` by an admin
   satisfying `INV_NO_SELF_APPROVAL`; investigation must be `DECIDED` or `AWAITING_REVIEW`
   with `outcome == null` (else `409 INVALID_STATE`).
2. Memory: `CONFIRMED_ACCOUNT_TAKEOVER | SANCTIONS_MATCH | FALSE_POSITIVE` ⇒ candidate
   `UNVERIFIED → VERIFIED` (`verifiedBy`, `verifiedAt`, `outcome`, embedding re-checked);
   `CLEAN` ⇒ `→ REJECTED`. Audit `memory.promoted` / `memory.rejected`.
3. Proposal: `proposeFromOutcome(investigation, memory)`. `LLM_MODE=fixture` (default): a
   deterministic template — for `CONFIRMED_ACCOUNT_TAKEOVER` insert `signing_key_history_check`
   after `memory` (if absent) and set `memoryRetrieval.k = 5`; other outcomes ⇒ no proposal.
   `LLM_MODE=live`: the model returns a JSON Patch only; it sees the policy and evidence, never
   the invariants module, and its output is validated like any other proposal.
4. Validation: apply patch to a copy, `validatePolicy()`, check §2 rules and equal
   `invariantsHash`. Invalid ⇒ `adaptation.rejected` event (reason in audit data), no new version.
5. `approveAdaptation: true` ⇒ supersede vN, insert vN+1, `harness_events`
   `adaptation.applied`, audit `harness.adapted`. `false` ⇒ `adaptation.rejected` event, no change.
   **No path creates a harness version without an admin approval recorded in the same request.**
6. The next investigation loads the active version at start; its receipt records `harnessVersion`.
