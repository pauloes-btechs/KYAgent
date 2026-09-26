# KYAgent — UI States (MVP)

Defines loading, empty, error, partial and domain states for every page in
[`DESIGN_SPEC.md`](DESIGN_SPEC.md). Error codes and reason codes come from
`docs/contracts/error-model.md` / `types.ts`. Colors come from
[`DESIGN_TOKENS.json`](DESIGN_TOKENS.json) `semanticMapping`.

## 1. Global state rules

| State | Treatment |
|---|---|
| **Initial load** | Skeletons matching final geometry (table rows × 8, FactSheet lines × 6). Shown only after 150 ms to avoid flash. `aria-busy="true"` on the region; SR text "Loading agents". |
| **Refetch (data present)** | Keep data visible; thin progress bar under the PageHeader; controls stay enabled except the one that triggered it. |
| **Mutation in flight** | Triggering button shows spinner + "Revoking…", disabled; other destructive actions disabled; no optimistic status change. |
| **Empty (no data at all)** | `EmptyState`: one sentence of what this is + primary next step if role allows it. Text only. |
| **Empty (filtered)** | "No results match these filters." + `Clear filters`. Distinct from true empty. |
| **Error (page)** | InlineAlert in content area: title, human message, `error.code` (mono), `requestId` (copy), `Retry`. Nav/shell stay usable. |
| **Error (field)** | Message under field, `aria-invalid`, `aria-describedby`; summary at top of form with anchor links. |
| **Offline / network** | Top-of-page warning "Can't reach KYAgent API." Retry with backoff (1, 2, 4, 8 s, max 30 s); manual `Retry now`. No mutations while offline. |
| **Unknown enum value** | Neutral badge with raw value; all actions for that resource hidden (deny by default). |
| **Pagination** | `Load more` at table end while `nextCursor != null`; loading more shows 3 skeleton rows appended; end shows "End of results". Errors loading more are inline at the table footer with retry, existing rows kept. |

## 2. HTTP error mapping

| API result | UI state |
|---|---|
| `400 VALIDATION_ERROR` | Field errors from `details[].path` (JSON pointer → field); unmatched paths listed in form summary. |
| `401 UNAUTHENTICATED` | Purge key → Sign in with "Your API key was rejected. It may have been revoked." |
| `403 FORBIDDEN` | Page: "You don't have access to this with a <role> key." Action: toast-free inline error in dialog; action removed after refetch. |
| `404 NOT_FOUND` | Page: "Not found or not visible to you." (no existence oracle). Link back to the list. |
| `409 CONFLICT` | Field-level where attributable (duplicate public key), else inline alert. |
| `409 INVALID_STATE` | Inline alert "This <resource> is <status>; that action isn't available." + auto refetch. |
| `409 OPERATOR_NOT_VERIFIED` | Critical banner on form; form disabled; link to operator page. |
| `413 PAYLOAD_TOO_LARGE` | Verify console: "Request exceeds the 64 KiB limit." |
| `415 UNSUPPORTED_MEDIA_TYPE` | Treated as client bug: generic error with requestId. |
| `500 INTERNAL_ERROR` (non-verify) | Page/dialog error with requestId; Retry. |
| `500` on `/v1/verify` with `decision: "DENY"` | Render as a decision: DENY + `INTERNAL_ERROR` reason. |
| `503 SERVICE_UNAVAILABLE` | Global banner "KYAgent is temporarily unavailable"; retry with backoff. |
| Unparseable error body | Generic "Unexpected response (HTTP <status>)", no raw body rendered. |

## 3. Page states

### P1 Sign in
| State | UI |
|---|---|
| Idle | Empty masked input; `Sign in` disabled until input matches `^kya_` prefix shape. |
| Submitting | Spinner in button; input read-only. |
| Rejected (401) | Inline error under input; focus to input. |
| Unreachable | Inline error + Retry; key not retained. |
| Signed out / expired | Info notice above form ("Signed out after 30 minutes of inactivity"). |

### P2 Overview
| State | UI |
|---|---|
| Loading | Skeleton attention list (5 rows). |
| Nothing needs attention | "Nothing needs your attention." + role quick links (admin: Operators; operator: Agents; business: Verifications). |
| Operator not verified (operator) | Warning/pending/critical StatusBanner at top describing consequence. |
| Partial failure | Each attention section loads independently; a failed section shows its own inline error with Retry. |

### P3/P5/P7/P11/P14/P20 Lists
| Page | True empty copy (+ action if permitted) |
|---|---|
| Operators | "No operators yet. Operators are accountable for agents." `New operator` |
| Businesses | "No businesses yet." `New business` |
| Agents (operator, verified) | "You haven't registered any agents." `Register agent` |
| Agents (operator, not verified) | "Agents can be registered once your organization is verified by an admin." (no button) |
| Agents (admin) | "No agents registered yet." |
| Grants (business) | "You haven't authorized any agents. Look up an agent to start." `Agent lookup` |
| Grants (operator) | "No business has granted your agents any permissions yet." |
| Credentials | "No credentials issued." (operator: "Issue one from an agent's page.") |
| API keys | Never truly empty for a signed-in admin; if list is empty anyway, show "No keys" + `Create API key`. |

### P4 Operator detail — domain states
| `status` | Banner | Actions (admin) |
|---|---|---|
| `pending` | pending: "Not yet verified. Agents cannot be registered." | Run verification, Suspend |
| `verified` | none | Suspend |
| `rejected` | critical: "Verification failed: <statusReason>." Shows KycResult/SanctionsResult. | Re-run verification, Suspend |
| `suspended` | warning: "Suspended: <statusReason>. All agents of this operator are denied (OPERATOR_SUSPENDED)." | — |
| `verification == null` | Verification panel: "Not yet run." | — |
| Running verification | Panel skeleton + "Running mock KYC and sanctions screen…" | disabled |
| Sanctions `skipped` | warning badge + note "Sanctions screening is off (SANCTIONS_MODE=off)." | — |

### P8 Agent register
| State | UI |
|---|---|
| Operator not verified | Form replaced by banner + link. |
| Public key invalid format | Field error "Must be a 43-character base64url Ed25519 public key." |
| Proof missing | `Register` disabled; helper text points to SigningStringPreview. |
| Submitting | Stepper locked, spinner. |
| Server rejects proof | Field error on proof; signing string preview highlighted. |

### P9 Agent detail — domain states
| `status` | Banner | Available actions (operator own / admin) |
|---|---|---|
| `active` | none (operator shown with its status; if operator not `verified`, warning "Operator is <status>; verifications will be denied") | Issue credential (operator), Suspend, Revoke |
| `suspended` | warning: "Suspended: <reason>. Verifications return AGENT_SUSPENDED." | Reactivate, Revoke |
| `revoked` | critical: "Revoked <revokedAt>: <reason>. Permanent. Verifications return AGENT_REVOKED." | none |
| Business viewer | Public profile only; no action menu. | — |

Tabs: each tab has own loading/empty/error. Empty grants tab (operator): "No grants yet. Share this agent id with a business."

### P10 Agent lookup
| State | UI |
|---|---|
| Idle | Input + helper "Enter an agent id (agt_…)". |
| Invalid id shape | Field error, no request. |
| Loading | IdentityCard skeleton. |
| Trusted | IdentityCard + positive verdict + `Grant permissions`. |
| Agent suspended/revoked | critical/warning verdict naming reason; no grant action. |
| Operator not verified/suspended | critical verdict "Operator is <status>"; no grant action. |
| Operator fetch failed | Agent shown; operator row error with retry; verdict "Unknown — can't confirm operator" (neutral); no grant action. |
| 404 | "No agent with this id is visible to you." |

### P12 Grant create
| State | UI |
|---|---|
| Agent unresolved | Later sections collapsed/disabled with explanation. |
| Agent not trusted | Inline critical alert; `Continue` disabled. |
| Action invalid / bare `*` | Chip rejected; field error with rule. |
| No actions | `Review` disabled; "Add at least one action." |
| Constraint toggled but empty | Field error "Enter a value or turn this constraint off." |
| Expiry past / > 365 d | Field error. |
| Review | Read-only summary; `Back` and `Create grant`. |
| Submitting | Buttons disabled; spinner. |

### P13 Grant detail
| Status | Banner | Actions |
|---|---|---|
| `active`, expires > 7 d | none | Revoke (business), Issue credential (operator) |
| `active`, expires ≤ 7 d | warning "Expires in <n> days" | same |
| `active`, `expiresAt` ≤ now (derived **expired**) | neutral "Expired <date>. Verifications return GRANT_EXPIRED." | none (create a new grant) |
| `revoked` | critical "Revoked: <reason>. Derived credentials return GRANT_REVOKED." | none |

### P15 Credential issue modal
| State | UI |
|---|---|
| No eligible grants | Empty state in modal; `Issue` hidden. |
| TTL out of range | Field error "Between 60 and <max> seconds." |
| Clamped by grant | Warning line under TTL. |
| Issuing | Spinner; modal not dismissible. |
| Issued | SecretReveal; `Done` disabled until acknowledgement checked. |
| Close attempt unacknowledged | Confirm "Close without copying? The credential cannot be shown again." |
| Error | Inline alert in modal; no secret panel. |

### P16 Credential detail
`active` (positive; warning if expires < 24 h) · derived **expired** (neutral, "CREDENTIAL_EXPIRED") · `revoked` (critical, "CREDENTIAL_REVOKED"). Revoke only when `active` and not expired. The JWS is never shown in any state.

### P17/P18 Verifications
| State | UI |
|---|---|
| Loading | Table skeleton. |
| Empty | "No verifications yet. Your backend calls POST /v1/verify for each agent request." Link to Developer. |
| Filtered empty | "No DENY decisions for this agent." + Clear filters. |
| New events available | Non-intrusive button "3 new — show" at top (focus not moved). |
| Drawer loading from deep link | Drawer skeleton. |
| Reason code not in catalogue | Show raw code, explainer "Unknown reason code — treat as DENY." |

### P19 Verify console
| State | UI |
|---|---|
| Empty editor | Placeholder skeleton JSON with field names (no values); `Verify` disabled. |
| Invalid JSON | Line/column error; `Verify` disabled. |
| Oversize (> 64 KiB client-side) | Error; `Verify` disabled. |
| Submitting | Result panel skeleton; editor read-only. |
| ALLOW | Stamp (allow tokens), grantId/credentialId links, verificationId. |
| DENY | Stamp (deny tokens), single ReasonCode, ReasonExplainer, "Who can fix this". |
| DENY `NONCE_REPLAYED` after resubmit | Explainer: "You submitted this signed request before. Generate a new signed request." |
| No decision (401/403/413/415/network) | Error panel, **no stamp**; network: "No decision received. Treat as DENY." |

### P20 API keys
| State | UI |
|---|---|
| Creating | Modal spinner. |
| Created | SecretReveal (plaintext once); acknowledgement gate. |
| Row `revoked` | critical badge, `revokedAt`; no actions. |
| Current session key row | Tagged "This session"; revoke dialog warns "You will be signed out." |
| `lastUsedAt == null` | "Never" (muted). |

### P21 Developer
Health `ok` (positive, store memory/mongo), unreachable (critical banner). JWKS
empty or fetch failure → error with retry; never falls back to cached keys.

### P22 Not found / Forbidden
Single message + link to Overview. Same copy for unknown and unauthorized resources.

## 4. Status badge reference

| Resource | Value | Token group | Label |
|---|---|---|---|
| Operator | `pending` / `verified` / `rejected` / `suspended` | pending / positive / critical / warning | Pending / Verified / Rejected / Suspended |
| Agent | `active` / `suspended` / `revoked` | positive / warning / critical | Active / Suspended / Revoked |
| Grant | `active` / expired (derived) / `revoked` | positive / neutral / critical | Active / Expired / Revoked |
| Credential | `active` / expired (derived) / `revoked` | positive / neutral / critical | Active / Expired / Revoked |
| API key | `active` / `revoked` | positive / critical | Active / Revoked |
| Business | `active` / `suspended` | positive / warning | Active / Suspended |
| KYC | `pass` / `fail` | positive / critical | Pass / Fail |
| Sanctions | `clear` / `hit` / `skipped` | positive / critical / warning | Clear / Hit / Skipped |
| Decision | `ALLOW` / `DENY` | decision.allow / decision.deny | ALLOW / DENY |

"Expired" is derived client-side from `expiresAt <= now` for display only; the
server remains authoritative for decisions.

## 5. Reason code explainer content

| Code | Step | Meaning | Who fixes |
|---|---|---|---|
| `ALLOWED` | — | All checks passed. | — |
| `MALFORMED_REQUEST` | 1 | Body invalid or fields differ from what the agent signed. | Business integration / agent |
| `AUDIENCE_MISMATCH` | 2 | Request was signed for a different business. | Agent |
| `AGENT_NOT_FOUND` | 3 | No such agent. | Agent / operator |
| `AGENT_REVOKED` | 4 | Agent permanently revoked. | Operator (register new agent) |
| `AGENT_SUSPENDED` | 4 | Agent temporarily suspended. | Operator / admin |
| `OPERATOR_NOT_VERIFIED` | 5 | Operator is pending or rejected. | Admin |
| `OPERATOR_SUSPENDED` | 5 | Operator suspended. | Admin |
| `TIMESTAMP_OUT_OF_WINDOW` | 6 | Signed timestamp too old/new (clock skew). | Agent (sync clock) |
| `SIGNATURE_INVALID` | 7 | Signature doesn't match the registered key. | Agent |
| `NONCE_REPLAYED` | 8 | Nonce already used — possible replay. | Agent (new nonce); investigate |
| `CREDENTIAL_INVALID` | 9a/9f | Credential malformed, wrong issuer/key, or unknown. | Operator (re-issue) |
| `CREDENTIAL_NOT_YET_VALID` | 9b | `nbf` in the future. | Agent (clock) |
| `CREDENTIAL_EXPIRED` | 9b | Credential expired. | Operator (re-issue) |
| `CREDENTIAL_SUBJECT_MISMATCH` | 9c | Credential belongs to another agent. | Agent |
| `CREDENTIAL_AUDIENCE_MISMATCH` | 9d | Credential issued for another business. | Agent |
| `CREDENTIAL_KEY_MISMATCH` | 9e | Credential not bound to this agent key. | Operator |
| `CREDENTIAL_REVOKED` | 9f | Credential revoked. | Operator (re-issue if appropriate) |
| `GRANT_REVOKED` | 9g | Grant revoked by the business. | Business |
| `GRANT_EXPIRED` | 9g | Grant expired. | Business (new grant) |
| `NO_GRANT` | 10 | No active grant from this business. | Business |
| `ACTION_NOT_PERMITTED` | 9h/10b | Action outside granted scope. | Business (extend grant) |
| `CONSTRAINT_VIOLATION` | 9i/10c | Amount/currency/resource outside constraints or missing. | Agent / business |
| `INTERNAL_ERROR` | any | Service error; denied by default. | KYAgent ops (quote requestId) |
