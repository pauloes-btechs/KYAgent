# KYAgent — User Flows (MVP)

Pages (`P#`) and components refer to [`DESIGN_SPEC.md`](DESIGN_SPEC.md); states
refer to [`UI_STATES.md`](UI_STATES.md). Every step maps to an endpoint in
`docs/contracts/openapi.yaml`; the dashboard has no other data source.

Legend: **→** navigation · **⇒** API call · **✖** error branch.

---

## F0. Sign in / sign out (all roles)

1. User opens any route without a key in memory → P1 Sign in (original route kept as `?next=`, path only).
2. Pastes API key → `Sign in`.
3. ⇒ role probe (DESIGN_SPEC §2). Button shows spinner; input disabled.
4. Success → role + owner id stored in memory → redirect to `next` if permitted for the role, else Overview.
   - ✖ `401` → inline error "This API key was not accepted." Input keeps value (masked), focus returns to input.
   - ✖ network / `5xx` → inline error with retry; key is not stored.
5. Sign out (top bar) or 30-min idle (warning dialog at 28 min) → key purged from memory → P1 with "Signed out".
6. Any later `401` on any call → purge key → P1 with "Your API key was rejected. It may have been revoked."

## F1. Operator onboarding (admin) — REQ-003

1. Operators (P3) → `New operator` → modal: type (individual/organization), legal name, contact email, country (ISO 3166 alpha-2 select).
2. ⇒ `POST /v1/operators` → toast "Operator created · op_…" → P4, status `pending`, StatusBanner "Not yet verified. Agents cannot be registered."
   - ✖ `400 VALIDATION_ERROR` → field errors from `details[].path`.
3. P4 → `Run verification` → confirm dialog explains: "MVP mock KYC + sanctions screen (mode: <SANCTIONS_MODE from response>)."
4. ⇒ `POST /v1/operators/{id}/verification` → Verification panel updates:
   - `verified` → positive banner; KycResult `pass`, SanctionsResult `clear`/`skipped`.
   - `rejected` → critical banner with `statusReason`; `Re-run verification` available.
   - ✖ `409 INVALID_STATE` (e.g. suspended) → inline alert, state refetched.
5. Create operator API key → F2 with role `operator`, owner = this operator (shortcut button on P4 pre-fills).

## F2. Issue an API key (admin) — REQ-010

1. API keys (P20) → `Create API key` → modal: name, role, owner (select; required for operator/business; hidden for admin).
2. ⇒ `POST /v1/api-keys` → modal switches to **SecretReveal** with `secret`.
3. Admin copies the key; must tick "I have copied this key. It cannot be shown again." to enable `Done`.
   - Esc / outside click while unacknowledged → confirm "Close without copying? The key will be lost; you'd need to revoke it and create a new one."
4. `Done` → secret dropped from state → table refetches; new row shows `displayPrefix`, status `active`.
5. Revoke: row ActionMenu → `Revoke` → ConfirmDestructiveDialog → ⇒ `POST /v1/api-keys/{id}/revoke` → row status `revoked`.
   - If the admin revokes the key they're signed in with → next call returns 401 → F0 step 6.

## F3. Business onboarding (admin)

1. Businesses (P5) → `New business` → name → ⇒ `POST /v1/businesses` → P6.
2. P6 shortcut `Create business API key` → F2 pre-filled (role `business`, owner `biz_…`).

## F4. Register an agent (operator) — REQ-001, REQ-003, REQ-004

Precondition: operator `verified`. Otherwise Agents list shows a StatusBanner
and the `Register agent` button is replaced by explanatory text (no disabled button without explanation).

1. Agents (P7) → `Register agent` → P8 step 1: name, description.
2. Step 2: SigningStringPreview shows `KYA-REGISTER-V1\n{operatorId}\n{publicKey}` (updates live as the public key is typed).
   Out-of-band: operator generates the Ed25519 key pair on the agent host and signs the string with the SDK/CLI snippet shown.
3. Paste public key (live check: base64url, 43 chars) and proof of possession.
4. `Register` ⇒ `POST /v1/agents`.
   - Success → P9 with toast "Agent registered · agt_…"; status `active`; key thumbprint displayed.
   - ✖ `400 VALIDATION_ERROR` (bad key / bad proof) → error on the relevant field: "Proof of possession does not verify for this public key and operator."
   - ✖ `409 OPERATOR_NOT_VERIFIED` → page-level critical alert, form disabled, link to My organization.
   - ✖ `409 CONFLICT` (key already registered) → field error on public key.
5. Next-step prompt on P9: "Share `agt_…` with the business so it can grant permissions."

## F5. Look up an agent before trusting it (business) — REQ-001

1. Agent lookup (P10) → paste `agt_…` → `Look up`.
2. ⇒ `GET /v1/agents/{id}` then ⇒ `GET /v1/operators/{operatorId}` (public profiles).
3. IdentityCard with verdict line:
   - agent `active` & operator `verified` → "Identity verified" (positive).
   - any other combination → "Not trusted — <reason>" (critical/warning) and `Grant permissions` is hidden.
   - ✖ `404` → "No agent with this id is visible to you."
4. `Grant permissions` → F6 with agent pre-filled.

## F6. Authorize an agent: create a grant (business) — REQ-002

1. Grants (P11) → `New grant` (or from F5) → P12.
2. Agent id → inline IdentityCard (compact). Must be trusted (F5 rules) to continue.
3. Actions: add patterns (e.g. `payments:create`, `orders:*`). Invalid pattern or bare `*` → inline error; chip not added.
4. Constraints (optional): maxAmount, currency, resources.
5. Expiry (required): preset or picker; ✖ past or > 365 days → field error.
6. Review: plain-language summary, e.g.
   "Invoice Bot (agt_…) may **payments:create** up to **250.00 USD** on resources **acct_123** until **2026-10-26 12:00 UTC**."
7. `Create grant` ⇒ `POST /v1/grants` → P13, toast "Grant created".
   - ✖ `404` agent → field error "Agent not found".
   - ✖ `409 INVALID_STATE` (agent not active / operator not verified) → page alert, back to step 2.
   - ✖ `400` → field errors mapped from `details[].path` (e.g. `/actions/1`).

## F7. Issue a credential to an agent (operator) — REQ-006

1. From P9 (`Issue credential`) or P13 (`Issue credential for this grant`) → modal P15.
2. Select active grant (only active, unexpired grants to this agent listed; if none → empty state "No active grants. A business must grant this agent permissions first.").
3. TTL preset / custom (60..max). Preview: "Expires 2026-09-26 13:00 UTC" and, when clamped, warning "Limited by grant expiry".
4. `Issue` ⇒ `POST /v1/agents/{id}/credentials` → SecretReveal with the JWS + decoded claims (`sub`, `aud`, `kya_actions`, `kya_constraints`, `exp`, `cnf.jkt`).
5. Operator copies → acknowledges → `Done` → JWS discarded → Credentials tab refetched.
   - ✖ `409 INVALID_STATE` (agent suspended/revoked, grant revoked/expired) → inline alert in modal, no secret panel.
6. Operator delivers the JWS to the agent out-of-band (outside KYAgent).

## F8. Verify an agent request (business) — REQ-005, REQ-009, REQ-012

Primary path is machine-to-machine (`POST /v1/verify` from the business backend).
The dashboard supports **inspection** and **debugging**:

**F8a Monitor decisions**
1. Verifications (P17), newest first. New events since load → "N new — show" button (no auto-shifting).
2. Filter `decision=DENY` to triage; click row → P18 drawer: DecisionStamp, ReasonCode, ReasonExplainer (failed check #, meaning, who fixes), ids linked to detail pages, `requestId` copy.

**F8b Debug with the Verify console**
1. Verify console (P19) → paste a `VerifyRequest` JSON produced by the agent SDK.
2. Client-side JSON parse check; ✖ invalid JSON → editor error at line/column, `Verify` disabled.
3. Confirm notice "Consumes the nonce and is logged" → `Verify` ⇒ `POST /v1/verify`.
4. Result panel: `ALLOW` + grantId/credentialId, or `DENY` + single reason. Announced via `role="status"`.
   - Re-submitting the same body yields `DENY NONCE_REPLAYED` — ReasonExplainer says so explicitly.
   - HTTP `500` with body `decision: "DENY"` → rendered as DENY `INTERNAL_ERROR` (never as a generic crash).
   - HTTP `4xx` without a decision body (401/403/413/415) → error panel, **no** decision stamp shown.
   - Network failure → error panel "No decision received. Treat as DENY." (REQ-012).

## F9. Revoke or suspend (all roles, scoped) — REQ-007

| Resource | Who | Endpoint | Reversible? |
|---|---|---|---|
| Agent | admin, operator (own) | `POST /v1/agents/{id}/revoke` | No |
| Agent | admin, operator (own) | `POST /v1/agents/{id}/suspend` → `/reactivate` | Yes |
| Credential | admin, operator (agent owner), business (audience) | `POST /v1/credentials/{id}/revoke` | No |
| Grant | admin, business (own) | `POST /v1/grants/{id}/revoke` | No |
| Operator | admin | `POST /v1/operators/{id}/suspend` | (no UI reactivation in MVP) |
| API key | admin | `POST /v1/api-keys/{id}/revoke` | No |

Flow:
1. Detail page ActionMenu → `Revoke …` / `Suspend …`.
2. ConfirmDestructiveDialog: consequence text specific to resource (e.g. agent: "All grants and credentials for this agent stop working on the next verification."), required reason, type-to-confirm (revoke only; suspend needs reason only).
3. ⇒ endpoint → wait for server response (no optimistic update) → refetch resource → StatusBanner shows new status + reason → toast "Agent revoked".
   - ✖ `409 INVALID_STATE` (already revoked) → dialog closes, inline info "Already revoked", data refetched.
   - ✖ `403`/`404` → dialog error; action removed from menu after refetch.
4. Reactivate (suspended agent only): simple confirm → ⇒ `/reactivate`.

## F10. Operator self-service overview (operator)

1. Overview shows own verification status; if `pending`/`rejected`/`suspended` a banner explains consequences and that an admin must act (no self-verification in MVP).
2. Attention list: suspended agents, credentials expiring within 24 h (link to re-issue via F7).

## F11. Inspect public keys (all)

Developer (P21) → JWKS viewer ⇒ `GET /.well-known/jwks.json`; health ⇒ `GET /healthz`.
Reason code catalogue for integrators. No authenticated data.

---

## Cross-flow rules

- After every mutation: refetch the affected resource and its parent list; never trust local state for status.
- Forms preserve input on server error; secrets are never preserved.
- Unsaved form + navigation → "Discard changes?" confirm (not for secret panels, which use the acknowledgement gate).
- Deep links: every resource has a stable URL; unauthorized → 404 page with no hint of existence (mirrors API).
