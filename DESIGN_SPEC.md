# KYAgent Dashboard — Design Spec (MVP)

Companion docs: [`USER_FLOWS.md`](USER_FLOWS.md) · [`UI_STATES.md`](UI_STATES.md) ·
[`DESIGN_TOKENS.json`](DESIGN_TOKENS.json). Binding contracts:
[`ARCHITECTURE.md`](ARCHITECTURE.md), [`docs/contracts/`](docs/contracts/).

## 1. Product framing

KYAgent is a **security control plane**, not a marketing site. The dashboard is
the human surface over the same public API (`dashboard/`, Next.js, ARCHITECTURE §6):
it has **no privileged backdoor** — every screen is a view over an endpoint in
`openapi.yaml`, gated by the RBAC matrix (ARCHITECTURE §5).

Design principles, in priority order:

1. **Decisions are legible.** `ALLOW` / `DENY` and its single reason code are
   the most important pixels in the product. Always shown as a text stamp plus
   the mono reason code — never color alone.
2. **Identity is exact.** IDs, key thumbprints, action patterns and reason
   codes are shown verbatim in monospace, copyable, never truncated without a
   full-value tooltip and copy button.
3. **Destructive actions are deliberate.** Revocation is irreversible for
   agents, credentials, grants and API keys (ARCHITECTURE §4). Every revoke
   requires a typed confirmation and a reason; the UI states "cannot be undone".
4. **Secrets are shown once and never again.** API-key plaintext and credential
   JWS are displayed only in the creation response panel, never persisted in
   browser storage, never re-fetchable.
5. **Deny by default in the UI too.** If the dashboard cannot determine
   permission or state (network error, 403, unknown status value), it hides
   the action and shows the error — it never optimistically enables it.
6. **Dense, calm, flat.** Tables over cards; borders over shadows; one accent
   color (indigo) for primary actions; semantic colors reserved for status and
   decisions. No gradients, illustrations, hero banners or metric vanity tiles.

## 2. Authentication model in the UI

- Sign-in = paste an API key (`kya_<keyId>_<secret>`). The dashboard calls a
  cheap authenticated read to resolve the role: admin → `GET /v1/api-keys?limit=1`;
  otherwise the key's role is inferred by probing `GET /v1/agents?limit=1`
  (operator) then `GET /v1/grants?limit=1` (business). *Implementation note:*
  if the API later exposes a `whoami` endpoint, use that instead; the UI must not
  guess a role from the key string.
- The key is held **in memory only** (React context) for the tab session. It is
  never written to `localStorage`, `sessionStorage`, cookies, URLs or logs.
  Reload ⇒ sign in again. A banner on the sign-in screen states this.
- Idle timeout: 30 min without interaction ⇒ key cleared, return to sign-in.
- Any `401 UNAUTHENTICATED` (e.g. key revoked mid-session) ⇒ clear key,
  route to sign-in with message "Your API key was rejected. It may have been revoked."
- The resolved role and owner (`op_…` / `biz_…` / "Platform admin") are shown
  permanently in the top bar so users know whose authority they act under.

## 3. Information architecture

### 3.1 Navigation (left rail, role-filtered)

Items not permitted for the role are **absent**, not disabled.

| Nav item | Route | admin | operator | business |
|---|---|---|---|---|
| Overview | `/` | ✔ | ✔ | ✔ |
| Operators | `/operators` | ✔ | — (see "My organization") | — |
| My organization | `/operators/{self}` | — | ✔ | — |
| Businesses | `/businesses` | ✔ | — | — |
| My business | `/businesses/{self}` | — | — | ✔ |
| Agents | `/agents` | ✔ | ✔ (own) | — (lookup via Agent lookup) |
| Agent lookup | `/agents/lookup` | — | — | ✔ |
| Grants | `/grants` | ✔ | ✔ (read, to own agents) | ✔ (own) |
| Credentials | `/credentials` | ✔ | ✔ (own agents) | ✔ (audience) |
| Verifications | `/verifications` | ✔ | — | ✔ (own) |
| Verify console | `/verify` | — | — | ✔ |
| API keys | `/api-keys` | ✔ | — | — |
| Developer | `/developer` | ✔ | ✔ | ✔ |

Groups in the rail: **Identity** (Operators / My organization, Businesses / My
business, Agents / Agent lookup) · **Authorization** (Grants, Credentials) ·
**Decisions** (Verifications, Verify console) · **Admin** (API keys) ·
**Developer**. Empty groups are omitted.

### 3.2 Top bar

`[≡ menu (<md)] KYAgent · <Page title breadcrumb> ······ [Role chip: operator · op_01J8…] [Theme toggle] [Sign out]`

- Role chip is a `Badge` (neutral) with mono owner id and copy-on-click.
- Environment chip: if `/healthz` returns `store: "memory"` show a warning
  chip "In-memory store — data is not persisted".

### 3.3 Page inventory

| # | Page | Route | Primary endpoints | Roles |
|---|---|---|---|---|
| P1 | Sign in | `/signin` | probe reads (§2) | public |
| P2 | Overview | `/` | list endpoints (counts from first page, `limit=50`) | all |
| P3 | Operator list | `/operators` | `GET /v1/operators` | admin |
| P4 | Operator detail | `/operators/{id}` | `GET /v1/operators/{id}`, `POST …/verification`, `POST …/suspend`, `GET /v1/agents?operatorId=` | admin, operator (own), business (public profile) |
| P5 | Business list | `/businesses` | `GET/POST /v1/businesses` | admin |
| P6 | Business detail | `/businesses/{id}` | `GET /v1/businesses/{id}` | admin, business (own) |
| P7 | Agent list | `/agents` | `GET /v1/agents` | admin, operator |
| P8 | Agent register | `/agents/new` | `POST /v1/agents` | operator (verified) |
| P9 | Agent detail | `/agents/{id}` | `GET /v1/agents/{id}`, revoke/suspend/reactivate, grants + credentials filtered by agent | admin, operator (own), business (public profile) |
| P10 | Agent lookup | `/agents/lookup` | `GET /v1/agents/{id}`, `GET /v1/operators/{id}` | business |
| P11 | Grant list | `/grants` | `GET /v1/grants` | admin, operator, business |
| P12 | Grant create | `/grants/new` | `POST /v1/grants` | business |
| P13 | Grant detail | `/grants/{id}` | `GET /v1/grants/{id}`, `POST …/revoke`, `GET /v1/credentials?grantId=` | admin, operator, business |
| P14 | Credential list | `/credentials` | `GET /v1/credentials` | all |
| P15 | Credential issue | modal on P9/P13 | `POST /v1/agents/{id}/credentials` | operator |
| P16 | Credential detail | `/credentials/{id}` | `GET /v1/credentials/{id}`, `POST …/revoke` | all (scoped) |
| P17 | Verification log | `/verifications` | `GET /v1/verifications` | admin, business |
| P18 | Verification detail | drawer on P17 | row data (`VerificationEvent`) | admin, business |
| P19 | Verify console | `/verify` | `POST /v1/verify` | business |
| P20 | API key list | `/api-keys` | `GET/POST /v1/api-keys`, `POST …/revoke` | admin |
| P21 | Developer | `/developer` | `GET /.well-known/jwks.json`, `GET /healthz`, static docs | all |
| P22 | Not found / Forbidden | `*` | — | all |

Query filters (e.g. `operatorId`, `agentId`, `status`, `decision`) are those
declared in `openapi.yaml`; the UI must not offer filters the API does not
support. Filters are reflected in the URL query string (never the API key).

## 4. Page layouts and component hierarchy

Global shell:

```
AppShell
├── SkipLink ("Skip to main content")
├── NavRail (role-filtered NavGroup › NavItem)
├── TopBar (Breadcrumbs, EnvChip, RoleChip, ThemeToggle, SignOutButton)
├── main#content
│   └── <Page>
├── ToastRegion (aria-live="polite")
└── ModalRoot / DrawerRoot (portal, focus-trapped)
```

Common page pattern (list pages):

```
ListPage
├── PageHeader (h1 title, one-line description, PrimaryAction?)
├── FilterBar (StatusFilter, IdSearch, DateRange?, ClearFilters)
├── DataTable
│   ├── TableHeader (sortable only where API supports ordering; default createdAt desc)
│   ├── TableRow[] (row click → detail route; row has a real <a> on the primary cell)
│   └── TableFooter (Pagination: "Load more" using nextCursor)
└── (state slots: Loading | Empty | Error — see UI_STATES.md)
```

Common detail pattern:

```
DetailPage
├── PageHeader (h1 name, IdBadge(mono, copy), StatusBadge, ActionMenu)
├── StatusBanner? (suspended / revoked / pending / rejected explanation + statusReason)
├── FactSheet (definition list: label/value pairs)
└── Tabs (related resources, each a DataTable)
```

### P1 Sign in
Single centered form (max 440 px) on `bg.canvas`: product name, one sentence
("Paste an admin, operator or business API key."), password-type input with
show/hide toggle, `Sign in` button, notice "Key is kept in this tab's memory
only and cleared on reload." No "remember me".

### P2 Overview
Not a vanity dashboard. Role-specific **attention list**: things requiring
action, each a row linking to the resource.
- admin: operators `pending` · operators `suspended` · API keys created in last 7 days.
- operator: own status (banner if not `verified` — "You cannot register agents until verified") · agents `suspended` · credentials expiring < 24 h.
- business: last 20 verifications (compact table with DecisionStamp + reason) · grants expiring < 7 days · DENY count by reason code for the loaded page (plain table, not chart).

### P4 Operator detail
FactSheet: type, legal name, country, contact email (admin/own only), status,
statusReason, createdAt/updatedAt. **Verification panel**: method `mock`,
KycResult badge, SanctionsMode + SanctionsResult badges, checkedAt; persistent
note "MVP: mock KYC. Not a real identity check." Actions (admin): `Run verification`
(enabled when `pending` or `rejected`; label "Re-run verification" when rejected),
`Suspend` (reason required). Tab: Agents.
Business role sees only the `OperatorPublicProfile` fields; no email, no actions.

### P8 Agent register (operator)
Two-step form, blocked with a banner if the operator isn't `verified`
(API returns `409 OPERATOR_NOT_VERIFIED`; UI pre-checks and still handles the error).

1. **Details**: name, description (optional).
2. **Key**: public key field (base64url, 43 chars, live format check), proof-of-possession
   field (base64url signature). A read-only `SigningStringPreview` shows the exact
   string to sign: `KYA-REGISTER-V1\n{operatorId}\n{publicKey}` with copy button,
   and a collapsible CLI/SDK snippet (`sdk/agentSigner.ts proofOfPossession()`).
   **The dashboard never generates or accepts private keys.** There is no
   "generate key pair" button; a callout explains keys are generated on the agent host.

On success: route to Agent detail with toast "Agent registered · agt_…".

### P9 Agent detail
Header: name, `agt_…` IdBadge, StatusBadge, ActionMenu (operator own / admin):
`Issue credential` (operator only, active agents only), `Suspend`, `Reactivate`
(only when suspended), `Revoke` (danger).
FactSheet: operator (link + operator StatusBadge — agents inherit risk from the
operator), public key (mono, wrapped), key thumbprint (mono), created, revokedAt,
statusReason. Tabs: **Grants** (to this agent), **Credentials**, **Recent decisions**
(admin only; business sees its own via Verifications filter).

### P10 Agent lookup (business)
The "KYC check" screen for relying parties. One input: agent id. Result is an
**IdentityCard** panel (not a decorative card — a bordered fact sheet):

```
Agent        agt_01J8…   [active]
Name         Invoice Bot
Key          thumbprint  x7Kq…   [copy]
Operator     Acme Robotics Ltd  op_01J8…  [verified]  GB  organization
Your grants  2 active  → view
```
Overall verdict line derived only from contract statuses: "Identity verified —
agent active, operator verified" or "Not trusted — operator suspended" (critical).
This is informational; the authoritative decision is `/v1/verify`.
`404` ⇒ "No agent with this id is visible to you." (no existence oracle wording).

### P12 Grant create (business)
Form sections:
1. **Agent**: agent id input → inline lookup preview (IdentityCard compact). Submit disabled until agent resolves `active` and operator `verified`.
2. **Actions**: `ActionPatternInput` — tokenized chips; each validated against
   `^[a-z0-9_-]+(:[a-z0-9_-]+)*(:\*)?$`; bare `*` rejected with message
   "A bare * is not allowed. Use a prefix such as orders:*". Helper shows what a
   wildcard matches ("orders:* matches orders:create, orders:refund:partial — not orders").
3. **Constraints** (optional, each toggled on): `maxAmount` (integer, minor units,
   with live "= 250.00 USD" hint when currency set), `currency` (ISO 4217 select),
   `resources` (tokenized list). Copy: "Missing values in the request are treated as violations."
4. **Expiry**: date-time picker, required, future, ≤ now + 365 days. Quick picks: 1 day, 7 days, 30 days, 90 days. Displayed in local time with UTC shown beneath.
Review step summarises the grant in plain language before `Create grant`.

### P13 Grant detail
Header with status (active / revoked / expired-derived). FactSheet: business,
agent (link), operator, actions (ActionChip list), constraints table, expiresAt
with relative time, statusReason. Business action: `Revoke grant` (danger;
copy "All credentials derived from this grant stop working on the next verification").
Operator action: `Issue credential for this grant`. Tab: Credentials.

### P15 Credential issue (operator, modal)
Fields: grant (preselected or select among active grants to the agent), TTL
(seconds, 60..max; presets 5 min, 1 h, 24 h; shows computed expiry
`min(now + ttl, grant.expiresAt)` and warns when clamped by grant expiry).
Result state = **SecretReveal** panel with the compact JWS: monospace, wrapped,
`Copy` button, `Decoded claims` disclosure (header + payload JSON, signature
omitted), and warning "This credential is shown once. KYAgent does not store it.
It only works together with the agent's private key." Closing requires checking
"I have copied the credential".

### P16 Credential detail
Record fields only (`CredentialRecord`) — never the JWS. Actions: `Revoke` for
agent owner / audience business / admin.

### P17 Verification log / P18 detail drawer
Columns: time (relative + absolute tooltip), DecisionStamp, reason code (mono),
agent id, action (mono), grant id, credential id, verification id.
Server filters (per `openapi.yaml`): decision (ALLOW/DENY), agent id. A reason-code
quick filter applies **client-side to loaded rows only** and is labelled
"in loaded results" so users don't mistake it for a complete search.
Drawer: full `VerificationEvent`, `ReasonExplainer` (see §5), requestId (copy, for support).

### P19 Verify console (business)
A debugging tool to paste a real `VerifyRequest` body and see the decision.
Left: JSON editor (mono, line numbers, schema hint). Right: result panel with
DecisionStamp, reason, ReasonExplainer, raw JSON response. Warning: "This call
is a real verification: it consumes the nonce and is recorded in your log."
No field in the console accepts a private key; signing must be done by the agent/SDK.

### P20 API keys (admin)
Table: name, displayPrefix (mono), role badge, owner id, status, created, last used.
`Create API key` modal: name, role, owner (required select for operator/business —
populated from lists; disabled for admin). Result = **SecretReveal** with the
plaintext `secret`, same once-only pattern as P15. `Revoke` (danger, typed confirm).

### P21 Developer
Static, read-only: service health (`/healthz`), JWKS viewer (kid, alg, x),
signing-string reference for `KYA-SIG-V1`, reason code catalogue (table of all
`REASON_CODES` with the verification step number and remediation hint), link to
OpenAPI. Pure reference — no secrets, no key generation.

## 5. Component library

| Component | Purpose / rules |
|---|---|
| `DecisionStamp` | `ALLOW` / `DENY`; mono semibold uppercase, 2 px border, `decision.*` tokens, leading icon (check / cross). Text always present. `aria-label="Decision: deny"`. |
| `ReasonCode` | Mono code chip. Tooltip + `ReasonExplainer` link. |
| `ReasonExplainer` | Maps each `ReasonCode` to: failed check # (ARCHITECTURE §3), human explanation, who can fix it (agent / operator / business / admin). E.g. `NONCE_REPLAYED` → "Step 8: this nonce was already used by this agent. Possible replay attack, or the client retried with the same nonce." Content is static, versioned with the reason code list. |
| `StatusBadge` | Text + small dot; color from `semanticMapping` in tokens. Unknown value ⇒ neutral badge showing raw value (never hidden). |
| `IdBadge` | Mono id, middle-truncated at ≥ 20 chars (`agt_01J8…4QZ`), full value in tooltip and accessible name, copy button. |
| `CopyButton` | Icon button, `aria-label="Copy <thing>"`, announces "Copied" via live region. Clipboard contents are not logged. |
| `FactSheet` | `<dl>` two-column (label caption / value body); single column < sm. |
| `DataTable` | Semantic `<table>`, sticky header, 44 px rows (36 px compact toggle), row link on first cell, keyboard navigable, "Load more" pagination via `nextCursor`. < sm renders as stacked `<li>` rows with the same fields. |
| `FilterBar` | Controls bound to URL query; `Clear filters`. Only query params declared in `openapi.yaml` (e.g. `status`, `operatorId`, `agentId`, `grantId`, `decision`). |
| `ActionMenu` | Overflow menu of permitted actions only; destructive items last, separated, danger colored. |
| `ConfirmDestructiveDialog` | Title "Revoke agent agt_…?", consequence text, required `reason` textarea (maps to `SuspendRequest.reason` / revoke reason), type-to-confirm input (the resource id's last 6 chars), `Revoke` danger button disabled until valid. Focus starts on Cancel. |
| `SecretReveal` | One-time secret display (`secret.*` tokens), copy button, acknowledgement checkbox gates close; secret is dropped from React state on close; `autocomplete="off"`, excluded from any analytics. |
| `ActionPatternInput` / `ActionChip` | Tokenized input with regex validation; chips mono; wildcard chips show `*` suffix with tooltip of match semantics. |
| `ConstraintEditor` | Toggle-per-constraint fieldset. |
| `ExpiryField` | Date-time + presets + UTC readout + relative time; validates future and ≤ 365 d. |
| `SigningStringPreview` | Mono pre block showing exact bytes-to-sign with visible `\n` markers. |
| `IdentityCard` | Bordered fact panel combining agent + operator statuses (P10, P12). |
| `JsonViewer` / `JsonEditor` | Mono, line numbers, collapsible; editor validates JSON before enabling submit. |
| `StatusBanner` | Full-width inline alert for resource state (warning/critical/pending), includes `statusReason`. |
| `InlineAlert`, `Toast` | Errors/info. Toasts only for success confirmations; errors stay inline and persistent. |
| `EmptyState` | Text-only: one-line explanation + next action button (role-permitting). No illustrations. |
| `Skeleton` | Row-shaped placeholders matching table/fact sheet geometry. |
| `RelativeTime` | `<time datetime>` with relative text, absolute UTC in tooltip. Expiry < 24 h rendered with warning token. |

## 6. Content and formatting rules

- Timestamps: relative in tables ("3 min ago", "in 6 days"), absolute ISO-like
  `2026-09-26 12:00:00 UTC` in detail views and tooltips. Server times are UTC.
- IDs, keys, actions, reason codes, JSON: always `typography.code`.
- Amounts: `maxAmount` stored in minor units; display both ("25000 · 250.00 USD").
  Currency exponent from ISO 4217; unknown ⇒ show raw minor units only.
- Terminology is fixed: *Operator*, *Business*, *Agent*, *Grant*, *Credential*,
  *Verification*, *Revoke* (irreversible), *Suspend* (reversible). Never "delete".
- Error copy shows the API `error.code`, human message, and `requestId` (copyable)
  — never stack traces, never request headers.
- Never render: API key plaintext after the reveal panel closes; credential JWS
  after the issue modal closes; `Authorization` headers; pepper/server key material.

## 7. Responsive behavior

| Breakpoint (tokens) | Layout |
|---|---|
| ≥ lg (1200) | Full nav rail (232 px), content max 1280 px, detail drawers (480 px) overlay the right of the table, table keeps context. |
| md–lg (900–1199) | Nav collapses to 64 px icon rail with tooltips + accessible labels; drawers overlay full height. |
| sm–md (640–899) | Icon rail; drawers become full-screen sheets; FactSheet stays two columns; FilterBar wraps. |
| < sm (< 640) | Nav in off-canvas sheet (hamburger); tables render as stacked rows showing primary id, status, and 2 key fields; ActionMenu becomes bottom sheet; all targets ≥ 44 px; Verify console stacks editor above result. |

Horizontal scroll is only allowed inside `JsonViewer`/`SigningStringPreview`
code blocks, never for the page. Long mono values wrap with `overflow-wrap: anywhere`.

## 8. Accessibility (WCAG 2.2 AA)

- **Color independence:** decisions and statuses always carry text; icons are
  supplementary and `aria-hidden`. Contrast pairs listed in `DESIGN_TOKENS.json`
  `color.contrastPairs` are verified by an automated test.
- **Keyboard:** everything reachable in logical order; skip link; visible focus
  ring (2 px `border.focus`, 2 px offset) on every interactive element, never removed;
  menus/dialogs follow WAI-ARIA APG patterns (Esc closes, arrow keys in menus);
  focus trapped in modals/drawers and restored to the trigger on close.
- **Semantics:** one `h1` per page; landmarks `nav`, `main`, `header`; tables use
  `<th scope>`; FactSheet is `<dl>`; forms have `<label for>`, required marked in
  text, errors linked via `aria-describedby` and summarised at top with links to fields.
- **Live regions:** toast region `polite`; verification result panel announces
  "Decision: DENY, reason NONCE_REPLAYED" (`role="status"`); errors use `role="alert"`
  only for blocking failures.
- **Motion:** respect `prefers-reduced-motion` (all durations → 0); no auto-refresh
  that moves content under the cursor — new verification rows appear behind a
  "N new — show" button.
- **Timeouts:** idle sign-out warns 2 min ahead with a dialog allowing extension (WCAG 2.2.1).
- **Target size:** ≥ 24×24 px everywhere (2.5.8), ≥ 44 px below `md`.
- **Text:** supports 200 % zoom and 320 px reflow; no text in images.
- **Copy buttons** announce success; secret fields are not read automatically by
  screen readers until focused (no live region on secret content).

## 9. Security-relevant UI requirements (traceability)

| Req | UI obligation |
|---|---|
| REQ-001 | Agent lookup (P10) + Agent detail show identity, key thumbprint, bound operator and statuses. |
| REQ-002 | Grant create/detail (P12/P13): explicit actions, constraints, mandatory expiry. |
| REQ-003 | Operator verification panel (P4); agent registration blocked unless operator `verified`; operator shown on every agent view. |
| REQ-004 | Registration takes public key + proof of possession only; dashboard never handles private keys. |
| REQ-005 | DecisionStamp + ReasonCode + ReasonExplainer in P17–P19. |
| REQ-006 | Credential issue modal shows scope, TTL clamp, expiry; JWS shown once. |
| REQ-007 | Revoke flows everywhere with irreversible copy; statuses refetched after mutation (no optimistic "revoked" without server confirmation). |
| REQ-009 | Verify console warns about nonce consumption; `NONCE_REPLAYED` / `TIMESTAMP_OUT_OF_WINDOW` explained. |
| REQ-010 | API key admin (P20), hashed-at-rest explained ("KYAgent cannot show this key again"); role-filtered nav; 401/403 handling. |
| REQ-011 | No secret configuration UI; Developer page shows only public JWKS. |
| REQ-012 | UI hides actions on unknown permission/state; verify errors render as DENY with `INTERNAL_ERROR`. |

## 10. Out of scope (MVP)

Real KYC document upload, billing, org/user management beyond API keys,
charts/analytics, agent key rotation UI (revoke + re-register), blockchain views,
bot-detection views, localization (English only; copy centralized for later i18n).
