# KYAgent — Demo runbook (MongoDB Atlas)

This runbook reproduces all five hackathon demos from a fresh clone with an Atlas connection
string. Scope and acceptance come from [`DELIVERY_PLAN.md`](../DELIVERY_PLAN.md) §1, §5 and §10.
Every command and expected output below was rehearsed on Atlas on 2026-09-28, and the output
excerpts are copied from that run. Ids with a ULID suffix (`inv_01M3…`, `rcp_…`, `hev_…`) and
hashes change on every run. The fixed demo ids (`agt_TREASURYBOT`, `grt_TB_USDC`,
`mem_INV-1042`, …) do not change.

## The judge story

Read this word for word (DELIVERY_PLAN §10):

> KYAgent is an investigation harness for AI agents that move money. Every decision is assembled inside MongoDB Atlas: Atlas Search screens wallets and counterparties against sanctions, Vector Search pulls in only *human-verified* security memories as precedent, and Change Streams re-screen agents the moment a sanctions list changes. When an analyst confirms an account takeover, the harness rewrites its own investigation policy into a new, versioned, auditable harness version stored in MongoDB. The next case visibly runs the extra step, while a frozen set of invariants (exact-sanctions block, delegation limits, no self-approval, no unverified precedent) stays out of reach of the model and the adaptation loop.

## 1. Prerequisites

| Item | Requirement |
|---|---|
| Node.js | 20 or later. Run `npm install` once. It installs the official `mongodb` driver. Without it, every demo script fails with `Cannot find package 'mongodb'`. |
| Atlas cluster | Any Atlas tier with Atlas Search and Vector Search, and **M0 (free) is enough**. The demo uses 2 of M0's 3 search-index slots (`sanctions.sanctions_search`, `security_memories.memory_vector`), so other search indexes in the cluster must leave 2 slots free. Change streams work on every Atlas tier because Atlas clusters are replica sets. Add your IP to the Atlas network access list. |
| Database user | Needs read/write on the demo database and permission to create Atlas Search indexes on it. `make demo-reset` creates the indexes. Atlas's built-in *Read and write to any database* role covers this for a hackathon cluster. |
| Other services | None. The demo runs fully in fixture mode (see §5), so it needs no Voyage, LLM, OFAC or chain access. |

### `.env`

```bash
npm install
npm run env:init          # writes .env (git-ignored, 0600) with signing key, pepper, bootstrap admin key
```

Edit `.env` and set these values:

| Key | Value |
|---|---|
| `MONGODB_URI` | Your Atlas `mongodb+srv://…` string, **in single quotes**. The `&` in `?retryWrites=true&w=majority` breaks `. ./.env` if it is unquoted. |
| `MONGODB_DB` | `kyagent` (the default) |
| `HOST` | `127.0.0.1` (recommended for a laptop demo) |
| `NODE_ENV` | `development`. The demo scripts refuse to run with `production`. |
| `KYA_SIGNING_PRIVATE_KEY`, `KYA_API_KEY_PEPPER`, `KYA_BOOTSTRAP_ADMIN_API_KEY` | Keep the values `env:init` generated. A fixed pepper means API keys stay valid across server restarts. |
| `SANCTIONS_MODE`, `CHAIN_MODE`, `LLM_MODE`, `EMBEDDINGS_MODE` | Leave them unset or set them to `fixture`. |

Load `.env` into **every** terminal you use. Never echo `MONGODB_URI` or a key on a shared screen.

```bash
set -a; . ./.env; set +a
```

### Reset to the judging scenario

```bash
make demo-reset
```

Expected (about 9 s in rehearsal):

```
demo-reset: database kyagent
  cleared   {...}
  migrations 0 applied, 8 up to date
  indexes   sanctions.sanctions_search=READY, security_memories.memory_vector=READY
  seeded    {"operators":1,"businesses":1,"agents":1,"grants":1,"transactions":30,"security_memories":3,"sanctions":50,"sanctions_updates":1,"passports":1,"harness_versions":1}
  $search sanctions_search -> sdn_LAZARUS, sdn_006
  $vectorSearch memory_vector (VERIFIED) -> mem_INV-1042, mem_INV-0977
demo-reset: OK (scenario restored, both search indexes queryable)
```

On a brand-new cluster the first run also creates both search indexes. It waits until they are
queryable, which can take a few minutes. `make demo CHECK=1` re-checks the scenario and both
indexes without changing anything.

## 2. Terminal layout for the live run

| Terminal | Command | Why |
|---|---|---|
| **A: server** | `npm start` | API and dashboard on `http://127.0.0.1:8080/dashboard/`, **plus the sanctions change-stream watcher**. Wait for `sanctions watcher started` in the log (about 3 s). |
| **B: driver** | `make demo CHECK=1 DEMO=n`, `npm run sanctions:apply`, `curl` | Runs each demo on Atlas and prints the evidence. `make demo DEMO=n` listens on an ephemeral port, so it can run next to terminal A. |
| **Browser** | `http://127.0.0.1:8080/dashboard/` | Sign in with `KYA_BOOTSTRAP_ADMIN_API_KEY` from `.env`. The Continuous-KYA strip and the live event list are admin-only. |

> Why `npm start` rather than `make demo` for the live run? `make demo` (`scripts/demo.js`)
> serves the API and dashboard on Atlas but **does not start the sanctions watcher**. Only
> `src/server.js` does. Demo 4 needs the watcher, so the live run uses `npm start`. `make demo`
> is still useful on its own for Demos 1–3 and for handing out the demo-only keys it prints.

**Run order: 1 → 2 → 3 → 5 → 4.** Demos 1 and 2 need the pristine state (TreasuryBot's original
key, passport `ACTIVE`). Demo 3 rotates TreasuryBot's signing key. Demo 5 builds on the Demo 3
case. Demo 4 suspends the passport, so it runs last. To start over, run `make demo-reset`
(and restart terminal A).

## 3. Three-minute version

| Time | Demo | Do | Say |
|---|---|---|---|
| 0:00 | Story | Read the judge story aloud with the dashboard on screen. | |
| 0:25 | 1 + 2 | `make demo CHECK=1 DEMO=1`, then `DEMO=2`. Each takes about 3 s. | "Same agent, same delegation: 1 500 USDC to a known counterparty is ALLOW. 30 000 USDC is BLOCK by an immutable invariant, and both come with a receipt stored in Atlas." |
| 0:55 | 3 | `make demo CHECK=1 DEMO=3` (about 3 s), then open the investigation id in **Investigations**. | "Rotated key, new counterparty, amount near the ceiling. `$vectorSearch` pulls the human-VERIFIED takeover INV-1042 as precedent, so the case goes to REVIEW. The irrelevant memory scores below the threshold and is not used." |
| 1:40 | 5 | Confirm the Demo 3 case with `curl`, then run the next case (about 4 s). Show `/v1/harness/versions`. | "An analyst confirmed the takeover. The case became VERIFIED memory, and the harness wrote v2 with the old policy, new policy, diff, evidence and approval. The next case runs `signing_key_history_check`. The invariants hash is identical in v1 and v2." |
| 2:20 | 4 | Leave the dashboard visible and run `npm run sanctions:apply` in B. | "A sanctions list write in Atlas fires the change stream. TreasuryBot is re-screened, and its passport goes ACTIVE → RE_SCREENING → SUSPENDED live, in about 2 s in rehearsal." |
| 2:50 | Close | | "Every step you saw is a MongoDB Atlas read or write, and every decision has a hash-anchored receipt." |

## 4. Walkthrough: the five demos

### Demo 1: clean ALLOW (P1)

```bash
make demo CHECK=1 DEMO=1
```

Expected:

```
  stages    identity[code]=passed -> delegation[find]=passed -> sanctions[$search]=passed -> signals[aggregate]=passed -> memory[$vectorSearch]=passed -> policy[code]=passed -> decision[code]=passed
  signals   (none)
  identity  VERIFIED (ALLOWED) · action AUTHORIZED
  decision  ALLOW (CLEAR)  identity=ALLOW  status=DECIDED
  receipt   receipts/rcp_… receiptHash=… riskDecision=ALLOW
  passport  pp_TREASURYBOT ACTIVE agent=agt_TREASURYBOT delegation=grt_TB_USDC v1 harness=v1 sanctions=2026-09-01 …
DEMO 1 OK: ALLOW / CLEAR, passport ACTIVE, receipt persisted
```

**Screen:** **Investigations** → paste the `inv_…` id from the `HTTP` line → **Load evidence**. You see four
panels: *Current signals* (none), *MongoDB security memory (Vector Search)*, *Harness v1*, and
*Decision + receipt* (ALLOW / CLEAR). **Open receipt** shows the stored receipt.

**Talking points:** the same Ed25519 identity check as `/v1/verify`, which is unchanged and
byte-compatible, then delegation from `grants`, sanctions from `$search`, signals from an
aggregation over 30 Atlas transactions, and memory from `$vectorSearch`. The receipt is anchored
by a `receipt.issued` event in the hash-chained audit log.

### Demo 2: BLOCK over the delegation maximum (P1)

```bash
make demo CHECK=1 DEMO=2
```

Expected:

```
  delegation grt_TB_USDC maxAmount=25,000 USDC
  stages    identity[code]=passed -> delegation[find]=failed -> … -> decision[code]=failed
  signals   AMOUNT_ANOMALY, NEAR_CEILING
  identity  VERIFIED (ALLOWED) · action UNAUTHORIZED
  decision  BLOCK (DELEGATION_MAX_EXCEEDED<-CONSTRAINT_VIOLATION)  identity=DENY  status=DECIDED
DEMO 2 OK: BLOCK / DELEGATION_MAX_EXCEEDED (wraps CONSTRAINT_VIOLATION), identity VERIFIED, receipt persisted
```

**Talking points:** the agent is who it says it is (identity VERIFIED) but is not allowed to do
this (action UNAUTHORIZED). `INV_DELEGATION_MAX` is an immutable invariant. The risk reason wraps
the existing `/v1/verify` reason `CONSTRAINT_VIOLATION`, so existing integrators still see the code
they already handle.

### Demo 3: verified memory via Vector Search changes the decision (P0)

```bash
make demo CHECK=1 DEMO=3
```

Expected:

```
  case      agt_TREASURYBOT payments:create 21,000 USDC -> 0x7a11000000000000000000000000000000c0ffee (Unfamiliar OTC desk)
  key       signed with the rotated key l7k3V-RjzWugyj_uwdw3_JBS6WEUs8TXVlAr6rj4g-E (rotation applied now)
  HTTP      POST /v1/investigations -> 201 inv_…          <- note this id for Demo 5
  stages    … signals[aggregate]=flagged -> memory[$vectorSearch]=flagged -> policy[code]=flagged -> decision[code]=flagged
  signals   NEW_COUNTERPARTY, SIGNING_KEY_CHANGED, AMOUNT_ANOMALY
  memory    $vectorSearch k=3 minScorePpm=780000 hits=1
    - mem_INV-1042  score=0.9629 (962910 ppm)  VERIFIED  CONFIRMED_ACCOUNT_TAKEOVER  precedent=true  "Treasury agent account takeover"
  decision  REVIEW (MEMORY_PRECEDENT_TAKEOVER)  identity=DENY  status=AWAITING_REVIEW
DEMO 3 OK: REVIEW / MEMORY_PRECEDENT_TAKEOVER from a VERIFIED Vector Search precedent
```

**Screen:** open the id in **Investigations**. The *MongoDB security memory* panel shows
`mem_INV-1042`, its score and a VERIFIED badge. *Decision + receipt* shows
REVIEW / `MEMORY_PRECEDENT_TAKEOVER`.

**Talking points:**
- The case is similar to INV-1042 but not identical: different amount, different counterparty.
- `mem_INV-1101` is similar but UNVERIFIED. The index filter `status: VERIFIED` excludes it,
  because unverified memory is never used as precedent.
- `mem_INV-0977`, an irrelevant rate-limit false positive, falls below `minScore`, so it is not
  treated as proof.
- The hits are persisted on the investigation in Atlas, so they survive a restart.
- The `identity=` field is the existing ALLOW/DENY value. `riskDecision` is the new
  ALLOW/REVIEW/BLOCK verdict.

### Demo 5: human confirmation, then memory VERIFIED, harness v2, and a different next case (P0)

Run this in terminal B with `.env` loaded, while `npm start` is running. `INV_A` is the Demo 3
investigation id. The admin confirms it. The business key that opened the case could not confirm
it, because `INV_NO_SELF_APPROVAL` forbids that.

```bash
INV_A=inv_…   # from Demo 3
curl -s -X POST "http://127.0.0.1:8080/v1/investigations/$INV_A/confirm" \
  -H "Authorization: Bearer $KYA_BOOTSTRAP_ADMIN_API_KEY" -H 'Content-Type: application/json' \
  -d '{"outcome":"CONFIRMED_ACCOUNT_TAKEOVER","approveAdaptation":true,"note":"analyst confirmed"}'
```

Expected response (`200`; the parts to show):

```
"memory":{"id":"mem_inv_…","status":"VERIFIED"},
"adaptation":{"proposed":true,"applied":true,"eventId":"hev_…","fromVersion":1,"toVersion":2,
  "diff":[{"op":"add","path":"/steps/5","value":"signing_key_history_check"},{"op":"replace","path":"/memoryRetrieval/k","value":5}]}
```

Show the persisted versions and the adaptation event. Both are admin-readable.

```bash
curl -s http://127.0.0.1:8080/v1/harness/versions -H "Authorization: Bearer $KYA_BOOTSTRAP_ADMIN_API_KEY"
curl -s http://127.0.0.1:8080/v1/harness/events   -H "Authorization: Bearer $KYA_BOOTSTRAP_ADMIN_API_KEY"
```

Expected: v2 is `active` with steps
`identity>delegation>sanctions>signals>memory>signing_key_history_check>policy`, and v1 is
`superseded`. Both have the **same `invariantsHash`**. The event records `oldPolicy`,
`newPolicy`, `diff`, evidence, `approvedBy` (admin) and `approvedAt`.

Next, run an equivalent case. It needs a business key and a request signed on the "agent host".
The dashboard never holds agent keys, so this one-liner signs it with the fixture key.

```bash
BIZ_KEY=$(curl -s -X POST http://127.0.0.1:8080/v1/api-keys \
  -H "Authorization: Bearer $KYA_BOOTSTRAP_ADMIN_API_KEY" -H 'Content-Type: application/json' \
  -d '{"name":"demo 5 business","role":"business","ownerId":"biz_CIRCLEPAY"}' \
  | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>process.stdout.write(JSON.parse(s).secret))')

node --input-type=module -e "
import { buildVerifyRequest } from './src/sdk/agentSigner.js';
import { DEMO3_CASE, DEMO_IDS, treasuryBotKey } from './src/seed/hackathon.js';
console.log(JSON.stringify(buildVerifyRequest(treasuryBotKey('rotated').privateKey,
  { agentId: DEMO_IDS.agent, audience: DEMO_IDS.business, action: DEMO3_CASE.action, context: { ...DEMO3_CASE.context } })));
" | curl -s -X POST http://127.0.0.1:8080/v1/investigations \
  -H "Authorization: Bearer $BIZ_KEY" -H 'Content-Type: application/json' --data-binary @-
```

Expected (`201`): `harnessVersion: 2`, `riskDecision: REVIEW` / `MEMORY_PRECEDENT_TAKEOVER`, and stages

```
identity -> delegation -> sanctions[$search] -> signals[aggregate] -> memory[$vectorSearch]
  -> signing_key_history_check[find+aggregate]=flagged -> policy -> decision
```

The memory hits are the newly VERIFIED `mem_inv_…` (from the case just confirmed) and `mem_INV-1042`.

**Screen:** open the new id in **Investigations**. The harness panel reads *Harness v2* and shows the
extra step, with the callout *"Additional provenance investigation invoked because of verified
prior incidents"*.

**Talking points:** a human approved the change, and the LLM only *proposes* policy diffs.
`LLM_MODE=fixture` uses a deterministic template. The invariants are code, and their hash is
identical across versions. Adaptation can change steps and retrieval settings, but it cannot
change the invariants.

> A signed request is valid for ±300 s and its nonce is single-use, so sign and post in one go
> (as above). Re-run the whole command to get a fresh request.

### Demo 4: Change Streams continuous KYA, passport SUSPENDED (P0)

Keep the dashboard (admin) visible. The **Continuous KYA** strip is fed by `GET /v1/events/stream`.
In terminal B, run:

```bash
npm run sanctions:apply
```

Expected in B:

```
apply-sanctions-update: upd_2026-09-26 applied (dataset 2026-09-26; sdn_MERIDIAN_OTC)
```

**Screen:** the strip advances through *MongoDB Change Detected → Affected Agent Found →
Re-screen Started → Passport Suspended*. The live list shows an `investigation.decided` row with trigger `sanctions_change` and
BLOCK. **Open** it to see the `SANCTIONS_EXACT_MATCH` evidence from `$search`. The events observed
in rehearsal, in order:

```
sanctions.change_detected, change_detected, affected_agent, passport.status_changed (ACTIVE→RE_SCREENING),
rescreen_started, investigation.decided (BLOCK), passport.status_changed (RE_SCREENING→SUSPENDED), passport_suspended
```

In rehearsal, the sanctions write to SUSPENDED took about 2.1 s. The passport document in Atlas
(`kyagent.passports`, `_id: "pp_TREASURYBOT"`) ends with `status: "SUSPENDED"` and
`statusHistory` `ACTIVE → RE_SCREENING → SUSPENDED`. Show it in Atlas Data Explorer or with the
MongoDB MCP server if asked.

**Talking points:** the update is a real write to `sanctions`, so the change stream fires by
itself, with no polling. The update adds TreasuryBot's *existing* counterparty wallet, which the
watcher finds and re-screens. An exact sanctioned-wallet hit is deterministic and always BLOCK.
The watcher persists its resume token in `watcher_state`, so a restart does not miss an update.

## 5. Fallback modes

The data-source modes default to `fixture` and work offline. **Fixture changes where data comes
from, never the store.** Every mode still reads and writes Atlas, and there is no in-memory
substitute for the live demo.

| Mode | Demo value | What `fixture` means | `live` |
|---|---|---|---|
| `EMBEDDINGS_MODE` | `fixture` | Pinned vectors in `fixtures/embeddings.json` (precomputed with `voyage-3.5-lite`, 1024-d), still queried with `$vectorSearch` | Needs `VOYAGE_API_KEY` |
| `SANCTIONS_MODE` | `fixture` | `fixtures/sanctions/*.json` seeded into Atlas `sanctions`, queried with `$search`; the update is a real Atlas write | Real OFAC import is P4, not built |
| `CHAIN_MODE` | `fixture` | `fixtures/transactions/treasurybot.json` seeded into Atlas `transactions` | Real RPC is P4, not built |
| `LLM_MODE` | `fixture` | Deterministic template adaptation proposal | Only with an injected client (`buildApp({ llm })`). `npm start` injects none, so `live` records `adaptation.rejected`. **Keep `fixture` for the demo.** |

If a presentation surface fails, use one of these:

- **Dashboard unavailable:** run every demo headless. Demos 1–3 run with
  `make demo CHECK=1 DEMO=n`. Each prints its evidence and exits non-zero on any mismatch. Demos
  4 and 5 use the `curl` / `npm run sanctions:apply` commands above, and the terminal output
  carries the story.
- **Live stream not visible:** the investigation and passport are in Atlas. Open the investigation
  by id in **Investigations**, or show `kyagent.passports` / `kyagent.investigations` in Atlas Data
  Explorer.
- **Atlas unreachable:** there is no live fallback, by design (P0-1). Show the automated evidence
  instead: `ATLAS_TEST_URI=<uri> npm run test:atlas` (acceptance tests for every demo on unique
  throwaway databases) when a network is available, and `npm test` offline, where the Atlas suites
  are skipped and reported as skipped.

## 6. Recovery if a step fails

| Symptom | Cause | Fix |
|---|---|---|
| `Cannot find package 'mongodb'` | Dependencies not installed | `npm install` |
| `Atlas required: set MONGODB_URI …` | `.env` not loaded in this terminal | `set -a; . ./.env; set +a` |
| `Atlas required: could not connect …` / timeout | IP not on the Atlas access list, wrong URI, or cluster paused | Fix network access, then `make demo-reset` |
| `demo-reset failed: …` during indexes, or a search index is not queryable | Index still building, or no free search-index slot (M0 allows 3) | Wait and re-run `make demo-reset`, which is idempotent. Free a search-index slot if needed. |
| `Demo scenario not loaded (…): run make demo-reset` | Seed missing or changed | `make demo-reset` |
| `Demo 1 needs the pristine scenario …` | Demo 3 or 4 already ran | `make demo-reset`, then restart terminal A |
| `DEMO 3 MISMATCH: top memory mem_inv_…` | Demo 5 already ran, so the confirmed case is now the closest VERIFIED memory (expected) | `make demo-reset` |
| Confirm returns `403` | The key is not admin, or it initiated the case (`INV_NO_SELF_APPROVAL`) | Use `KYA_BOOTSTRAP_ADMIN_API_KEY` |
| Confirm returns `409 INVALID_STATE` | Case already confirmed | Use a fresh Demo 3 case after `make demo-reset` |
| Investigation BLOCK `IDENTITY_DENIED` with `TIMESTAMP_OUT_OF_WINDOW` / `NONCE_REPLAYED` | Signed request is stale or was re-posted | Re-run the sign-and-post one-liner |
| `sanctions:apply` prints `already applied`, and nothing happens | Update applied in an earlier run | `make demo-reset`, restart terminal A, and re-run Demos in order |
| Passport stays `ACTIVE` after `sanctions:apply` | Watcher not running (for example, the server is `make demo`) | Use `npm start` and wait for `sanctions watcher started` |
| Dashboard `Your API key was rejected` | The server was restarted with a different pepper, or the key was a `make demo` key deleted by a later `make demo` | Keep `KYA_API_KEY_PEPPER` fixed in `.env`, and sign in with `KYA_BOOTSTRAP_ADMIN_API_KEY` |
| `Could not listen on …` / `EADDRINUSE` | Port 8080 busy | `PORT=8081 npm start` (and adjust the URLs) |

## 7. Rehearsal timings (observed, single run, 2026-09-28)

| Step | Observed |
|---|---|
| `make demo-reset` (indexes already existed) | about 9 s |
| `make demo CHECK=1 DEMO=1` / `2` / `3` | about 2.8 s / 2.7 s / 2.6 s (script-reported `elapsed`) |
| `npm start` until `sanctions watcher started` | about 3 s |
| Demo 5: confirm, list versions and events, next case | about 4 s |
| Demo 4: `sanctions:apply` to passport `SUSPENDED` | about 2.1 s between the change event and suspension (about 4 s including the script start) |

These are wall-clock observations from one rehearsal. They are not benchmarks, and they depend
on cluster tier, region and network.
