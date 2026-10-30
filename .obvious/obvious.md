# KYAgentGate — obvious.md

**Repo:** `pauloes-btechs/KYAgentGate` (KYAgent — Know-Your-Agent: identity verification,
authorization and continuous risk screening for autonomous AI agents).
**Snapshot:** `0gnc9smgsg07pyc205vk:default` (captured 2026-10-30T15:31:42.930Z).
`dev_stack_healthy: true` — API verified end-to-end in memory-store mode.

## Stack

- Node.js >= 20 (no framework — plain `node:http`), ESM (`"type": "module"`).
- Data layer: MongoDB via the official `mongodb` driver. **In-memory store** when
  `MONGODB_URI` is unset (dev/test only; no persistence, no change streams).
- Static dashboard served by the API at `/dashboard/`.
- Package manager: npm (`package-lock.json`; a stray untracked `bun.lock` exists — ignore it).
- Test runner: `node --test` (built-in; no Jest/Mocha).

## Commands

| Purpose | Command |
|---|---|
| Install deps | `npm install` (deps preinstalled in snapshot) |
| Start API (in-memory, no .env) | `npm run dev` — ephemeral signing key/pepper, memory store |
| Start API (with .env secrets) | `node --env-file=.env src/server.js` |
| Generate .env + secrets | `npm run env:init` (writes git-ignored `.env`, mode 0600) |
| Tests | `npm test` (local/memory); `npm run test:atlas` (needs Atlas) |
| Full local stack | `docker compose up --build -d` (mongo:7 + migrate + api on 127.0.0.1:8080) |
| Atlas demo scenario | `make demo-reset`, `make demo CHECK=1` |

## Local dev (this sandbox)

Docker is **not available** in the sandbox, so the canonical run is in-memory mode:

1. `npm run env:init` — generates `KYA_SIGNING_PRIVATE_KEY`, `KYA_API_KEY_PEPPER`,
   `KYA_BOOTSTRAP_ADMIN_API_KEY` into `.env`.
2. `node --env-file=.env src/server.js` — listens on **port 8080** (from `PORT` in `.env`),
   `store: "memory"`, sanctions in `mock` mode, embeddings in `fixture` mode.
3. Health: `curl http://127.0.0.1:8080/healthz` → `{"status":"ok","store":"memory"}`.
4. Dashboard: `http://127.0.0.1:8080/dashboard/` (HTTP 200).
5. Auth: `Authorization: Bearer $KYA_BOOTSTRAP_ADMIN_API_KEY` for admin endpoints.

`npm run dev` does **not** load `.env` (Node 20 needs `--env-file`) and falls back to
ephemeral keys — fine for smoke tests, but the bootstrap admin key in `.env` only works
with the `--env-file` invocation.

## Env vars

See `.env.example` and `docs/contracts/environment.md`. Key ones: `PORT` (8080),
`HOST`, `NODE_ENV`, `MONGODB_URI`/`MONGODB_DB` (leave `MONGODB_URI` empty for memory store),
`KYA_SIGNING_PRIVATE_KEY`, `KYA_API_KEY_PEPPER`, `KYA_BOOTSTRAP_ADMIN_API_KEY`,
`SANCTIONS_MODE=mock`, `EMBEDDINGS_MODE=fixture`. `VOYAGE_API_KEY` only for live embeddings.

## Codebase map

See [codebase-map.md](codebase-map.md).

## Local verification

1. `npm test` — 269 tests: 265 pass, 1 known pre-existing failure
   (`test/docs.test.js`: README links to missing `docs/explainer/index.html`), 3 skipped.
2. `curl http://127.0.0.1:8080/healthz` → 200 `{"status":"ok","store":"memory"}`.
3. Primary flow (API, verified 2026-10-30):
   - `POST /v1/businesses` with bootstrap admin key → 201 `biz_…`
   - `POST /v1/operators` → 201 `op_…`
   - `GET /v1/audit-events/integrity` → `{"valid":true,"count":2,…}`
   - `GET /dashboard/` → 200
4. Known limitation: Docker/Compose unavailable in sandbox — full mongo+migrate+api stack
   not exercised locally; documented in `skills/local-dev/SKILL.md`.

## Gotchas

- `MONGODB_URI` unset ⇒ memory store: data lost on restart, sanctions watcher disabled
  (no change streams), Atlas-only features (`make demo*`, `test:atlas`) cannot run.
- Server binds all interfaces in dev (`HOST=0.0.0.0`); compose build pins the API to
  `127.0.0.1:8080`.
- If port 8080 is already in use (`EADDRINUSE`), kill the previous `node src/server.js`
  child process — killing the `npm run dev` wrapper does not kill it.
