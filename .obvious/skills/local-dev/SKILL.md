---
name: local-dev
---

# local-dev — running KYAgentGate locally

## Environment (as onboarded 2026-10-30)

- Node.js 20.20.2, npm 10.8.2. Docker **not installed** in the sandbox — the compose stack
  (mongo:7 + migrate + api) cannot be started here; the documented Docker path applies only
  to machines with Docker.
- Dependencies are preinstalled in `node_modules/` (root-owned; `npm ci` fails with EACCES —
  do not reinstall, the existing tree satisfies `package.json`).
- `npm run env:init` generates `.env` (git-ignored, 0600) with `KYA_SIGNING_PRIVATE_KEY`,
  `KYA_API_KEY_PEPPER`, `KYA_BOOTSTRAP_ADMIN_API_KEY`. Leave `MONGODB_URI` empty for the
  in-memory store.

## Canonical start

```bash
node --env-file=.env src/server.js   # port 8080, store=memory
# or: npm run dev                    # same but ephemeral keys (.env NOT loaded by Node 20)
```

If you see `EADDRINUSE: 8080`, find and kill the stray `node src/server.js` child
(`ss -tlnp | grep 8080`), then restart.

## Verification checklist (proven on 2026-10-30)

1. `curl http://127.0.0.1:8080/healthz` → `{"status":"ok","store":"memory"}`.
2. `ADMIN=$(grep '^KYA_BOOTSTRAP_ADMIN_API_KEY=' .env | cut -d= -f2)`
3. `curl -X POST http://127.0.0.1:8080/v1/businesses -H "Authorization: Bearer $ADMIN" \
     -H 'Content-Type: application/json' -d '{"name":"Northwind"}'` → 201 `biz_…`
4. `curl -X POST http://127.0.0.1:8080/v1/operators -H "Authorization: Bearer $ADMIN" \
     -H 'Content-Type: application/json' -d '{"type":"organization","legalName":"Acme Ops Ltd","contactEmail":"ops@acme.example","country":"GB"}'` → 201 `op_…`
5. `curl http://127.0.0.1:8080/v1/audit-events/integrity -H "Authorization: Bearer $ADMIN"`
   → `{"valid":true,…}` (hash-chained audit log intact).
6. `npm test` → 265 pass / 1 known failure (`docs.test.js`: missing
   `docs/explainer/index.html`, pre-existing) / 3 skipped.
7. `curl -o /dev/null -w '%{http_code}' http://127.0.0.1:8080/dashboard/` → 200.

## Full-stack mode (Docker available only)

`npm run env:init && docker compose up --build -d` — mongo, one-shot migrate, API on
`127.0.0.1:8080`; optional `docker compose --profile seed run --rm seed` for demo data.
`make demo-reset` / `make demo CHECK=1` require a MongoDB Atlas cluster with Atlas Search
and Vector Search (see `docs/DEMO.md`); they never fall back to the in-memory store.
