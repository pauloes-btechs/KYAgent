# KYAgentGate — Codebase Map

Zero-framework Node.js HTTP API (`src/`), static dashboard (`dashboard/`), MongoDB storage
with in-memory fallback, built-in `node --test` suites (`test/`).

| Path | Contents |
|---|---|
| `src/` | App entry and wiring: `server.js` (listen), `app.js` (router, auth, routes), `config.js`, `errors.js`, `logger.js`, `events.js`, `ids.js`, `rateLimit.js`, `validate.js`, `contracts.js`, `seed.js` |
| `src/crypto/` | Ed25519 signing, JWS credentials, API-key hashing/pepper |
| `src/investigation/` | Seven-stage investigation pipeline (identity → delegation → sanctions → signals → memory → policy → decision) |
| `src/harness/` | Versioned harness policies, invariants, adaptation loop |
| `src/memory/` | Vector memory (embeddings, similarity recall of VERIFIED precedent) |
| `src/sanctions/` | Mock/fixture sanctions screening, list updates |
| `src/services/` | Domain services behind the routes (businesses, operators, agents, grants, credentials, apiKeys, audit, trust, verification) |
| `src/store/` | `memory.js` (in-memory store) and `mongo.js` (MongoDB store), storage interface |
| `src/sdk/` | Client SDK used by `examples/sdk-quickstart.js` |
| `src/watchers/` | Sanctions change-stream watcher (Mongo only) |
| `dashboard/` | Static operator console: `index.html`, `app.js`, `investigations.js`, `trust.js`, `styles.css` |
| `scripts/` | CLI utilities: `migrate.js`, `seed.js`, `demo*.js`, `init-env.js`, key generators, `apply-sanctions-update.js` |
| `test/` | Built-in test suites (269 tests) incl. `test/atlas/` (needs Atlas) and `test/vectors/` |
| `docs/` | Contracts (`openapi.yaml`, per-domain contract docs), guides, demo runbook, live console page |
| `fixtures/` | Embeddings, memories, sanctions, transaction fixtures |
| `examples/` | `sdk-quickstart.js` SDK walkthrough |
