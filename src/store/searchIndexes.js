// Atlas Search / Vector Search index management (search-indexes.json, T03).
// Definitions are passed verbatim to createSearchIndex(); the function then polls
// listSearchIndexes(name) until every index is queryable. These indexes exist only
// on Atlas (or mongodb-atlas-local) — there is no in-memory emulation.
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const CONTRACT_PATH = resolve(dirname(fileURLToPath(import.meta.url)), '../../docs/contracts/search-indexes.json');

/** The binding index definitions ({ collection, name, type, definition }[]). */
export function loadSearchIndexDefs(path = CONTRACT_PATH) {
  const { indexes } = JSON.parse(readFileSync(path, 'utf8'));
  return indexes.map(({ collection, name, type, definition }) => ({ collection, name, type, definition }));
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const NAMESPACE_EXISTS = 48;

async function findIndex(coll, name) {
  const [ix] = await coll.listSearchIndexes(name).toArray();
  return ix ?? null;
}

/**
 * Create any missing search indexes from `defs` and wait until all are queryable.
 * Existing indexes with the same name are left as-is (idempotent).
 * Resolves to [{ collection, name, type, status, queryable, created }]; rejects on
 * a FAILED index or when `timeoutMs` elapses.
 */
export async function ensureSearchIndexes(
  db,
  defs = loadSearchIndexDefs(),
  { timeoutMs = 120_000, intervalMs = 2_000, now = () => Date.now() } = {},
) {
  const created = new Set();
  for (const d of defs) {
    // createSearchIndex requires an existing collection.
    try {
      await db.createCollection(d.collection);
    } catch (err) {
      if (!(err && (err.code === NAMESPACE_EXISTS || err.codeName === 'NamespaceExists'))) throw err;
    }
    const coll = db.collection(d.collection);
    if (!(await findIndex(coll, d.name))) {
      await coll.createSearchIndex({ name: d.name, type: d.type, definition: d.definition });
      created.add(d.name);
    }
  }

  const deadline = now() + timeoutMs;
  const results = new Map();
  for (;;) {
    for (const d of defs) {
      if (results.get(d.name)?.queryable) continue;
      const ix = await findIndex(db.collection(d.collection), d.name);
      if (ix?.status === 'FAILED') {
        throw new Error(`search index ${d.collection}.${d.name} FAILED: ${ix.message ?? 'no message'}`);
      }
      results.set(d.name, {
        collection: d.collection,
        name: d.name,
        type: d.type,
        status: ix?.status ?? 'MISSING',
        queryable: ix?.queryable === true,
        created: created.has(d.name),
      });
    }
    const pending = defs.filter((d) => !results.get(d.name).queryable);
    if (pending.length === 0) return defs.map((d) => results.get(d.name));
    if (now() >= deadline) {
      const s = pending.map((d) => `${d.collection}.${d.name}=${results.get(d.name).status}`).join(', ');
      throw new Error(`search indexes not queryable after ${timeoutMs} ms: ${s}`);
    }
    await sleep(intervalMs);
  }
}
