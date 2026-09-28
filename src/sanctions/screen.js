// Sanctions stage screening (investigation-pipeline.md §4 stage 3, DELIVERY_PLAN T09).
//
// (a) Exact wallet screen — the INV_SANCTIONS_EXACT_BLOCK invariant. A plain B-tree `find`:
//
//   sanctions.find({ 'wallets.address': { $in: [agentWallet, counterparty, …] } })
//
//     Any hit ⇒ BLOCK SANCTIONS_EXACT_MATCH. Deterministic: it never depends on `$search`, on
//     scores, or on the fuzzy threshold, and it is decided before the fuzzy query runs.
// (b) Fuzzy / alias / phonetic name screen — Atlas Search over the `sanctions_search` index:
//
//   $search { index: 'sanctions_search', compound: { should: [
//               text { query: name, path: ['name','aliases'], fuzzy: { maxEdits: 2 } },
//               text { query: name, path: [{ value:'name', multi:'phonetic' }, { value:'aliases', multi:'phonetic' }] } ],
//             minimumShouldMatch: 1 } }
//             highlight { path: ['name','aliases'] }
//   $limit 5 ; $project { name, aliases, programs, datasetVersion, score: { $meta: 'searchScore' },
//                         highlights: { $meta: 'searchHighlights' } }
//
//     Fuzzy hits are evidence. They add REVIEW SANCTIONS_FUZZY_MATCH only when the active policy
//     sets `sanctionsFuzzy.minScorePpm` (searchScore is unbounded BM25, so no threshold is assumed).
// There is no in-memory `$search`: without a driver Db the fuzzy screen throws AtlasRequiredError,
// and an empty result from a missing / non-queryable index is an error, not a clean result.
import { holds } from '../harness/invariants.js';
import { AtlasRequiredError } from '../store/memory.js';

export const SANCTIONS_COLLECTION = 'sanctions';
export const SANCTIONS_INDEX = 'sanctions_search';
export const FUZZY_DEFAULTS = Object.freeze({ limit: 5, maxEdits: 2 });

export class SanctionsScreenError extends Error {
  constructor(message, code = 'SANCTIONS_SCREEN_FAILED') {
    super(message);
    this.name = 'SanctionsScreenError';
    this.code = code;
  }
}

const PPM = 1_000_000;
const toPpm = (score) => Math.round(score * PPM);
const norm = (a) => (typeof a === 'string' && a.trim() ? a.trim().toLowerCase() : null);
const idOf = (d) => d?.id ?? d?._id ?? null;

/** The exact aggregation run against `sanctions` for one name (exported for tests and evidence). */
export function fuzzySearchPipeline(query, { limit = FUZZY_DEFAULTS.limit, maxEdits = FUZZY_DEFAULTS.maxEdits } = {}) {
  return [
    {
      $search: {
        index: SANCTIONS_INDEX,
        compound: {
          should: [
            { text: { query, path: ['name', 'aliases'], fuzzy: { maxEdits } } },
            { text: { query, path: [{ value: 'name', multi: 'phonetic' }, { value: 'aliases', multi: 'phonetic' }] } },
          ],
          minimumShouldMatch: 1,
        },
        highlight: { path: ['name', 'aliases'] },
      },
    },
    { $limit: limit },
    { $project: { _id: 1, name: 1, aliases: 1, type: 1, programs: 1, datasetVersion: 1, score: { $meta: 'searchScore' }, highlights: { $meta: 'searchHighlights' } } },
  ];
}

/** Current dataset version = max `datasetVersion` in `sanctions` (null when empty). */
export async function currentDatasetVersion(store) {
  if (store.db) {
    const [d] = await store.db.collection(SANCTIONS_COLLECTION).find({}, { projection: { datasetVersion: 1 } }).sort({ datasetVersion: -1 }).limit(1).toArray();
    return d?.datasetVersion ?? null;
  }
  const all = await store.sanctions.find();
  return all.reduce((max, s) => (s.datasetVersion && (!max || s.datasetVersion > max) ? s.datasetVersion : max), null);
}

/**
 * Exact wallet screen (INV_SANCTIONS_EXACT_BLOCK). `addresses` are compared lowercased.
 * Returns `{ held, exactHits: [{ sanctionsId, address, name, programs, datasetVersion }] }`.
 */
export async function exactScreen(store, addresses) {
  const wanted = [...new Set(addresses.map(norm).filter(Boolean))];
  let docs = [];
  if (wanted.length) {
    if (store.db) {
      docs = await store.db
        .collection(SANCTIONS_COLLECTION)
        .find({ 'wallets.address': { $in: wanted } }, { projection: { name: 1, programs: 1, wallets: 1, datasetVersion: 1 } })
        .sort({ _id: 1 })
        .toArray();
    } else {
      // MemoryStore CRUD double (unit tests): same predicate via the repository lookup.
      const byId = new Map();
      for (const a of wanted) for (const d of await store.sanctions.findByWallet(a)) byId.set(idOf(d), d);
      docs = [...byId.values()].sort((x, y) => String(idOf(x)).localeCompare(String(idOf(y))));
    }
  }
  const exactHits = [];
  const sanctionedAddresses = [];
  for (const d of docs) {
    for (const w of d.wallets ?? []) {
      const a = norm(w.address);
      if (!a) continue;
      sanctionedAddresses.push(a);
      if (wanted.includes(a)) {
        exactHits.push({ sanctionsId: idOf(d), address: a, name: d.name, programs: [...(d.programs ?? [])], datasetVersion: d.datasetVersion ?? null });
      }
    }
  }
  const held = holds('INV_SANCTIONS_EXACT_BLOCK', { addresses: wanted, sanctionedAddresses });
  // Fail closed: the invariant and the hit list must agree.
  if (held === exactHits.length > 0) throw new SanctionsScreenError('exact sanctions screen is inconsistent', 'INCONSISTENT_EXACT_SCREEN');
  return { held, exactHits };
}

async function assertIndexQueryable(coll) {
  const [ix] = await coll.listSearchIndexes(SANCTIONS_INDEX).toArray();
  if (!ix) throw new SanctionsScreenError(`search index ${SANCTIONS_COLLECTION}.${SANCTIONS_INDEX} is missing`, 'INDEX_NOT_READY');
  if (ix.queryable !== true) {
    throw new SanctionsScreenError(`search index ${SANCTIONS_COLLECTION}.${SANCTIONS_INDEX} is not queryable (${ix.status})`, 'INDEX_NOT_READY');
  }
}

// The listed name or alias that matched: the best-scoring highlighted value, else the primary name.
function matchedValue(d) {
  const values = [d.name, ...(d.aliases ?? [])].filter((v) => typeof v === 'string');
  const best = [...(d.highlights ?? [])]
    .filter((h) => h.texts?.some((t) => t.type === 'hit'))
    .sort((a, b) => (b.score ?? 0) - (a.score ?? 0))[0];
  if (best) {
    const text = best.texts.map((t) => t.value).join('');
    const exact = values.find((v) => v === text) ?? values.find((v) => v.includes(text) || text.includes(v));
    if (exact) return exact;
  }
  return d.name;
}

/**
 * Fuzzy / alias / phonetic name screen via Atlas `$search`. Returns the top `limit` hits, each
 * `{ sanctionsId, name, aliases, programs, datasetVersion, query, matched, score, scorePpm }`.
 */
export async function fuzzyScreen(db, name, { limit = FUZZY_DEFAULTS.limit } = {}) {
  if (!db) throw new AtlasRequiredError('$search');
  if (typeof name !== 'string' || !name.trim()) throw new SanctionsScreenError('name must be a non-empty string', 'INVALID_INPUT');
  const coll = db.collection(SANCTIONS_COLLECTION);
  const raw = await coll.aggregate(fuzzySearchPipeline(name.trim(), { limit })).toArray();
  if (raw.length === 0) await assertIndexQueryable(coll);
  return raw.map((d) => {
    if (typeof d.score !== 'number' || !Number.isFinite(d.score)) throw new SanctionsScreenError(`searchScore missing for ${d._id}`, 'INVALID_SCORE');
    return {
      sanctionsId: d._id,
      name: d.name,
      aliases: [...(d.aliases ?? [])],
      programs: [...(d.programs ?? [])],
      datasetVersion: d.datasetVersion ?? null,
      query: name.trim(),
      matched: matchedValue(d),
      score: d.score,
      scorePpm: toPpm(d.score),
    };
  });
}

/**
 * Run the whole sanctions stage for one payment.
 * `screened` = [{ role: 'wallet'|'counterparty', address, name? }]; fuzzy names are screened
 * only where a name is present (the signed `counterpartyName`).
 * `fuzzy` = policy.sanctionsFuzzy ({ minScorePpm, limit }) or undefined (evidence only).
 * Returns `{ result, evidence, exactHit, fuzzyFlagged }` in the investigation-pipeline.md shape.
 */
export async function screenSanctions({ store, screened, fuzzy }) {
  const limit = fuzzy?.limit ?? FUZZY_DEFAULTS.limit;
  const minScorePpm = fuzzy?.minScorePpm ?? null;
  const addresses = screened.map((s) => s.address).filter((a) => a != null);

  const { held, exactHits } = await exactScreen(store, addresses);
  const datasetVersion = await currentDatasetVersion(store);

  const evidence = [
    {
      id: 'invariant:INV_SANCTIONS_EXACT_BLOCK',
      kind: 'invariant',
      source: 'harness/invariants',
      ref: 'INV_SANCTIONS_EXACT_BLOCK',
      summary: `held: ${held}`,
      data: { held, screenedAddresses: addresses.map(norm).filter(Boolean) },
    },
    ...exactHits.map((h) => ({
      id: `sanctions:${h.sanctionsId}:${h.address}`,
      kind: 'sanctions_exact',
      source: SANCTIONS_COLLECTION,
      ref: h.sanctionsId,
      summary: `exact wallet match ${h.address} listed for "${h.name}" (${h.programs.join(', ') || 'no program'})`,
      data: { ...h },
    })),
  ];

  const result = {
    datasetVersion,
    screened: screened.map((s) => ({ role: s.role, address: norm(s.address), name: s.name ?? null })),
    exactHits,
    fuzzyHits: [],
    fuzzy: { engine: '$search', index: SANCTIONS_INDEX, limit, minScorePpm, queried: [] },
  };

  // Exact decision is final here; the fuzzy screen below only adds evidence. If it throws, the
  // caller still receives the exact outcome through `err.stagePartial`.
  try {
    for (const s of screened) {
      if (typeof s.name !== 'string' || !s.name.trim()) continue;
      result.fuzzy.queried.push(s.role);
      for (const h of await fuzzyScreen(store.db, s.name, { limit })) {
        // Integers only (scores as *Ppm): stage results feed the hashed receipt.
        const fuzzyHit = { role: s.role, sanctionsId: h.sanctionsId, name: h.name, query: h.query, matched: h.matched, scorePpm: h.scorePpm, datasetVersion: h.datasetVersion };
        result.fuzzyHits.push(fuzzyHit);
        evidence.push({
          id: `sanctions_fuzzy:${s.role}:${h.sanctionsId}`,
          kind: 'sanctions_fuzzy',
          source: SANCTIONS_COLLECTION,
          ref: h.sanctionsId,
          summary: `${s.role} name "${h.query}" ~ "${h.matched}" of "${h.name}" (searchScore ${h.scorePpm} ppm, dataset ${h.datasetVersion})`,
          data: { role: s.role, sanctionsId: h.sanctionsId, name: h.name, query: h.query, matched: h.matched, scorePpm: h.scorePpm, datasetVersion: h.datasetVersion, programs: h.programs },
        });
      }
    }
  } catch (err) {
    err.stagePartial = { result, evidence, exactHit: !held };
    throw err;
  }

  const fuzzyFlagged = minScorePpm != null ? result.fuzzyHits.filter((h) => h.scorePpm >= minScorePpm) : [];
  return { result, evidence, exactHit: !held, fuzzyFlagged };
}
