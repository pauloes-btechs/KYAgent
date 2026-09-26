// Memory stage retrieval (investigation-pipeline.md §4 stage 5, DELIVERY_PLAN T07).
// Atlas Vector Search over `security_memories` with the `memory_vector` index:
//
//   $vectorSearch { index: 'memory_vector', path: 'embedding', queryVector: embed(signalsText(signals)),
//                   numCandidates, limit: k, filter: { status: 'VERIFIED' } }
//   $project      { score: { $meta: 'vectorSearchScore' }, … }
//
// Then two post-filters, each counted in the result:
// - any non-VERIFIED hit is dropped (second enforcement of INV_UNVERIFIED_MEMORY_NOT_PRECEDENT;
//   the `filter` above is the first);
// - any hit with score < minScore is dropped (irrelevant memory is never context, never precedent).
// There is no in-memory emulation: without a driver Db this throws AtlasRequiredError, and an
// empty result from a missing / non-queryable index is an error, not a clean result.
import { holds } from '../harness/invariants.js';
import { AtlasRequiredError } from '../store/memory.js';
import { embedWithMeta } from './embeddings.js';
import { normalizeSignals, signalsText } from './signalsText.js';

export const MEMORY_INDEX = 'memory_vector';
export const MEMORY_COLLECTION = 'security_memories';
export const MEMORY_DEFAULTS = Object.freeze({ k: 3, numCandidates: 100, minScorePpm: 780_000 });

export class MemoryRetrievalError extends Error {
  constructor(message, code = 'MEMORY_RETRIEVAL_FAILED') {
    super(message);
    this.name = 'MemoryRetrievalError';
    this.code = code;
  }
}

const PPM = 1_000_000;
export const toPpm = (score) => Math.round(score * PPM);

function resolveOptions(opts) {
  const k = opts.k ?? MEMORY_DEFAULTS.k;
  const numCandidates = opts.numCandidates ?? MEMORY_DEFAULTS.numCandidates;
  // `minScore` (float, 0..1) or `minScorePpm` (integer, as stored in harness_versions.policy).
  const minScorePpm = opts.minScore !== undefined ? toPpm(opts.minScore) : opts.minScorePpm ?? MEMORY_DEFAULTS.minScorePpm;
  if (!Number.isSafeInteger(k) || k < 1) throw new MemoryRetrievalError('k must be a positive integer', 'INVALID_INPUT');
  if (!Number.isSafeInteger(numCandidates) || numCandidates < k) {
    throw new MemoryRetrievalError('numCandidates must be an integer >= k', 'INVALID_INPUT');
  }
  if (!Number.isSafeInteger(minScorePpm) || minScorePpm < 0 || minScorePpm > PPM) {
    throw new MemoryRetrievalError('minScore must be within [0, 1]', 'INVALID_INPUT');
  }
  return { k, numCandidates, minScorePpm };
}

/** The exact aggregation run against `security_memories` (exported for tests and evidence). */
export function vectorSearchPipeline(queryVector, { k, numCandidates }) {
  return [
    {
      $vectorSearch: {
        index: MEMORY_INDEX,
        path: 'embedding',
        queryVector,
        numCandidates,
        limit: k,
        filter: { status: 'VERIFIED' },
      },
    },
    {
      $project: {
        _id: 1,
        title: 1,
        status: 1,
        outcome: 1,
        signals: 1,
        recommendedSteps: 1,
        sourceInvestigationId: 1,
        score: { $meta: 'vectorSearchScore' },
      },
    },
  ];
}

async function assertIndexQueryable(coll) {
  const [ix] = await coll.listSearchIndexes(MEMORY_INDEX).toArray();
  if (!ix) throw new MemoryRetrievalError(`search index ${MEMORY_COLLECTION}.${MEMORY_INDEX} is missing`, 'INDEX_NOT_READY');
  if (ix.queryable !== true) {
    throw new MemoryRetrievalError(`search index ${MEMORY_COLLECTION}.${MEMORY_INDEX} is not queryable (${ix.status})`, 'INDEX_NOT_READY');
  }
}

/**
 * Retrieve VERIFIED security memories similar to a signal set.
 * `db` is the driver Db (`store.db`); options: `k`, `numCandidates`, `minScore` | `minScorePpm`,
 * `embed` (options passed to embedWithMeta, e.g. `env`).
 * Returns the memory stage `result` shape plus `evidence` (investigation-pipeline.md §3–4).
 */
export async function retrieveMemories({ db, signals, ...opts }) {
  if (!db) throw new AtlasRequiredError('$vectorSearch');
  const { k, numCandidates, minScorePpm } = resolveOptions(opts);
  const set = normalizeSignals(signals);
  const text = signalsText(set);
  const { embedding, embeddingModel, embeddingTextSha256 } = await embedWithMeta(text, opts.embed);

  const coll = db.collection(MEMORY_COLLECTION);
  const raw = await coll.aggregate(vectorSearchPipeline(embedding, { k, numCandidates })).toArray();
  if (raw.length === 0) await assertIndexQueryable(coll);

  let droppedUnverified = 0;
  let droppedBelowScore = 0;
  const hits = [];
  for (const d of raw) {
    if (!holds('INV_UNVERIFIED_MEMORY_NOT_PRECEDENT', { memory: d })) {
      droppedUnverified += 1;
      continue;
    }
    if (typeof d.score !== 'number' || !Number.isFinite(d.score)) {
      throw new MemoryRetrievalError(`vectorSearchScore missing for ${d._id}`, 'INVALID_SCORE');
    }
    const scorePpm = toPpm(d.score);
    if (scorePpm < minScorePpm) {
      droppedBelowScore += 1;
      continue;
    }
    hits.push({
      memoryId: d._id,
      title: d.title,
      status: d.status,
      outcome: d.outcome ?? null,
      score: d.score,
      scorePpm,
      signals: Array.isArray(d.signals) ? [...d.signals] : [],
      recommendedSteps: Array.isArray(d.recommendedSteps) ? [...d.recommendedSteps] : [],
    });
  }

  const evidence = hits.map((h, i) => ({
    id: `memory:${h.memoryId}`,
    kind: 'memory',
    source: MEMORY_COLLECTION,
    ref: h.memoryId,
    summary: `rank ${i + 1}: ${h.status} ${h.outcome ?? 'no outcome'} precedent "${h.title}" (score ${h.scorePpm} ppm >= ${minScorePpm})`,
    data: { rank: i + 1, memoryId: h.memoryId, status: h.status, outcome: h.outcome, scorePpm: h.scorePpm, signals: h.signals },
  }));

  return {
    engine: '$vectorSearch',
    index: MEMORY_INDEX,
    querySignals: set,
    queryTextSha256: embeddingTextSha256,
    embeddingModel,
    k,
    numCandidates,
    minScorePpm,
    hits,
    droppedBelowScore,
    droppedUnverified,
    evidence,
  };
}
