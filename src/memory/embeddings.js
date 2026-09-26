import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { textSha256 } from './signalsText.js';

/**
 * Embeddings adapter (DELIVERY_PLAN T05).
 * - EMBEDDINGS_MODE=live: Voyage `voyage-3.5-lite` (VOYAGE_API_KEY), output_dimension = index dims.
 * - EMBEDDINGS_MODE=fixture (default, offline): lookup by sha256(text) in fixtures/embeddings.json.
 *   Unknown text throws; there is never a silent zero/random vector.
 * Every vector is asserted to have exactly the `memory_vector` index numDimensions.
 */
export const LIVE_MODEL = 'voyage-3.5-lite';
export const VOYAGE_URL = 'https://api.voyageai.com/v1/embeddings';
export const EMBEDDINGS_MODES = Object.freeze(['fixture', 'live']);

const SEARCH_INDEXES_PATH = fileURLToPath(new URL('../../docs/contracts/search-indexes.json', import.meta.url));
export const DEFAULT_FIXTURE_PATH = fileURLToPath(new URL('../../fixtures/embeddings.json', import.meta.url));

export class EmbeddingError extends Error {
  constructor(message, code = 'EMBEDDING_FAILED') {
    super(message);
    this.name = 'EmbeddingError';
    this.code = code;
  }
}

/** numDimensions of the `memory_vector` index (docs/contracts/search-indexes.json). */
export function indexNumDimensions(path = SEARCH_INDEXES_PATH) {
  const doc = JSON.parse(readFileSync(path, 'utf8'));
  const idx = (doc.indexes ?? []).find((i) => i.name === 'memory_vector');
  const field = idx?.definition?.fields?.find((f) => f.type === 'vector' && f.path === 'embedding');
  if (!Number.isSafeInteger(field?.numDimensions) || field.numDimensions <= 0) {
    throw new EmbeddingError('memory_vector numDimensions not found in search-indexes.json', 'INDEX_CONTRACT');
  }
  return field.numDimensions;
}

export const EMBEDDING_DIMENSIONS = indexNumDimensions();

export function embeddingsMode(env = process.env) {
  const mode = env.EMBEDDINGS_MODE || 'fixture';
  if (!EMBEDDINGS_MODES.includes(mode)) {
    throw new EmbeddingError(`EMBEDDINGS_MODE must be one of ${EMBEDDINGS_MODES.join('|')}`, 'CONFIG');
  }
  return mode;
}

export function assertEmbedding(vector, dims = EMBEDDING_DIMENSIONS) {
  if (!Array.isArray(vector)) throw new EmbeddingError('embedding is not an array', 'INVALID_VECTOR');
  if (vector.length !== dims) {
    throw new EmbeddingError(`embedding has ${vector.length} dimensions, index requires ${dims}`, 'DIMENSION_MISMATCH');
  }
  let nonZero = false;
  for (const x of vector) {
    if (typeof x !== 'number' || !Number.isFinite(x)) throw new EmbeddingError('embedding has a non-finite component', 'INVALID_VECTOR');
    if (x !== 0) nonZero = true;
  }
  if (!nonZero) throw new EmbeddingError('embedding is a zero vector', 'INVALID_VECTOR');
  return vector;
}

const fixtureCache = new Map();
export function loadFixture(path = DEFAULT_FIXTURE_PATH) {
  if (fixtureCache.has(path)) return fixtureCache.get(path);
  const doc = JSON.parse(readFileSync(path, 'utf8'));
  if (doc.dimensions !== EMBEDDING_DIMENSIONS) {
    throw new EmbeddingError(`fixture dimensions ${doc.dimensions} != index ${EMBEDDING_DIMENSIONS}`, 'DIMENSION_MISMATCH');
  }
  if (typeof doc.model !== 'string' || !doc.vectors || typeof doc.vectors !== 'object') {
    throw new EmbeddingError('malformed embeddings fixture', 'FIXTURE');
  }
  fixtureCache.set(path, doc);
  return doc;
}

function embedFixture(text, sha, fixturePath) {
  const doc = loadFixture(fixturePath);
  const entry = Object.hasOwn(doc.vectors, sha) ? doc.vectors[sha] : null;
  if (!entry) throw new EmbeddingError(`no fixture embedding for text sha256 ${sha}`, 'FIXTURE_UNKNOWN_TEXT');
  if (entry.text !== text) throw new EmbeddingError(`fixture text mismatch for sha256 ${sha}`, 'FIXTURE');
  return { embedding: assertEmbedding([...entry.embedding]), embeddingModel: doc.model };
}

async function embedLive(text, { env, fetchImpl, inputType, timeoutMs }) {
  const apiKey = env.VOYAGE_API_KEY;
  if (!apiKey) throw new EmbeddingError('EMBEDDINGS_MODE=live requires VOYAGE_API_KEY', 'CONFIG');
  if (typeof fetchImpl !== 'function') throw new EmbeddingError('fetch is not available', 'CONFIG');
  const body = { input: [text], model: LIVE_MODEL, output_dimension: EMBEDDING_DIMENSIONS };
  if (inputType) body.input_type = inputType;
  let res;
  try {
    res = await fetchImpl(VOYAGE_URL, {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${apiKey}` },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(timeoutMs),
    });
  } catch (err) {
    throw new EmbeddingError(`Voyage request failed: ${err?.name ?? 'Error'}`, 'PROVIDER');
  }
  if (!res.ok) throw new EmbeddingError(`Voyage returned HTTP ${res.status}`, 'PROVIDER');
  let json;
  try {
    json = await res.json();
  } catch {
    throw new EmbeddingError('Voyage returned a non-JSON body', 'PROVIDER');
  }
  const vector = json?.data?.[0]?.embedding;
  return { embedding: assertEmbedding(vector), embeddingModel: typeof json?.model === 'string' ? json.model : LIVE_MODEL };
}

/**
 * Embed `text`, returning `{ embedding, embeddingModel, embeddingTextSha256, mode }`.
 * Options: `env` (default process.env), `fetchImpl` (default global fetch), `inputType`
 * ('query'|'document'; omitted by default so stored memories and queries share one space),
 * `fixturePath`, `timeoutMs`.
 */
export async function embedWithMeta(text, options = {}) {
  const { env = process.env, fetchImpl = globalThis.fetch, inputType, fixturePath = DEFAULT_FIXTURE_PATH, timeoutMs = 10_000 } = options;
  if (typeof text !== 'string' || text.length === 0) throw new EmbeddingError('text must be a non-empty string', 'INVALID_INPUT');
  const mode = embeddingsMode(env);
  const embeddingTextSha256 = textSha256(text);
  const out = mode === 'live'
    ? await embedLive(text, { env, fetchImpl, inputType, timeoutMs })
    : embedFixture(text, embeddingTextSha256, fixturePath);
  return { ...out, embeddingTextSha256, mode };
}

/** Embed `text` and return the vector only (length === EMBEDDING_DIMENSIONS). */
export async function embed(text, options) {
  return (await embedWithMeta(text, options)).embedding;
}
