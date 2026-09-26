import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { SIGNALS, SignalsTextError, signalsText, textSha256 } from '../src/memory/signalsText.js';
import {
  EMBEDDING_DIMENSIONS,
  EmbeddingError,
  LIVE_MODEL,
  VOYAGE_URL,
  embed,
  embedWithMeta,
  embeddingsMode,
  loadFixture,
} from '../src/memory/embeddings.js';
import { FIXTURE_MODEL } from '../src/memory/fixtureVectors.js';
import { buildFixture } from '../scripts/gen-embeddings-fixture.js';

const TAKEOVER = ['SIGNING_KEY_CHANGED', 'NEW_COUNTERPARTY', 'AMOUNT_ANOMALY', 'NEAR_CEILING']; // mem_INV-1042
const IRRELEVANT = ['VELOCITY']; // mem_INV-0977
const FIXTURE_ENV = { EMBEDDINGS_MODE: 'fixture' };
const cosine = (a, b) => {
  let d = 0, na = 0, nb = 0;
  for (let i = 0; i < a.length; i += 1) { d += a[i] * b[i]; na += a[i] * a[i]; nb += b[i] * b[i]; }
  return d / Math.sqrt(na * nb);
};
const atlasScore = (c) => (1 + c) / 2; // $vectorSearch cosine score
const MIN_SCORE = 0.78; // harness v1 memoryRetrieval.minScorePpm = 780000

test('SIGNALS matches docs/contracts/types.ts', () => {
  const ts = readFileSync(new URL('../docs/contracts/types.ts', import.meta.url), 'utf8');
  const m = ts.match(/export const SIGNALS = \[([^\]]+)\]/);
  assert.ok(m);
  assert.deepEqual([...SIGNALS], [...m[1].matchAll(/'([A-Z_]+)'/g)].map((x) => x[1]));
});

test('signalsText is deterministic, order- and duplicate-insensitive, canonical JSON', () => {
  const a = signalsText(TAKEOVER);
  assert.equal(a, signalsText([...TAKEOVER].reverse()));
  assert.equal(a, signalsText({ signals: [...TAKEOVER, 'NEAR_CEILING'] }));
  assert.equal(a, '{"kind":"kya.signals","signals":["AMOUNT_ANOMALY","NEAR_CEILING","NEW_COUNTERPARTY","SIGNING_KEY_CHANGED"],"v":1}');
  assert.notEqual(a, signalsText(TAKEOVER.slice(0, 3)));
  assert.equal(signalsText([]), '{"kind":"kya.signals","signals":[],"v":1}');
  assert.throws(() => signalsText(['NOT_A_SIGNAL']), SignalsTextError);
  assert.throws(() => signalsText('SIGNING_KEY_CHANGED'), SignalsTextError);
});

test('index numDimensions is 1024 and default mode is fixture', () => {
  assert.equal(EMBEDDING_DIMENSIONS, 1024);
  assert.equal(embeddingsMode({}), 'fixture');
  assert.equal(embeddingsMode({ EMBEDDINGS_MODE: 'live' }), 'live');
  assert.throws(() => embeddingsMode({ EMBEDDINGS_MODE: 'random' }), EmbeddingError);
});

test('fixture mode returns 1024-d vectors keyed by sha256(signalsText)', async () => {
  const text = signalsText(TAKEOVER);
  const r = await embedWithMeta(text, { env: FIXTURE_ENV });
  assert.equal(r.embedding.length, 1024);
  assert.equal(r.embeddingModel, FIXTURE_MODEL);
  assert.equal(r.embeddingTextSha256, textSha256(text));
  assert.equal(r.mode, 'fixture');
  assert.deepEqual(await embed(text, { env: FIXTURE_ENV }), r.embedding);
});

test('unknown text in fixture mode throws (never a silent zero vector)', async () => {
  await assert.rejects(embed('treasury agent account takeover', { env: FIXTURE_ENV }), (e) => e instanceof EmbeddingError && e.code === 'FIXTURE_UNKNOWN_TEXT');
  await assert.rejects(embed('', { env: FIXTURE_ENV }), EmbeddingError);
});

test('fixture covers every subset of the closed signal set and regenerates byte-identically', () => {
  const doc = loadFixture();
  assert.equal(doc.dimensions, 1024);
  assert.equal(Object.keys(doc.vectors).length, 2 ** SIGNALS.length);
  for (const [sha, entry] of Object.entries(doc.vectors)) {
    assert.equal(sha, textSha256(entry.text));
    assert.equal(entry.text, signalsText(entry.signals));
    assert.equal(entry.embedding.length, 1024);
  }
  const committed = readFileSync(new URL('../fixtures/embeddings.json', import.meta.url), 'utf8');
  assert.equal(`${JSON.stringify(buildFixture())}\n`, committed);
});

test('fixture geometry: similar takeover patterns are near, irrelevant/clean are far', async () => {
  const v = async (s) => embed(signalsText(s), { env: FIXTURE_ENV });
  const takeover = await v(TAKEOVER);
  const similar = await v(['SIGNING_KEY_CHANGED', 'NEW_COUNTERPARTY', 'AMOUNT_ANOMALY']);
  const swapped = await v(['SIGNING_KEY_CHANGED', 'NEW_COUNTERPARTY', 'AMOUNT_ANOMALY', 'VELOCITY']);
  const irrelevant = await v(IRRELEVANT);
  const clean = await v([]);
  assert.ok(Math.abs(cosine(takeover, takeover) - 1) < 1e-6);
  assert.ok(atlasScore(cosine(takeover, similar)) >= MIN_SCORE);
  assert.ok(atlasScore(cosine(takeover, swapped)) >= MIN_SCORE);
  assert.ok(atlasScore(cosine(takeover, irrelevant)) < MIN_SCORE);
  assert.ok(atlasScore(cosine(takeover, clean)) < MIN_SCORE);
  assert.ok(Math.abs(cosine(takeover, irrelevant)) < 1e-5);
  assert.ok(cosine(similar, takeover) > cosine(similar, irrelevant) + 0.5);
});

test('live mode calls Voyage voyage-3.5-lite with output_dimension 1024 and asserts the dimension', async () => {
  const text = signalsText(TAKEOVER);
  const calls = [];
  const vec = Array.from({ length: 1024 }, (_, i) => Math.sin(i + 1));
  const fetchImpl = async (url, init) => {
    calls.push({ url, init });
    return { ok: true, status: 200, json: async () => ({ model: LIVE_MODEL, data: [{ index: 0, embedding: vec }] }) };
  };
  const env = { EMBEDDINGS_MODE: 'live', VOYAGE_API_KEY: 'test-key' };
  const r = await embedWithMeta(text, { env, fetchImpl });
  assert.equal(r.embedding.length, 1024);
  assert.equal(r.embeddingModel, LIVE_MODEL);
  assert.equal(r.mode, 'live');
  assert.equal(calls[0].url, VOYAGE_URL);
  const body = JSON.parse(calls[0].init.body);
  assert.deepEqual(body, { input: [text], model: 'voyage-3.5-lite', output_dimension: 1024 });
  assert.equal(calls[0].init.headers.authorization, 'Bearer test-key');

  const fixtureVec = await embed(text, { env: FIXTURE_ENV });
  assert.equal(r.embedding.length, fixtureVec.length);

  const short = async () => ({ ok: true, status: 200, json: async () => ({ data: [{ embedding: vec.slice(0, 512) }] }) });
  await assert.rejects(embed(text, { env, fetchImpl: short }), (e) => e.code === 'DIMENSION_MISMATCH');
  const zero = async () => ({ ok: true, status: 200, json: async () => ({ data: [{ embedding: new Array(1024).fill(0) }] }) });
  await assert.rejects(embed(text, { env, fetchImpl: zero }), (e) => e.code === 'INVALID_VECTOR');
  const fail = async () => ({ ok: false, status: 401, json: async () => ({}) });
  await assert.rejects(embed(text, { env, fetchImpl: fail }), (e) => e.code === 'PROVIDER' && !e.message.includes('test-key'));
  await assert.rejects(embed(text, { env: { EMBEDDINGS_MODE: 'live' }, fetchImpl }), (e) => e.code === 'CONFIG');
});

test('live Voyage vectors share the fixture dimension (requires VOYAGE_API_KEY)', { skip: !process.env.VOYAGE_API_KEY && 'VOYAGE_API_KEY not set' }, async () => {
  const text = signalsText(TAKEOVER);
  const live = await embedWithMeta(text, { env: { ...process.env, EMBEDDINGS_MODE: 'live' } });
  const fixture = await embed(text, { env: FIXTURE_ENV });
  assert.equal(live.embedding.length, 1024);
  assert.equal(live.embedding.length, fixture.length);
});
