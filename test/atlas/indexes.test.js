// T03 Atlas acceptance: migrations 001–008 apply on a real Atlas cluster, the
// $jsonSchema validators hold (harness_versions rejects an `invariants` key) and
// both search indexes from search-indexes.json become queryable in < 120 s.
// Runs only when ATLAS_TEST_URI is set; uses a unique per-run database that is
// dropped afterwards (which also frees the M0 search-index slots).
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { after, before, describe, test } from 'node:test';
import { INVARIANTS_HASH } from '../../src/harness/invariants.js';
import { MIGRATIONS, runMigrations } from '../../src/store/migrations.js';
import { ensureSearchIndexes, loadSearchIndexDefs } from '../../src/store/searchIndexes.js';

const uri = process.env.ATLAS_TEST_URI;
const skip = uri ? false : 'ATLAS_TEST_URI not set';

const V1_POLICY = {
  steps: ['identity', 'delegation', 'sanctions', 'signals', 'memory', 'policy'],
  memoryRetrieval: { k: 3, numCandidates: 100, minScorePpm: 780000, filter: { status: 'VERIFIED' } },
  contextAssembly: { maxMemories: 3, includeSignalStats: true, includeSanctionsEvidence: true },
  evidenceRequests: [],
  escalation: [
    {
      id: 'precedent_takeover',
      when: { precedentOutcomeIn: ['CONFIRMED_ACCOUNT_TAKEOVER'] },
      then: { riskDecision: 'REVIEW', reasonCode: 'MEMORY_PRECEDENT_TAKEOVER' },
    },
  ],
};

const harnessDoc = (version, policy, status = 'superseded') => ({
  _id: version,
  version,
  status,
  parentVersion: null,
  invariantsHash: INVARIANTS_HASH,
  policy,
  policyHash: createHash('sha256').update(JSON.stringify(policy)).digest('hex'),
  createdAt: new Date(),
  approvedBy: { role: 'system', apiKeyId: null, ownerId: null, label: 'seed' },
  sourceEventId: null,
});

const isValidationError = (err) => err && err.code === 121;

describe('atlas: migrations + search indexes', { skip, timeout: 300_000 }, () => {
  let client;
  let db;

  before(async () => {
    const { MongoClient } = await import('mongodb');
    client = new MongoClient(uri, { serverSelectionTimeoutMS: 10_000 });
    await client.connect();
    db = client.db(`kyagent_t03_${Date.now()}_${randomBytes(3).toString('hex')}`);
  });

  after(async () => {
    if (db) await db.dropDatabase().catch(() => {});
    if (client) await client.close();
  });

  test('migrations apply once and are idempotent', async () => {
    const first = await runMigrations(db);
    assert.deepEqual(first.applied, MIGRATIONS.map((m) => m.id));
    const second = await runMigrations(db);
    assert.deepEqual(second.applied, []);
  });

  test('sanctions has the exact-wallet B-tree index; agents has the wallet index', async () => {
    const keys = async (c) => (await db.collection(c).indexes()).map((i) => Object.keys(i.key).join());
    assert.ok((await keys('sanctions')).includes('wallets.address'));
    assert.ok((await keys('agents')).includes('wallets.address'));
  });

  test('principals view projects operators without contactEmail', async () => {
    await db.collection('operators').insertOne({ _id: 'op_T03', legalName: 'Acme', status: 'verified', contactEmail: 'x@example.com' });
    const p = await db.collection('principals').findOne({ _id: 'op_T03' });
    assert.equal(p.principalId, 'op_T03');
    assert.equal(p.contactEmail, undefined);
  });

  test('harness_versions validator accepts v1 and rejects any invariants key', async () => {
    const hv = db.collection('harness_versions');
    await hv.insertOne(harnessDoc(1, V1_POLICY, 'active'));
    await assert.rejects(hv.insertOne({ ...harnessDoc(2, V1_POLICY), invariants: [] }), isValidationError);
    await assert.rejects(hv.insertOne(harnessDoc(3, { ...V1_POLICY, skipInvariants: true })), isValidationError);
    await assert.rejects(
      hv.insertOne(harnessDoc(4, { ...V1_POLICY, memoryRetrieval: { ...V1_POLICY.memoryRetrieval, filter: { status: 'UNVERIFIED' } } })),
      isValidationError,
    );
    // Unique partial index: at most one active version.
    await assert.rejects(hv.insertOne(harnessDoc(5, V1_POLICY, 'active')), (e) => e.code === 11000);
  });

  test('sanctions validator enforces lowercased EVM addresses', async () => {
    const s = db.collection('sanctions');
    const doc = { _id: 'sdn_T03', name: 'Test', aliases: [], type: 'entity', datasetVersion: '2026-09-26' };
    await s.insertOne({ ...doc, wallets: [{ chain: 'evm', address: `0x${'a'.repeat(40)}` }] });
    await assert.rejects(s.insertOne({ ...doc, _id: 'sdn_T03b', wallets: [{ chain: 'evm', address: `0x${'A'.repeat(40)}` }] }), isValidationError);
  });

  test('security_memories validator: 1024-dim embedding; VERIFIED requires verifier', async () => {
    const m = db.collection('security_memories');
    const base = {
      title: 't', signals: [], signalsText: 's', embedding: Array(1024).fill(0.5), embeddingModel: 'voyage-3.5-lite', createdAt: new Date(),
    };
    await m.insertOne({ ...base, _id: 'mem_A', status: 'UNVERIFIED', sourceInvestigationId: 'inv_A' });
    await assert.rejects(m.insertOne({ ...base, _id: 'mem_B', status: 'VERIFIED', sourceInvestigationId: 'inv_B' }), isValidationError);
    await assert.rejects(m.insertOne({ ...base, _id: 'mem_C', status: 'UNVERIFIED', embedding: [0.1], sourceInvestigationId: 'inv_C' }), isValidationError);
  });

  test('ensureSearchIndexes: both indexes reach queryable in < 120 s and re-run is idempotent', { timeout: 150_000 }, async () => {
    const defs = loadSearchIndexDefs();
    assert.deepEqual(defs.map((d) => d.name).sort(), ['memory_vector', 'sanctions_search']);
    const t0 = Date.now();
    const res = await ensureSearchIndexes(db, defs, { timeoutMs: 120_000 });
    const elapsed = Date.now() - t0;
    assert.ok(elapsed < 120_000, `took ${elapsed} ms`);
    for (const r of res) assert.equal(r.queryable, true, `${r.collection}.${r.name} status=${r.status}`);
    const byName = Object.fromEntries(res.map((r) => [r.name, r]));
    assert.equal(byName.sanctions_search.type, 'search');
    assert.equal(byName.memory_vector.type, 'vectorSearch');

    const again = await ensureSearchIndexes(db, defs, { timeoutMs: 10_000 });
    assert.ok(again.every((r) => r.queryable && !r.created));
  });
});
