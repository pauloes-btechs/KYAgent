// T07 Atlas acceptance (gate `vector_memory`): the memory stage runs a real `$vectorSearch` on
// the `memory_vector` index over the hackathon seed memories.
// - a similar-but-not-identical case (different amount and counterparty) ranks mem_INV-1042 first;
// - a VELOCITY-only query does not return mem_INV-1042 above minScore;
// - mem_INV-1101 (UNVERIFIED, same vector as 1042) is never returned;
// - the same query in a fresh process with a new client returns identical hits (persistence).
// Runs only when ATLAS_TEST_URI is set; uses a unique per-run database dropped afterwards
// (which also frees the search-index slot).
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { after, before, describe, test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { runInvestigation } from '../../src/investigation/pipeline.js';
import { retrieveMemories } from '../../src/memory/retrieve.js';
import { HARNESS_V1_POLICY, USDC, seedHackathon, treasuryBotKey } from '../../src/seed/hackathon.js';
import { ensureSearchIndexes, loadSearchIndexDefs } from '../../src/store/searchIndexes.js';

const uri = process.env.ATLAS_TEST_URI;
const skip = uri ? false : 'ATLAS_TEST_URI not set';
const RETRIEVE_URL = new URL('../../src/memory/retrieve.js', import.meta.url).href;
const REPO_ROOT = fileURLToPath(new URL('../../', import.meta.url));

const TAKEOVER = ['AMOUNT_ANOMALY', 'NEAR_CEILING', 'NEW_COUNTERPARTY', 'SIGNING_KEY_CHANGED'];
const SIMILAR = ['AMOUNT_ANOMALY', 'NEW_COUNTERPARTY', 'SIGNING_KEY_CHANGED'];
const OPTS = { ...HARNESS_V1_POLICY.memoryRetrieval };
delete OPTS.filter;
const SIMILAR_CP = { address: '0x7a11000000000000000000000000000000c0ffee', name: 'Unfamiliar OTC desk' };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const view = (r) => r.hits.map((h) => ({ memoryId: h.memoryId, status: h.status, scorePpm: h.scorePpm }));

describe('atlas: Vector Search verified security memory', { skip, timeout: 300_000 }, () => {
  let store;
  let dbName;
  const now = new Date();

  const openStore = async () => {
    const { MongoStore } = await import('../../src/store/mongo.js');
    const s = new MongoStore(uri, dbName);
    await s.init();
    return s;
  };

  before(async () => {
    dbName = `kyagent_t07_${Date.now()}_${randomBytes(3).toString('hex')}`;
    store = await openStore();
    await seedHackathon(store.db, { now });
    // TreasuryBot's signing key was rotated 2 h ago (the takeover precondition of Demo 3).
    const rotatedAt = new Date(now.getTime() - 2 * 3_600_000);
    const agent = await store.db.collection('agents').findOne({ _id: 'agt_TREASURYBOT' });
    await store.db.collection('agents').updateOne(
      { _id: 'agt_TREASURYBOT' },
      {
        $set: {
          keyThumbprint: treasuryBotKey('rotated').thumbprint,
          publicKey: treasuryBotKey('rotated').publicKey,
          signingKeyHistory: [
            { ...agent.signingKeyHistory[0], to: rotatedAt },
            { thumbprint: treasuryBotKey('rotated').thumbprint, from: rotatedAt, to: null },
          ],
        },
      },
    );
    // Both indexes: the sanctions stage screens the counterparty name with $search.
    await ensureSearchIndexes(store.db, loadSearchIndexDefs(), { timeoutMs: 180_000 });
    // Freshly inserted documents take a moment to reach the index.
    const deadline = Date.now() + 120_000;
    for (;;) {
      const r = await retrieveMemories({ db: store.db, signals: TAKEOVER, ...OPTS, minScorePpm: 0 }).catch(() => null);
      if (r && r.hits.length >= 2) break;
      if (Date.now() > deadline) throw new Error('memory_vector did not index the seeded memories in time');
      await sleep(2_000);
    }
  });

  after(async () => {
    if (store?.db) await store.db.dropDatabase().catch(() => {});
    if (store) await store.close();
  });

  test('similar non-identical case: pipeline records $vectorSearch and ranks mem_INV-1042 first', async () => {
    const r = await runInvestigation({
      store,
      agentId: 'agt_TREASURYBOT',
      delegationId: 'grt_TB_USDC',
      now,
      tx: {
        id: 'txn_T07_SIMILAR',
        asset: 'USDC',
        amount: 21_000 * USDC, // 1042 was a near-ceiling payment; this one is not
        counterparty: SIMILAR_CP,
        signingKeyThumbprint: treasuryBotKey('rotated').thumbprint,
      },
    });
    assert.deepEqual(r.stages.map((s) => s.name), ['identity', 'delegation', 'sanctions', 'signals', 'memory', 'decision']);
    assert.deepEqual(r.stages.map((s) => s.status).slice(0, 2), ['passed', 'passed']);
    assert.deepEqual([...r.signals].sort(), SIMILAR);
    const mem = r.stages[4];
    assert.equal(mem.engine, '$vectorSearch');
    assert.equal(r.memory.engine, '$vectorSearch');
    assert.equal(r.memory.hits[0].memoryId, 'mem_INV-1042');
    assert.equal(r.memory.hits[0].status, 'VERIFIED');
    assert.equal(r.memory.hits[0].outcome, 'CONFIRMED_ACCOUNT_TAKEOVER');
    assert.ok(r.memory.hits[0].scorePpm >= r.memory.minScorePpm && r.memory.hits[0].scorePpm < 1_000_000, `score ${r.memory.hits[0].scorePpm}`);
    assert.ok(r.memory.hits.every((h) => h.status === 'VERIFIED' && h.memoryId !== 'mem_INV-1101'));
    // Visible in the evidence with memoryId / score / status.
    const ev = r.evidence.find((e) => e.id === 'memory:mem_INV-1042');
    assert.ok(ev, 'memory evidence present');
    assert.equal(ev.kind, 'memory');
    assert.equal(ev.data.memoryId, 'mem_INV-1042');
    assert.equal(ev.data.status, 'VERIFIED');
    assert.equal(ev.data.scorePpm, r.memory.hits[0].scorePpm);
    // Precedent escalates to REVIEW (never proof, never BLOCK by itself).
    assert.equal(r.riskDecision, 'REVIEW');
    assert.equal(r.reasons[0].code, 'MEMORY_PRECEDENT_TAKEOVER');
    assert.deepEqual(r.reasons[0].evidenceRefs, ['mem_INV-1042']);
  });

  test('retrieval of the similar signal set returns mem_INV-1042 at rank 1', async () => {
    const r = await retrieveMemories({ db: store.db, signals: SIMILAR, ...OPTS });
    assert.equal(r.hits[0]?.memoryId, 'mem_INV-1042');
    assert.equal(r.droppedUnverified, 0);
  });

  test('VELOCITY-only query does not return mem_INV-1042 above minScore', async () => {
    const r = await retrieveMemories({ db: store.db, signals: ['VELOCITY'], ...OPTS });
    assert.ok(!r.hits.some((h) => h.memoryId === 'mem_INV-1042'), JSON.stringify(view(r)));
    // 1042 is in the candidate set but scores below the cutoff: it was dropped, not missed.
    const all = await retrieveMemories({ db: store.db, signals: ['VELOCITY'], ...OPTS, minScorePpm: 0 });
    const t = all.hits.find((h) => h.memoryId === 'mem_INV-1042');
    assert.ok(t && t.scorePpm < OPTS.minScorePpm, JSON.stringify(view(all)));
    assert.ok(r.droppedBelowScore >= 1);
    // The pipeline raises no takeover precedent for such a case.
    assert.ok(!r.hits.some((h) => h.outcome === 'CONFIRMED_ACCOUNT_TAKEOVER'));
  });

  test('mem_INV-1101 (UNVERIFIED) is never returned, even as the closest vector', async () => {
    const doc = await store.db.collection('security_memories').findOne({ _id: 'mem_INV-1101' });
    const ref = await store.db.collection('security_memories').findOne({ _id: 'mem_INV-1042' });
    assert.equal(doc.status, 'UNVERIFIED');
    assert.deepEqual(doc.embedding, ref.embedding);
    for (const signals of [TAKEOVER, SIMILAR, ['VELOCITY'], []]) {
      const r = await retrieveMemories({ db: store.db, signals, k: 10, numCandidates: 100, minScorePpm: 0 });
      assert.ok(r.hits.length > 0);
      assert.ok(!r.hits.some((h) => h.memoryId === 'mem_INV-1101'), JSON.stringify(view(r)));
      assert.ok(r.hits.every((h) => h.status === 'VERIFIED'));
    }
  });

  test('persistence: identical hits after closing the client and querying from a new process', async () => {
    const before = view(await retrieveMemories({ db: store.db, signals: SIMILAR, ...OPTS }));
    await store.close();
    store = await openStore(); // reopen in-process with a new client
    const reopened = view(await retrieveMemories({ db: store.db, signals: SIMILAR, ...OPTS }));
    assert.deepEqual(reopened, before);

    const script = `
      import { MongoClient } from 'mongodb';
      const { retrieveMemories } = await import(process.env.T07_RETRIEVE_URL);
      const client = new MongoClient(process.env.ATLAS_TEST_URI, { serverSelectionTimeoutMS: 10000 });
      await client.connect();
      try {
        const r = await retrieveMemories({ db: client.db(process.env.T07_DB), signals: JSON.parse(process.env.T07_SIGNALS), ...JSON.parse(process.env.T07_OPTS) });
        process.stdout.write(JSON.stringify(r.hits.map((h) => ({ memoryId: h.memoryId, status: h.status, scorePpm: h.scorePpm }))));
      } finally {
        await client.close();
      }`;
    const child = spawnSync(process.execPath, ['--input-type=module', '-e', script], {
      cwd: REPO_ROOT,
      env: { ...process.env, T07_RETRIEVE_URL: RETRIEVE_URL, T07_DB: dbName, T07_SIGNALS: JSON.stringify(SIMILAR), T07_OPTS: JSON.stringify(OPTS) },
      encoding: 'utf8',
      timeout: 60_000,
    });
    assert.equal(child.status, 0, `child failed: ${child.stderr}`);
    assert.deepEqual(JSON.parse(child.stdout), before);
    assert.equal(before[0].memoryId, 'mem_INV-1042');
  });
});
