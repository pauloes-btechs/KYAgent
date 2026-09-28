// T09 Atlas acceptance (MongoDB Search sanctions stage, REQ-P0-2):
// - an exact sanctioned wallet is a deterministic BLOCK SANCTIONS_EXACT_MATCH (10/10 runs), from
//   the B-tree `find` on `wallets.address`, never from `$search`;
// - `$search` over the `sanctions_search` index (fuzzy maxEdits 2 + phonetic multi) returns the
//   Lazarus entity in the top 3 for "Lazarus Grp" and "Lazarous Group";
// - a clean counterparty produces no hit;
// - the stage output lands in the persisted investigation's `stages[sanctions].evidence`
//   (through the real POST /v1/investigations API on MongoStore).
// Runs only when ATLAS_TEST_URI is set; uses a unique per-run database dropped afterwards.
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { after, before, describe, test } from 'node:test';
import { buildApp } from '../../src/app.js';
import { loadConfig } from '../../src/config.js';
import { generateApiKey, hashApiKeySecret } from '../../src/crypto/apiKeys.js';
import { runInvestigation } from '../../src/investigation/pipeline.js';
import { retrieveMemories } from '../../src/memory/retrieve.js';
import { exactScreen, fuzzyScreen } from '../../src/sanctions/screen.js';
import { buildVerifyRequest } from '../../src/sdk/agentSigner.js';
import { DEMO3_CASE, DEMO_IDS, HARNESS_V1_POLICY, USDC, buildHackathonDocs, seedHackathon, treasuryBotKey } from '../../src/seed/hackathon.js';
import { ensureSearchIndexes, loadSearchIndexDefs } from '../../src/store/searchIndexes.js';

const uri = process.env.ATLAS_TEST_URI;
const skip = uri ? false : 'ATLAS_TEST_URI not set';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const docs = buildHackathonDocs();
const LAZARUS = docs.sanctions.find((s) => s._id === 'sdn_LAZARUS');
const LAZARUS_WALLET = LAZARUS.wallets[0].address;
const DATASET = LAZARUS.datasetVersion;
const CLEAN_CP = '0x7a11000000000000000000000000000000c0ffee'; // not listed (asserted by the seed)
const CLEAN_NAME = 'Acme Widgets';

describe('atlas: MongoDB Search sanctions stage', { skip, timeout: 420_000 }, () => {
  let app;
  let store;
  let base;
  let businessKey;

  const tx = (counterparty, over = {}) => ({
    asset: 'USDC',
    amount: 100 * USDC,
    counterparty,
    signingKeyThumbprint: treasuryBotKey('original').thumbprint,
    ...over,
  });
  const investigate = (counterparty) =>
    runInvestigation({ store, agentId: DEMO_IDS.agent, delegationId: DEMO_IDS.delegation, policy: HARNESS_V1_POLICY, tx: tx(counterparty) });
  const stage = (r, name) => r.stages.find((s) => s.name === name);

  before(async () => {
    const dbName = `kyagent_t09_${Date.now()}_${randomBytes(3).toString('hex')}`;
    const config = loadConfig({ NODE_ENV: 'test', LOG_LEVEL: 'silent', MONGODB_URI: uri, MONGODB_DB: dbName });
    const { MongoStore } = await import('../../src/store/mongo.js');
    store = new MongoStore(uri, dbName);
    app = buildApp({ config, store });
    await app.init();
    assert.equal(store.kind, 'mongo');

    await seedHackathon(store.db);
    const biz = generateApiKey();
    await store.apiKeys.insert({
      id: biz.keyId,
      name: 't09 test business',
      role: 'business',
      ownerId: DEMO_IDS.business,
      secretHash: hashApiKeySecret(config.pepper, biz.secret),
      status: 'active',
      createdAt: new Date(),
      lastUsedAt: null,
      revokedAt: null,
      demo: true,
    });
    businessKey = biz.plaintext;

    await ensureSearchIndexes(store.db, loadSearchIndexDefs(), { timeoutMs: 180_000 });
    // Freshly inserted documents take a moment to reach both indexes.
    const deadline = Date.now() + 120_000;
    for (;;) {
      const s = await fuzzyScreen(store.db, LAZARUS.name).catch(() => []);
      const m = await retrieveMemories({ db: store.db, signals: DEMO3_CASE.expectedSignals, minScorePpm: 0 }).catch(() => null);
      if (s.some((h) => h.sanctionsId === LAZARUS._id) && m && m.hits.length >= 2) break;
      if (Date.now() > deadline) throw new Error('search indexes did not index the seeded documents in time');
      await sleep(2_000);
    }
    ({ port: base } = await app.listen(0, '127.0.0.1'));
    base = `http://127.0.0.1:${base}`;
  });

  after(async () => {
    if (store?.db) await store.db.dropDatabase().catch(() => {});
    if (app) await app.close().catch(() => {});
  });

  test('exact sanctioned counterparty wallet -> BLOCK SANCTIONS_EXACT_MATCH, 10/10 runs', async () => {
    const outcomes = [];
    for (let i = 0; i < 10; i++) {
      // Mixed-case input on odd runs: the invariant compares lowercased addresses.
      const address = i % 2 ? LAZARUS_WALLET.toUpperCase().replace('0X', '0x') : LAZARUS_WALLET;
      const r = await investigate({ address });
      const s = stage(r, 'sanctions');
      assert.equal(r.riskDecision, 'BLOCK', `run ${i}`);
      assert.equal(r.reasons[0].code, 'SANCTIONS_EXACT_MATCH', `run ${i}: ${JSON.stringify(r.reasons)}`);
      assert.equal(r.reasons[0].invariantId, 'INV_SANCTIONS_EXACT_BLOCK');
      assert.deepEqual(r.reasons[0].evidenceRefs, [LAZARUS._id]);
      assert.equal(s.status, 'failed');
      assert.deepEqual(s.result.exactHits.map((h) => [h.sanctionsId, h.address]), [[LAZARUS._id, LAZARUS_WALLET]]);
      assert.equal(s.result.datasetVersion, DATASET);
      outcomes.push(JSON.stringify([r.riskDecision, r.reasons.map((x) => x.code), s.result.exactHits, s.evidence.filter((e) => e.kind !== 'memory')]));
    }
    assert.equal(new Set(outcomes).size, 1, 'identical outcome on every run');

    // The exact screen alone (a plain find, no $search) is equally deterministic.
    for (let i = 0; i < 10; i++) {
      const { held, exactHits } = await exactScreen(store, [docs.agents[0].wallets[0].address, LAZARUS.wallets[1].address]);
      assert.equal(held, false);
      assert.deepEqual(exactHits.map((h) => h.sanctionsId), [LAZARUS._id]);
    }
  });

  test("fuzzy/alias names: 'Lazarus Grp' and 'Lazarous Group' return the entity in the top 3", async () => {
    for (const q of ['Lazarus Grp', 'Lazarous Group']) {
      const hits = await fuzzyScreen(store.db, q);
      assert.ok(hits.length <= 5);
      const rank = hits.findIndex((h) => h.sanctionsId === LAZARUS._id);
      assert.ok(rank >= 0 && rank < 3, `${q}: ${JSON.stringify(hits.map((h) => h.sanctionsId))}`);
      const hit = hits[rank];
      assert.equal(hit.datasetVersion, DATASET);
      assert.ok(Number.isSafeInteger(hit.scorePpm) && hit.scorePpm > 0);
      assert.ok([LAZARUS.name, ...LAZARUS.aliases].includes(hit.matched), hit.matched);
      assert.ok(hits.every((h, i) => i === 0 || hits[i - 1].score >= h.score), 'ordered by searchScore');

      // Through the pipeline: clean address + look-alike name -> fuzzy evidence, never an exact BLOCK.
      const r = await investigate({ address: CLEAN_CP, name: q });
      const s = stage(r, 'sanctions');
      assert.deepEqual(s.result.exactHits, []);
      assert.ok(s.result.fuzzyHits.slice(0, 3).some((h) => h.sanctionsId === LAZARUS._id && h.role === 'counterparty' && h.query === q));
      assert.ok(s.evidence.some((e) => e.kind === 'sanctions_fuzzy' && e.ref === LAZARUS._id && e.data.datasetVersion === DATASET));
      assert.ok(!r.reasons.some((x) => x.code === 'SANCTIONS_EXACT_MATCH'));
    }
  });

  test('clean counterparty -> no exact hit, no fuzzy hit, no sanctions reason', async () => {
    const { held, exactHits } = await exactScreen(store, [CLEAN_CP]);
    assert.equal(held, true);
    assert.deepEqual(exactHits, []);
    const r = await investigate({ address: CLEAN_CP, name: CLEAN_NAME });
    const s = stage(r, 'sanctions');
    assert.equal(s.status, 'passed');
    assert.equal(s.engine, '$search');
    assert.deepEqual(s.result.exactHits, []);
    assert.deepEqual(s.result.fuzzyHits, []);
    assert.deepEqual(s.result.fuzzy.queried, ['counterparty']);
    assert.ok(s.evidence.some((e) => e.id === 'invariant:INV_SANCTIONS_EXACT_BLOCK' && e.data.held === true));
    assert.ok(!r.reasons.some((x) => x.stage === 'sanctions'));
  });

  test('POST /v1/investigations: evidence lands in the persisted investigation.stages[sanctions]', async () => {
    const body = buildVerifyRequest(treasuryBotKey('original').privateKey, {
      agentId: DEMO_IDS.agent,
      audience: DEMO_IDS.business,
      action: DEMO3_CASE.action,
      context: { amount: 100 * USDC, currency: 'USDC', counterparty: LAZARUS_WALLET, counterpartyName: 'Lazarous Group' },
    });
    const res = await fetch(`${base}/v1/investigations`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${businessKey}`, 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    const inv = await res.json();
    assert.equal(res.status, 201, JSON.stringify(inv));
    assert.equal(inv.riskDecision, 'BLOCK');
    assert.equal(inv.reasons[0].code, 'SANCTIONS_EXACT_MATCH');

    const doc = await store.db.collection('investigations').findOne({ _id: inv.id });
    assert.ok(doc, 'investigation persisted in Atlas');
    assert.equal(doc.riskDecision, 'BLOCK');
    const s = doc.stages.find((x) => x.name === 'sanctions');
    assert.ok(s, 'sanctions stage persisted');
    assert.deepEqual(doc.stages.map((x) => x.name).slice(0, 3), ['identity', 'delegation', 'sanctions']);
    assert.equal(s.status, 'failed');
    assert.equal(s.result.datasetVersion, DATASET);
    assert.deepEqual(s.result.exactHits.map((h) => h.sanctionsId), [LAZARUS._id]);
    assert.ok(s.evidence.some((e) => e.kind === 'sanctions_exact' && e.ref === LAZARUS._id && e.data.address === LAZARUS_WALLET));
    assert.ok(s.evidence.some((e) => e.kind === 'sanctions_fuzzy' && e.ref === LAZARUS._id));
    assert.ok(s.evidence.some((e) => e.id === 'invariant:INV_SANCTIONS_EXACT_BLOCK' && e.data.held === false));
  });
});
