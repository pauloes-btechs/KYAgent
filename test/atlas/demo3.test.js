// T08 Atlas acceptance (Demo 3 end-to-end): POST /v1/investigations on MongoStore runs the
// suspicious TreasuryBot case (rotated key, new counterparty, amount above p95) through the real
// HTTP API; the memory stage's `$vectorSearch` retrieves the VERIFIED takeover mem_INV-1042, the
// decision is REVIEW / MEMORY_PRECEDENT_TAKEOVER, and the investigation document persisted in
// Atlas carries `memory.hits` (read back through a separate client). `scripts/demo.js --demo 3
// --check` must exit 0 on the same database.
// Runs only when ATLAS_TEST_URI is set; uses a unique per-run database dropped afterwards.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { after, before, describe, test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { buildApp } from '../../src/app.js';
import { loadConfig } from '../../src/config.js';
import { generateApiKey, hashApiKeySecret } from '../../src/crypto/apiKeys.js';
import { retrieveMemories } from '../../src/memory/retrieve.js';
import { buildVerifyRequest } from '../../src/sdk/agentSigner.js';
import { DEMO3_CASE, DEMO_IDS, rotateTreasuryBotKey, seedHackathon, treasuryBotKey } from '../../src/seed/hackathon.js';
import { ensureSearchIndexes, loadSearchIndexDefs } from '../../src/store/searchIndexes.js';

const uri = process.env.ATLAS_TEST_URI;
const skip = uri ? false : 'ATLAS_TEST_URI not set';
const REPO_ROOT = fileURLToPath(new URL('../../', import.meta.url));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

describe('atlas: Demo 3 end-to-end (POST /v1/investigations)', { skip, timeout: 420_000 }, () => {
  let app;
  let store;
  let base;
  let dbName;
  let adminKey;
  let businessKey;

  const post = async (key, body) => {
    const res = await fetch(`${base}/v1/investigations`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${key}`, 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    return { status: res.status, body: await res.json() };
  };
  const demo3Request = () =>
    buildVerifyRequest(treasuryBotKey('rotated').privateKey, {
      agentId: DEMO_IDS.agent,
      audience: DEMO_IDS.business,
      action: DEMO3_CASE.action,
      context: { ...DEMO3_CASE.context },
    });

  before(async () => {
    dbName = `kyagent_t08_${Date.now()}_${randomBytes(3).toString('hex')}`;
    adminKey = generateApiKey().plaintext;
    const config = loadConfig({ NODE_ENV: 'test', LOG_LEVEL: 'silent', MONGODB_URI: uri, MONGODB_DB: dbName, KYA_BOOTSTRAP_ADMIN_API_KEY: adminKey });
    const { MongoStore } = await import('../../src/store/mongo.js');
    store = new MongoStore(uri, dbName);
    app = buildApp({ config, store });
    await app.init();
    assert.equal(store.kind, 'mongo');

    await seedHackathon(store.db);
    await rotateTreasuryBotKey(store.db);
    const biz = generateApiKey();
    await store.apiKeys.insert({
      id: biz.keyId,
      name: 'demo3 test business',
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

    await ensureSearchIndexes(store.db, loadSearchIndexDefs().filter((d) => d.name === 'memory_vector'), { timeoutMs: 180_000 });
    const deadline = Date.now() + 120_000;
    for (;;) {
      const r = await retrieveMemories({ db: store.db, signals: DEMO3_CASE.expectedSignals, minScorePpm: 0 }).catch(() => null);
      if (r && r.hits.length >= 2) break;
      if (Date.now() > deadline) throw new Error('memory_vector did not index the seeded memories in time');
      await sleep(2_000);
    }
    ({ port: base } = await app.listen(0, '127.0.0.1'));
    base = `http://127.0.0.1:${base}`;
  });

  after(async () => {
    if (store?.db) await store.db.dropDatabase().catch(() => {});
    if (app) await app.close().catch(() => {});
  });

  let investigationId;

  test('business: suspicious TreasuryBot payment -> REVIEW / MEMORY_PRECEDENT_TAKEOVER from VERIFIED mem_INV-1042', async () => {
    const { status, body: inv } = await post(businessKey, demo3Request());
    assert.equal(status, 201, JSON.stringify(inv));
    investigationId = inv.id;
    assert.match(inv.id, /^inv_[0-9A-Z]{26}$/);
    assert.equal(inv.trigger, 'api');
    assert.equal(inv.businessId, DEMO_IDS.business);
    assert.equal(inv.delegationId, DEMO_IDS.delegation);
    assert.deepEqual(inv.stages.map((s) => s.name), ['identity', 'delegation', 'signals', 'memory', 'decision']);
    assert.equal(inv.stages[0].result.mode, 'signed');
    assert.equal(inv.stages[0].result.reasonCode, 'ALLOWED');
    assert.equal(inv.stages[0].evidence[0].data.signature, 'valid');
    assert.equal(inv.stages[0].evidence[0].data.nonce, 'fresh');
    assert.equal(inv.stages[1].status, 'passed');
    assert.deepEqual([...inv.signals].sort(), [...DEMO3_CASE.expectedSignals]);
    assert.equal(inv.stages[3].engine, '$vectorSearch');
    assert.equal(inv.memory.engine, '$vectorSearch');
    const top = inv.memory.hits[0];
    assert.equal(top.memoryId, 'mem_INV-1042');
    assert.equal(top.status, 'VERIFIED');
    assert.equal(top.outcome, 'CONFIRMED_ACCOUNT_TAKEOVER');
    assert.equal(top.usedAsPrecedent, true);
    assert.ok(top.scorePpm >= inv.memory.minScorePpm && top.scorePpm < 1_000_000, `score ${top.scorePpm}`);
    assert.ok(inv.memory.hits.every((h) => h.status === 'VERIFIED' && h.memoryId !== 'mem_INV-1101'));
    assert.equal(inv.decision, 'DENY'); // identity-layer vocabulary: anything but ALLOW is DENY
    assert.equal(inv.riskDecision, 'REVIEW');
    assert.equal(inv.status, 'AWAITING_REVIEW');
    assert.equal(inv.reasons[0].code, 'MEMORY_PRECEDENT_TAKEOVER');
    assert.deepEqual(inv.reasons[0].evidenceRefs, ['mem_INV-1042']);
    assert.ok(inv.stages.flatMap((s) => s.evidence).some((e) => e.id === 'memory:mem_INV-1042' && e.data.status === 'VERIFIED'));
  });

  test('the investigation document persisted in Atlas carries memory.hits and survives a new client', async () => {
    assert.ok(investigationId, 'first test produced an investigation');
    const doc = await store.db.collection('investigations').findOne({ _id: investigationId });
    assert.ok(doc);
    assert.equal(doc.riskDecision, 'REVIEW');
    assert.equal(doc.harnessVersion, 1);
    assert.equal(doc.memory.hits[0].memoryId, 'mem_INV-1042');
    assert.equal(doc.memory.hits[0].status, 'VERIFIED');
    assert.equal(doc.stages.length, 5);

    const { MongoClient } = await import('mongodb');
    const client = new MongoClient(uri, { serverSelectionTimeoutMS: 10_000 });
    await client.connect();
    try {
      const again = await client.db(dbName).collection('investigations').findOne({ _id: investigationId });
      assert.deepEqual(again.memory.hits.map((h) => [h.memoryId, h.status, h.scorePpm]), doc.memory.hits.map((h) => [h.memoryId, h.status, h.scorePpm]));
      const audit = await client.db(dbName).collection('audit_events').findOne({ type: 'investigation.decided', subjectId: investigationId });
      assert.equal(audit?.data?.riskDecision, 'REVIEW');
      assert.deepEqual(audit.data.memoryHits[0], 'mem_INV-1042');
    } finally {
      await client.close();
    }
  });

  test('replaying the same signed request is BLOCK / IDENTITY_DENIED (nonce consumed once, later stages skipped)', async () => {
    const body = demo3Request();
    assert.equal((await post(businessKey, body)).status, 201);
    const { status, body: inv } = await post(businessKey, body);
    assert.equal(status, 201);
    assert.equal(inv.riskDecision, 'BLOCK');
    assert.equal(inv.reasons[0].code, 'IDENTITY_DENIED');
    assert.equal(inv.reasons[0].identityReasonCode, 'NONCE_REPLAYED');
    assert.deepEqual(inv.stages.slice(1, 4).map((s) => s.status), ['skipped', 'skipped', 'skipped']);
    assert.deepEqual(inv.memory.hits, []);
  });

  test('admin caller: audience names the business; same REVIEW outcome', async () => {
    const { status, body: inv } = await post(adminKey, demo3Request());
    assert.equal(status, 201, JSON.stringify(inv));
    assert.equal(inv.businessId, DEMO_IDS.business);
    assert.equal(inv.riskDecision, 'REVIEW');
    assert.equal(inv.memory.hits[0].memoryId, 'mem_INV-1042');
  });

  test('scripts/demo.js --demo 3 --check exits 0 on the expected outcome', () => {
    const env = { ...process.env, MONGODB_URI: uri, MONGODB_DB: dbName, PORT: '0', LOG_LEVEL: 'silent' };
    delete env.NODE_ENV;
    const child = spawnSync(process.execPath, ['scripts/demo.js', '--check', '--demo', '3'], { cwd: REPO_ROOT, env, encoding: 'utf8', timeout: 120_000 });
    assert.equal(child.status, 0, `demo failed:\n${child.stdout}\n${child.stderr}`);
    assert.match(child.stdout, /DEMO 3 OK/);
    assert.match(child.stdout, /mem_INV-1042 .*VERIFIED/);
    assert.match(child.stdout, /decision {2}REVIEW \(MEMORY_PRECEDENT_TAKEOVER/);
  });
});
