// T13 Atlas acceptance (Demo 5, REQ-P0-5): a human-confirmed CONFIRMED_ACCOUNT_TAKEOVER promotes
// the case memory to VERIFIED and produces harness v2 (persisted with old/new policy, diff,
// evidence, timestamp and admin approval); an equivalent later case runs the extra adaptive step
// `signing_key_history_check` under harnessVersion 2; INVARIANTS_HASH is identical in v1 and v2;
// a self-approval attempt is 403 and writes nothing. Everything goes through the real HTTP API on
// MongoStore and is read back from Atlas.
// Runs only when ATLAS_TEST_URI is set; uses a unique per-run database dropped afterwards.
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { after, before, describe, test } from 'node:test';
import { buildApp } from '../../src/app.js';
import { loadConfig } from '../../src/config.js';
import { generateApiKey, hashApiKeySecret } from '../../src/crypto/apiKeys.js';
import { INVARIANTS_HASH } from '../../src/harness/invariants.js';
import { retrieveMemories } from '../../src/memory/retrieve.js';
import { buildVerifyRequest } from '../../src/sdk/agentSigner.js';
import { DEMO3_CASE, DEMO_IDS, rotateTreasuryBotKey, seedHackathon, treasuryBotKey } from '../../src/seed/hackathon.js';
import { ensureSearchIndexes, loadSearchIndexDefs } from '../../src/store/searchIndexes.js';

const uri = process.env.ATLAS_TEST_URI;
const skip = uri ? false : 'ATLAS_TEST_URI not set';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const STEP = 'signing_key_history_check';

describe('atlas: Demo 5 adaptive harness (confirm -> memory VERIFIED -> harness v2 -> extra step)', { skip, timeout: 480_000 }, () => {
  let app;
  let store;
  let base;
  let adminKey;
  let businessKey;
  let caseA;
  let caseB;
  let confirmation;

  const call = async (key, method, path, body) => {
    const res = await fetch(`${base}${path}`, {
      method,
      headers: { Authorization: `Bearer ${key}`, ...(body === undefined ? {} : { 'Content-Type': 'application/json' }) },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    return { status: res.status, body: await res.json() };
  };
  const investigate = async (key) => {
    const body = buildVerifyRequest(treasuryBotKey('rotated').privateKey, {
      agentId: DEMO_IDS.agent,
      audience: DEMO_IDS.business,
      action: DEMO3_CASE.action,
      context: { ...DEMO3_CASE.context },
    });
    const r = await call(key, 'POST', '/v1/investigations', body);
    assert.equal(r.status, 201, JSON.stringify(r.body));
    return r.body;
  };
  const col = (name) => store.db.collection(name);

  before(async () => {
    const dbName = `kyagent_t13_${Date.now()}_${randomBytes(3).toString('hex')}`;
    adminKey = generateApiKey().plaintext;
    const config = loadConfig({ NODE_ENV: 'test', LOG_LEVEL: 'silent', MONGODB_URI: uri, MONGODB_DB: dbName, KYA_BOOTSTRAP_ADMIN_API_KEY: adminKey });
    assert.equal(config.modes.llm, 'fixture');
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
      name: 'demo5 test business',
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

    // Both indexes: the sanctions stage screens the signed counterpartyName with $search.
    await ensureSearchIndexes(store.db, loadSearchIndexDefs(), { timeoutMs: 180_000 });
    const deadline = Date.now() + 120_000;
    for (;;) {
      const r = await retrieveMemories({ db: store.db, signals: DEMO3_CASE.expectedSignals, minScorePpm: 0 }).catch(() => null);
      if (r && r.hits.length >= 2) break;
      if (Date.now() > deadline) throw new Error('memory_vector did not index the seeded memories in time');
      await sleep(2_000);
    }
    const { port } = await app.listen(0, '127.0.0.1');
    base = `http://127.0.0.1:${port}`;
  });

  after(async () => {
    if (store?.db) await store.db.dropDatabase().catch(() => {});
    if (app) await app.close().catch(() => {});
  });

  test('before confirm: case A (REVIEW) leaves an UNVERIFIED case memory; case B runs N stages under harness v1', async () => {
    caseA = await investigate(businessKey);
    assert.equal(caseA.riskDecision, 'REVIEW');
    assert.equal(caseA.status, 'AWAITING_REVIEW');
    const candidate = await col('security_memories').findOne({ _id: `mem_${caseA.id}` });
    assert.equal(candidate?.status, 'UNVERIFIED');
    assert.equal(candidate.embedding.length, 1024);

    caseB = await investigate(businessKey);
    assert.equal(caseB.harnessVersion, 1);
    assert.deepEqual(caseB.stages.map((s) => s.name), ['identity', 'delegation', 'sanctions', 'signals', 'memory', 'decision']);
    assert.ok(!caseB.stages.some((s) => s.name === STEP));
    assert.equal(caseB.memory.k, 3);
    assert.equal((await col('investigations').findOne({ _id: caseB.id })).harnessVersion, 1);

    const versions = await col('harness_versions').find({}).toArray();
    assert.deepEqual(versions.map((v) => [v._id, v.status]), [[1, 'active']]);
  });

  test('self-approval: the admin that initiated a case cannot confirm it (403, nothing written)', async () => {
    const own = await investigate(adminKey);
    const auditBefore = await col('audit_events').countDocuments({});
    const r = await call(adminKey, 'POST', `/v1/investigations/${own.id}/confirm`, { outcome: 'CONFIRMED_ACCOUNT_TAKEOVER', approveAdaptation: true });
    assert.equal(r.status, 403, JSON.stringify(r.body));
    assert.equal(r.body.error.code, 'FORBIDDEN');
    assert.equal((await col('investigations').findOne({ _id: own.id })).status, 'AWAITING_REVIEW');
    assert.equal((await col('security_memories').findOne({ _id: `mem_${own.id}` }))?.status, 'UNVERIFIED');
    assert.equal(await col('harness_versions').countDocuments({}), 1);
    assert.equal(await col('harness_events').countDocuments({}), 0);
    assert.equal(await col('audit_events').countDocuments({}), auditBefore);
    // The business party of the case is not an admin: 403 as well.
    assert.equal((await call(businessKey, 'POST', `/v1/investigations/${caseA.id}/confirm`, { outcome: 'CONFIRMED_ACCOUNT_TAKEOVER', approveAdaptation: true })).status, 403);
  });

  test('admin confirms case A as CONFIRMED_ACCOUNT_TAKEOVER: memory VERIFIED, harness v2 persisted with diff/evidence/approval', async () => {
    const admin = await app.services.apiKeys.authenticate(`Bearer ${adminKey}`);
    const r = await call(adminKey, 'POST', `/v1/investigations/${caseA.id}/confirm`, {
      outcome: 'CONFIRMED_ACCOUNT_TAKEOVER',
      approveAdaptation: true,
      note: 'Rotated key was attacker-controlled',
    });
    assert.equal(r.status, 200, JSON.stringify(r.body));
    confirmation = r.body;
    assert.equal(r.body.investigation.status, 'CONFIRMED');
    assert.equal(r.body.investigation.outcome, 'CONFIRMED_ACCOUNT_TAKEOVER');
    assert.deepEqual(r.body.memory, { id: `mem_${caseA.id}`, status: 'VERIFIED' });
    assert.equal(r.body.adaptation.applied, true);
    assert.deepEqual([r.body.adaptation.fromVersion, r.body.adaptation.toVersion], [1, 2]);
    assert.deepEqual(r.body.adaptation.diff, [
      { op: 'add', path: '/steps/5', value: STEP },
      { op: 'replace', path: '/memoryRetrieval/k', value: 5 },
    ]);

    const mem = await col('security_memories').findOne({ _id: `mem_${caseA.id}` });
    assert.equal(mem.status, 'VERIFIED');
    assert.equal(mem.outcome, 'CONFIRMED_ACCOUNT_TAKEOVER');
    assert.equal(mem.verifiedBy.role, 'admin');
    assert.equal(mem.verifiedBy.apiKeyId, admin.apiKeyId);
    assert.ok(mem.verifiedAt instanceof Date);
    assert.equal(mem.embedding.length, 1024);

    const [v1, v2] = await col('harness_versions').find({}).sort({ _id: 1 }).toArray();
    assert.equal(v1.status, 'superseded');
    assert.equal(v2.status, 'active');
    assert.equal(v2.version, 2);
    assert.equal(v2.parentVersion, 1);
    assert.ok(v2.policy.steps.includes(STEP));
    assert.equal(v2.policy.memoryRetrieval.k, 5);
    assert.deepEqual(v2.policy.memoryRetrieval.filter, { status: 'VERIFIED' });
    assert.deepEqual(v2.approvedBy, { role: 'admin', apiKeyId: admin.apiKeyId, ownerId: null });
    // Immutable invariants: same hash in v1, v2 and the runtime.
    assert.equal(v1.invariantsHash, INVARIANTS_HASH);
    assert.equal(v2.invariantsHash, v1.invariantsHash);

    const ev = await col('harness_events').findOne({ _id: r.body.adaptation.eventId });
    assert.ok(ev, 'harness_events document persisted');
    assert.equal(v2.sourceEventId, ev._id);
    assert.equal(ev.type, 'adaptation.applied');
    assert.deepEqual([ev.fromVersion, ev.toVersion], [1, 2]);
    assert.deepEqual(ev.diff, r.body.adaptation.diff);
    assert.deepEqual(ev.oldPolicy, v1.policy);
    assert.deepEqual(ev.newPolicy, v2.policy);
    assert.equal(ev.invariantsHash, INVARIANTS_HASH);
    assert.deepEqual(ev.evidence, [{ type: 'investigation', id: caseA.id }, { type: 'memory', id: `mem_${caseA.id}` }]);
    assert.deepEqual(ev.approvedBy, v2.approvedBy);
    assert.ok(ev.at instanceof Date && ev.approvedAt instanceof Date);
    const aud = await col('audit_events').findOne({ _id: ev.auditEventId });
    assert.equal(aud?.type, 'harness.adapted');
    assert.ok(await col('audit_events').findOne({ type: 'memory.promoted', subjectId: `mem_${caseA.id}` }));
    assert.equal((await call(adminKey, 'GET', '/v1/audit-events/integrity')).body.valid, true);

    const list = await call(businessKey, 'GET', '/v1/harness/versions');
    assert.equal(list.status, 200);
    assert.equal(list.body.invariantsHash, INVARIANTS_HASH);
    assert.deepEqual(list.body.data.map((v) => [v.version, v.status, v.invariantsHash]), [
      [2, 'active', INVARIANTS_HASH],
      [1, 'superseded', INVARIANTS_HASH],
    ]);

    // A second confirmation of the same case is refused.
    assert.equal((await call(adminKey, 'POST', `/v1/investigations/${caseA.id}/confirm`, { outcome: 'CONFIRMED_ACCOUNT_TAKEOVER', approveAdaptation: true })).status, 409);
  });

  test("equivalent case B' runs N+1 stages including signing_key_history_check under harness v2", async () => {
    assert.ok(confirmation, 'confirmation test ran');
    const b2 = await investigate(businessKey);
    assert.equal(b2.harnessVersion, 2);
    const names = b2.stages.map((s) => s.name);
    assert.equal(names.length, caseB.stages.length + 1);
    assert.deepEqual(names, ['identity', 'delegation', 'sanctions', 'signals', 'memory', STEP, 'decision']);
    const step = b2.stages.find((s) => s.name === STEP);
    assert.equal(step.engine, 'find+aggregate');
    assert.equal(step.status, 'flagged');
    assert.equal(step.result.currentThumbprint, treasuryBotKey('rotated').thumbprint);
    assert.equal(step.result.previousThumbprint, treasuryBotKey('original').thumbprint);
    assert.equal(step.result.settledTxWithCurrentKey, 0);
    assert.ok(Number.isInteger(step.result.rotatedWithinHours));
    assert.deepEqual(step.reasons, []);
    // Different context size: the memory stage now retrieves with k = 5.
    assert.equal(b2.memory.k, 5);
    assert.notEqual(b2.memory.k, caseB.memory.k);
    assert.equal(b2.riskDecision, 'REVIEW');
    const doc = await col('investigations').findOne({ _id: b2.id });
    assert.equal(doc.harnessVersion, 2);
    assert.equal(doc.stages.length, 7);
  });

  test('the promoted memory is retrievable from Atlas Vector Search as a VERIFIED precedent', async () => {
    const id = `mem_${caseA.id}`;
    const deadline = Date.now() + 90_000;
    let hit = null;
    while (!hit) {
      const r = await retrieveMemories({ db: store.db, signals: DEMO3_CASE.expectedSignals, k: 5, minScorePpm: 0 });
      hit = r.hits.find((h) => h.memoryId === id) ?? null;
      if (hit) break;
      if (Date.now() > deadline) throw new Error(`${id} was not returned by $vectorSearch in time`);
      await sleep(2_000);
    }
    assert.equal(hit.status, 'VERIFIED');
    assert.equal(hit.outcome, 'CONFIRMED_ACCOUNT_TAKEOVER');
  });
});
