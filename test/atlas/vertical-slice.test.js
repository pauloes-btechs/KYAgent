// T14 Atlas acceptance: DELIVERY_PLAN.md §4 "New minimum vertical slice". One agent action goes
// through the real HTTP API on MongoStore: identity -> delegation -> sanctions ($search) ->
// signals -> memory ($vectorSearch) -> policy -> decision, is persisted with its receipt (anchored
// by a `receipt.issued` audit event), and then a sanctions data change is picked up by the change
// stream watcher, which re-screens the agent and moves its passport ACTIVE -> RE_SCREENING -> SUSPENDED.
// `atlasWorld()` is the `make demo-reset` equivalent on a unique database (dropped afterwards).
// Runs only when ATLAS_TEST_URI is set.
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { after, test } from 'node:test';
import { applySanctionsUpdate, updateIdOf } from '../../scripts/apply-sanctions-update.js';
import { buildApp } from '../../src/app.js';
import { loadConfig } from '../../src/config.js';
import { generateApiKey, hashApiKeySecret } from '../../src/crypto/apiKeys.js';
import { retrieveMemories } from '../../src/memory/retrieve.js';
import { buildVerifyRequest } from '../../src/sdk/agentSigner.js';
import { DEMO3_CASE, DEMO_IDS, USDC, rotateTreasuryBotKey, seedHackathon, treasuryBotKey } from '../../src/seed/hackathon.js';
import { ensureSearchIndexes, loadSearchIndexDefs } from '../../src/store/searchIndexes.js';
import { SanctionsWatcher } from '../../src/watchers/sanctionsWatcher.js';

const uri = process.env.ATLAS_TEST_URI;
const skip = uri ? false : 'ATLAS_TEST_URI not set';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const silent = { debug() {}, info() {}, warn() {}, error() {} };
// '0xNEWCOUNTERPARTY…' of the plan: a well-formed address TreasuryBot has never paid.
const NEW_COUNTERPARTY = '0x9e3a0000000000000000000000000000000c0de1';

const cleanups = [];
after(async () => {
  for (const fn of cleanups.reverse()) await Promise.resolve().then(fn).catch(() => {});
});

async function atlasWorld() {
  const dbName = `kyagent_t14_${Date.now()}_${randomBytes(3).toString('hex')}`;
  const adminKey = generateApiKey().plaintext;
  const config = loadConfig({ NODE_ENV: 'test', LOG_LEVEL: 'silent', MONGODB_URI: uri, MONGODB_DB: dbName, KYA_BOOTSTRAP_ADMIN_API_KEY: adminKey });
  const { MongoStore } = await import('../../src/store/mongo.js');
  const store = new MongoStore(uri, dbName);
  const app = buildApp({ config, store });
  cleanups.push(() => app.close());
  cleanups.push(() => store.db.dropDatabase());
  await app.init(); // migrations 001–008
  assert.equal(store.kind, 'mongo');
  assert.equal(store.capabilities.changeStreams, true, 'Atlas must support change streams');

  await seedHackathon(store.db);
  await rotateTreasuryBotKey(store.db); // the takeover precondition: a newly rotated signing key
  const biz = generateApiKey();
  await store.apiKeys.insert({
    id: biz.keyId,
    name: 'vertical slice business',
    role: 'business',
    ownerId: DEMO_IDS.business,
    secretHash: hashApiKeySecret(config.pepper, biz.secret),
    status: 'active',
    createdAt: new Date(),
    lastUsedAt: null,
    revokedAt: null,
    demo: true,
  });
  await ensureSearchIndexes(store.db, loadSearchIndexDefs(), { timeoutMs: 180_000 });
  const deadline = Date.now() + 120_000;
  for (;;) {
    const r = await retrieveMemories({ db: store.db, signals: DEMO3_CASE.expectedSignals, minScorePpm: 0 }).catch(() => null);
    if (r && r.hits.length >= 2) break;
    if (Date.now() > deadline) throw new Error('memory_vector did not index the seeded memories in time');
    await sleep(2_000);
  }

  const { port } = await app.listen(0, '127.0.0.1');
  const base = `http://127.0.0.1:${port}`;
  const watcher = new SanctionsWatcher({ store, audit: app.services.audit, events: app.events, logger: silent });
  await watcher.start();
  cleanups.push(() => watcher.stop());

  const agentByName = async (name) => {
    const a = await store.db.collection('agents').findOne({ name });
    assert.ok(a, `agent ${name} is seeded`);
    return a;
  };

  return {
    db: store.db,
    rotatedKey: treasuryBotKey('rotated').privateKey,

    /** Signed PaymentContext through POST /v1/investigations (trigger `api`); amount in whole USDC. */
    async investigate(name, { action, asset, amount, to, signingKey }) {
      const agent = await agentByName(name);
      const body = buildVerifyRequest(signingKey, {
        agentId: agent._id,
        audience: DEMO_IDS.business,
        action,
        context: { amount: amount * USDC, currency: asset, counterparty: to },
      });
      const res = await fetch(`${base}/v1/investigations`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${biz.plaintext}`, 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      const inv = await res.json();
      assert.equal(res.status, 201, JSON.stringify(inv));
      return { ...inv, investigationId: inv.id };
    },

    async auditHas(type, investigationId) {
      return Boolean(await store.db.collection('audit_events').findOne({ type, 'data.investigationId': investigationId }));
    },

    applySanctionsUpdate: (id) => applySanctionsUpdate(store, updateIdOf(id), { audit: app.services.audit }),

    async waitForPassport(name, status, { timeoutMs }) {
      const agent = await agentByName(name);
      const until = Date.now() + timeoutMs;
      for (;;) {
        const p = await store.db.collection('passports').findOne({ agentId: agent._id });
        if (p?.status === status) return p;
        if (Date.now() > until) throw new Error(`passport of ${name} is ${p?.status ?? 'missing'}, expected ${status} within ${timeoutMs} ms`);
        await sleep(200);
      }
    },
  };
}

test(
  'vertical slice: agent action -> Atlas -> Search -> signals -> Vector memory -> invariants+harness -> decision -> receipt -> persisted; then sanctions change -> watcher -> re-eval -> passport SUSPENDED',
  { skip, timeout: 600_000 },
  async () => {
    const w = await atlasWorld(); // make demo-reset equivalent on a unique db name
    // 1. action
    const r = await w.investigate('TreasuryBot', { action: 'payments:create', asset: 'USDC', amount: 24_000, to: NEW_COUNTERPARTY, signingKey: w.rotatedKey });
    // 2..5 stages present, in order, each with evidence
    assert.deepEqual(r.stages.map((s) => s.name), ['identity', 'delegation', 'sanctions', 'signals', 'memory', 'policy', 'decision']);
    assert.equal(r.stages[2].engine, '$search');
    assert.ok(r.signals.includes('SIGNING_KEY_CHANGED') && r.signals.includes('NEW_COUNTERPARTY'));
    assert.equal(r.memory.engine, '$vectorSearch');
    assert.equal(r.memory.hits[0].memoryId, 'mem_INV-1042');
    assert.equal(r.memory.hits[0].status, 'VERIFIED');
    assert.equal(r.riskDecision, 'REVIEW'); // precedent escalates; invariants did not block
    // 6..7 receipt + persistence
    const inv = await w.db.collection('investigations').findOne({ _id: r.investigationId });
    assert.equal(inv.receipt.harnessVersion, 1);
    assert.ok(inv.receipt.sanctionsDatasetVersion);
    assert.ok(await w.auditHas('receipt.issued', r.investigationId));
    // data change -> change stream -> re-eval -> trust state
    await w.applySanctionsUpdate('2026-09-26'); // adds TreasuryBot's counterparty wallet
    const p = await w.waitForPassport('TreasuryBot', 'SUSPENDED', { timeoutMs: 15000 });
    assert.deepEqual(p.statusHistory.map((h) => h.status), ['ACTIVE', 'RE_SCREENING', 'SUSPENDED']);
  },
);

test('vertical slice detail: evidence per stage, policy stage, receipt integrity, re-screen receipt', { skip, timeout: 600_000 }, async () => {
  const w = await atlasWorld();
  const r = await w.investigate('TreasuryBot', { action: 'payments:create', asset: 'USDC', amount: 24_000, to: NEW_COUNTERPARTY, signingKey: w.rotatedKey });
  for (const name of ['identity', 'delegation', 'sanctions', 'signals', 'memory', 'policy']) {
    assert.ok(r.stages.find((s) => s.name === name).evidence.length > 0, `${name} has evidence`);
  }
  assert.deepEqual([...r.signals].sort(), ['AMOUNT_ANOMALY', 'NEAR_CEILING', 'NEW_COUNTERPARTY', 'SIGNING_KEY_CHANGED']);
  assert.ok(r.memory.hits.every((h) => h.status === 'VERIFIED' && h.memoryId !== 'mem_INV-1101'));

  const policy = r.stages.find((s) => s.name === 'policy');
  assert.equal(policy.status, 'flagged');
  assert.equal(policy.result.harnessVersion, 1);
  assert.equal(policy.result.passportStatus, 'ACTIVE');
  assert.deepEqual(policy.result.escalationsFired, ['precedent_takeover']);
  const held = Object.fromEntries(policy.result.invariants.map((i) => [i.id, i.held]));
  assert.equal(held.INV_SANCTIONS_EXACT_BLOCK, true);
  assert.equal(held.INV_DELEGATION_MAX, true);
  assert.equal(r.reasons[0].code, 'MEMORY_PRECEDENT_TAKEOVER');
  assert.equal(r.reasons[0].stage, 'policy');
  assert.equal(r.decision, 'DENY'); // identity-layer vocabulary: anything but ALLOW is DENY

  const inv = await w.db.collection('investigations').findOne({ _id: r.investigationId });
  const stored = await w.db.collection('receipts').findOne({ _id: inv.receiptId });
  assert.ok(stored, 'receipt persisted in receipts');
  assert.equal(stored.receiptHash, inv.receiptHash);
  assert.equal(inv.receipt.riskDecision, 'REVIEW');
  assert.equal(inv.receipt.sanctionsDatasetVersion, '2026-09-01');
  assert.deepEqual(inv.receipt.memory.hits.map((h) => h.memoryId).slice(0, 1), ['mem_INV-1042']);
  assert.equal(inv.receipt.memory.hits[0].usedAsPrecedent, true);
  const anchor = await w.db.collection('audit_events').findOne({ _id: inv.receipt.anchor.auditEventId });
  assert.equal(anchor.type, 'receipt.issued');
  assert.equal(anchor.data.receiptHash, inv.receiptHash);
  const { receiptHashOf } = await import('../../src/services/receipts.js');
  const { _id, agentId, ...body } = stored;
  assert.equal(receiptHashOf({ ...body, receiptId: _id }), stored.receiptHash);
  assert.notEqual(receiptHashOf({ ...body, receiptId: _id, riskDecision: 'ALLOW' }), stored.receiptHash, 'tampering changes the hash');

  await w.applySanctionsUpdate('2026-09-26');
  const p = await w.waitForPassport('TreasuryBot', 'SUSPENDED', { timeoutMs: 15000 });
  const rescreen = await w.db.collection('investigations').findOne({ _id: p.lastInvestigationId });
  assert.equal(rescreen.trigger, 'sanctions_change');
  assert.equal(rescreen.riskDecision, 'BLOCK');
  assert.deepEqual(rescreen.stages.map((s) => s.name), ['identity', 'delegation', 'sanctions', 'signals', 'memory', 'policy', 'decision']);
  assert.equal(rescreen.receipt.sanctionsDatasetVersion, '2026-09-26');
  assert.ok(await w.auditHas('receipt.issued', rescreen._id));
});
