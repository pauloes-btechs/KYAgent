// T17 Atlas acceptance (Demos 1 and 2): on the `make demo-reset` scenario, `scripts/demo.js
// --check --demo 1` (TreasuryBot, 1 500 USDC to its known counterparty) exits 0 with ALLOW and its
// issued passport ACTIVE, and `--demo 2` (30 000 USDC, over the 25 000 USDC delegation
// maximum) exits 0 with BLOCK / DELEGATION_MAX_EXCEEDED wrapping CONSTRAINT_VIOLATION while the
// identity stage still passes. Both investigations, their receipts and the receipt.issued anchors
// are then read back from Atlas through a separate client.
// Runs only when ATLAS_TEST_URI is set; uses a unique per-run database dropped afterwards.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { after, before, describe, test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { buildApp } from '../../src/app.js';
import { loadConfig } from '../../src/config.js';
import { DEMO1_CASE, DEMO2_CASE, DEMO_IDS, rotateTreasuryBotKey, seedHackathon, waitForSearchReady } from '../../src/seed/hackathon.js';
import { ensureSearchIndexes, loadSearchIndexDefs } from '../../src/store/searchIndexes.js';

const uri = process.env.ATLAS_TEST_URI;
const skip = uri ? false : 'ATLAS_TEST_URI not set';
const REPO_ROOT = fileURLToPath(new URL('../../', import.meta.url));

describe('atlas: Demo 1 (ALLOW + passport) and Demo 2 (BLOCK over delegation max)', { skip, timeout: 600_000 }, () => {
  let app;
  let store;
  let dbName;
  let client;

  const runDemo = (n) => {
    const env = { ...process.env, MONGODB_URI: uri, MONGODB_DB: dbName, PORT: '0', LOG_LEVEL: 'silent' };
    delete env.NODE_ENV;
    return spawnSync(process.execPath, ['scripts/demo.js', '--check', '--demo', String(n)], { cwd: REPO_ROOT, env, encoding: 'utf8', timeout: 180_000 });
  };
  const investigationsOf = (amount) =>
    client.db(dbName).collection('investigations').find({ agentId: DEMO_IDS.agent, 'transaction.amount': amount }).toArray();

  before(async () => {
    dbName = `kyagent_t17_${Date.now()}_${randomBytes(3).toString('hex')}`;
    const config = loadConfig({ NODE_ENV: 'test', LOG_LEVEL: 'silent', MONGODB_URI: uri, MONGODB_DB: dbName });
    const { MongoStore } = await import('../../src/store/mongo.js');
    store = new MongoStore(uri, dbName);
    app = buildApp({ config, store });
    await app.init(); // migrations, as demo-reset does
    assert.equal(store.kind, 'mongo');
    await seedHackathon(store.db);
    await ensureSearchIndexes(store.db, loadSearchIndexDefs(), { timeoutMs: 180_000 });
    await waitForSearchReady(store.db, { timeoutMs: 180_000 });
    const { MongoClient } = await import('mongodb');
    client = new MongoClient(uri, { serverSelectionTimeoutMS: 10_000 });
    await client.connect();
  });

  after(async () => {
    if (client) await client.close().catch(() => {});
    if (store?.db) await store.db.dropDatabase().catch(() => {});
    if (app) await app.close().catch(() => {});
  });

  test('make demo CHECK=1 DEMO=1: ALLOW / CLEAR, passport ACTIVE, receipt persisted', async () => {
    const child = runDemo(1);
    assert.equal(child.status, 0, `demo 1 failed:\n${child.stdout}\n${child.stderr}`);
    assert.match(child.stdout, /DEMO 1 OK/);
    assert.match(child.stdout, /passport {2}pp_TREASURYBOT ACTIVE agent=agt_TREASURYBOT delegation=grt_TB_USDC/);
    assert.match(child.stdout, /decision {2}ALLOW \(CLEAR\)/);

    const [inv, ...more] = await investigationsOf(DEMO1_CASE.context.amount);
    assert.equal(more.length, 0);
    assert.equal(inv.riskDecision, 'ALLOW');
    assert.equal(inv.decision, 'ALLOW');
    assert.equal(inv.reasons[0].code, 'CLEAR');
    assert.deepEqual(inv.signals, []);
    assert.equal(inv.delegationId, DEMO_IDS.delegation);
    assert.equal(inv.stages.find((s) => s.name === 'identity').status, 'passed');
    assert.equal(inv.stages.find((s) => s.name === 'delegation').status, 'passed');

    const receipt = await client.db(dbName).collection('receipts').findOne({ _id: inv.receiptId });
    assert.ok(receipt, 'Demo 1 receipt exists');
    assert.equal(receipt.riskDecision, 'ALLOW');
    assert.equal(receipt.receiptHash, inv.receiptHash);
    const anchor = await client.db(dbName).collection('audit_events').findOne({ _id: receipt.anchor.auditEventId });
    assert.equal(anchor.type, 'receipt.issued');
    assert.equal(anchor.data.receiptHash, receipt.receiptHash);

    const passport = await client.db(dbName).collection('passports').findOne({ _id: DEMO_IDS.passport });
    assert.equal(passport.status, 'ACTIVE');
    assert.equal(passport.agentId, DEMO_IDS.agent);
    assert.equal(passport.delegationId, DEMO_IDS.delegation);
    assert.deepEqual(passport.statusHistory.map((h) => h.status), ['ACTIVE']);
    // demo API keys are removed after the run
    assert.equal(await client.db(dbName).collection('api_keys').countDocuments({ demo: true }), 0);
  });

  test('make demo CHECK=1 DEMO=2: BLOCK / DELEGATION_MAX_EXCEEDED wrapping CONSTRAINT_VIOLATION, identity VERIFIED, receipt persisted', async () => {
    const child = runDemo(2);
    assert.equal(child.status, 0, `demo 2 failed:\n${child.stdout}\n${child.stderr}`);
    assert.match(child.stdout, /DEMO 2 OK/);
    assert.match(child.stdout, /identity {2}VERIFIED \(ALLOWED\) · action UNAUTHORIZED/);
    assert.match(child.stdout, /decision {2}BLOCK \(DELEGATION_MAX_EXCEEDED<-CONSTRAINT_VIOLATION/);

    const [inv, ...more] = await investigationsOf(DEMO2_CASE.context.amount);
    assert.equal(more.length, 0);
    assert.equal(inv.riskDecision, 'BLOCK');
    assert.equal(inv.decision, 'DENY');
    assert.equal(inv.reasons[0].code, 'DELEGATION_MAX_EXCEEDED');
    assert.equal(inv.reasons[0].identityReasonCode, 'CONSTRAINT_VIOLATION');
    assert.equal(inv.reasons[0].invariantId, 'INV_DELEGATION_MAX');
    assert.equal(inv.stages.find((s) => s.name === 'identity').status, 'passed');
    assert.equal(inv.stages.find((s) => s.name === 'delegation').status, 'failed');

    const receipt = await client.db(dbName).collection('receipts').findOne({ _id: inv.receiptId });
    assert.ok(receipt, 'Demo 2 receipt exists');
    assert.equal(receipt.riskDecision, 'BLOCK');
    assert.equal(receipt.receiptHash, inv.receiptHash);
    const anchor = await client.db(dbName).collection('audit_events').findOne({ _id: receipt.anchor.auditEventId });
    assert.equal(anchor.data.receiptHash, receipt.receiptHash);
    assert.equal((await client.db(dbName).collection('passports').findOne({ _id: DEMO_IDS.passport })).status, 'ACTIVE');
  });

  test('Demo 1 refuses to run on a non-pristine scenario (rotated key) and exits non-zero', async () => {
    await rotateTreasuryBotKey(store.db);
    const child = runDemo(1);
    assert.notEqual(child.status, 0);
    assert.match(child.stderr, /DEMO 1 MISMATCH[\s\S]*make demo-reset/);
  });
});
