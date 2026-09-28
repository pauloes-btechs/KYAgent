// T11 Atlas acceptance (Demo 4, gate `change_stream`): a real MongoDB change stream on
// `sanctions` drives continuous KYA. Applying `upd_2026-09-26` (scripts/apply-sanctions-update.js)
// makes TreasuryBot's passport history [ACTIVE, RE_SCREENING, SUSPENDED] within 15 s, with a
// `sanctions_change` investigation, audit events and SSE events on GET /v1/events/stream. Killing
// the watcher mid-way and starting a new one resumes from the persisted token without missing
// the event; failures inside the long-running loop are retried in place, and a poison event is
// dead-lettered (passport failed closed) without blocking later sanctions changes.
// Runs only when ATLAS_TEST_URI is set; uses a unique per-run database dropped afterwards.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { after, before, describe, test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { applySanctionsUpdate, DEFAULT_UPDATE_ID } from '../../scripts/apply-sanctions-update.js';
import { buildApp } from '../../src/app.js';
import { loadConfig } from '../../src/config.js';
import { generateApiKey } from '../../src/crypto/apiKeys.js';
import { auditService } from '../../src/services/audit.js';
import { buildHackathonDocs, DEMO_IDS, seedHackathon } from '../../src/seed/hackathon.js';
import { ensureSearchIndexes, loadSearchIndexDefs } from '../../src/store/searchIndexes.js';
import { changeEventId, SanctionsWatcher, WATCHER_ID } from '../../src/watchers/sanctionsWatcher.js';

const uri = process.env.ATLAS_TEST_URI;
const skip = uri ? false : 'ATLAS_TEST_URI not set';
const REPO_ROOT = fileURLToPath(new URL('../../', import.meta.url));
const SDN = 'sdn_MERIDIAN_OTC';
const DEADLINE_MS = 15_000;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const silent = { debug() {}, info() {}, warn() {}, error() {} };

function runScript(env) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, ['scripts/apply-sanctions-update.js', DEFAULT_UPDATE_ID], { cwd: REPO_ROOT, env });
    let out = '';
    child.stdout.on('data', (d) => (out += d));
    child.stderr.on('data', (d) => (out += d));
    child.on('close', (code) => resolve({ code, out }));
  });
}

async function openStream(base, key) {
  const ac = new AbortController();
  const res = await fetch(`${base}/v1/events/stream`, { headers: { authorization: `Bearer ${key}` }, signal: ac.signal });
  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  const state = { text: '' };
  (async () => {
    for (;;) {
      const r = await reader.read().catch(() => ({ done: true }));
      if (r.done) return;
      state.text += decoder.decode(r.value, { stream: true });
    }
  })();
  const frames = () => [...state.text.matchAll(/event: (\S+)\ndata: (.*)\n\n/g)].map((m) => ({ event: m[1], data: JSON.parse(m[2]) }));
  return { res, frames, abort: () => ac.abort() };
}

describe('atlas: sanctions change stream -> re-screen -> passport SUSPENDED (Demo 4)', { skip, timeout: 600_000 }, () => {
  let app;
  let store;
  let base;
  let dbName;
  let adminKey;
  let watcher;
  const extraStores = [];

  const db = () => store.db;
  const passport = () => db().collection('passports').findOne({ _id: DEMO_IDS.passport });
  const watcherState = () => db().collection('watcher_state').findOne({ _id: WATCHER_ID });
  const newStore = async () => {
    const { MongoStore } = await import('../../src/store/mongo.js');
    const s = new MongoStore(uri, dbName);
    await s.init();
    extraStores.push(s);
    return s;
  };
  const newWatcher = (s, opts = {}) => new SanctionsWatcher({ store: s, audit: auditService({ store: s, clock: { now: () => new Date() } }), logger: silent, retryDelayMs: 100, ...opts });

  async function waitFor(fn, { timeoutMs, what }) {
    const deadline = Date.now() + timeoutMs;
    for (;;) {
      const v = await fn();
      if (v) return v;
      if (Date.now() > deadline) throw new Error(`timeout waiting for ${what}`);
      await sleep(200);
    }
  }
  const waitForStatus = (status, timeoutMs = DEADLINE_MS) => waitFor(async () => ((await passport())?.status === status ? passport() : null), { timeoutMs, what: `passport ${status}` });

  /** Restore the pre-update scenario without touching unrelated sanctions docs (no change events for TreasuryBot). */
  async function resetScenario() {
    const [seedPassport] = buildHackathonDocs().passports;
    await db().collection('passports').replaceOne({ _id: seedPassport._id }, seedPassport, { upsert: true });
    await db().collection('sanctions').deleteOne({ _id: SDN });
    await db().collection('sanctions_updates').updateOne({ _id: DEFAULT_UPDATE_ID }, { $set: { status: 'staged', appliedAt: null } });
    await db().collection('investigations').deleteMany({ trigger: 'sanctions_change' });
  }

  before(async () => {
    dbName = `kyagent_t11_${Date.now()}_${randomBytes(3).toString('hex')}`;
    adminKey = generateApiKey().plaintext;
    const config = loadConfig({ NODE_ENV: 'test', LOG_LEVEL: 'silent', MONGODB_URI: uri, MONGODB_DB: dbName, KYA_BOOTSTRAP_ADMIN_API_KEY: adminKey });
    const { MongoStore } = await import('../../src/store/mongo.js');
    store = new MongoStore(uri, dbName);
    app = buildApp({ config, store });
    await app.init();
    assert.equal(store.kind, 'mongo');
    assert.equal(store.capabilities.changeStreams, true, 'Atlas must support change streams');
    await seedHackathon(store.db);
    // The sanctions stage also screens counterparty names with $search (sanctions_search).
    await ensureSearchIndexes(store.db, loadSearchIndexDefs().filter((d) => d.collection === 'sanctions'), { timeoutMs: 180_000 });
    const { port } = await app.listen(0, '127.0.0.1');
    base = `http://127.0.0.1:${port}`;
    watcher = new SanctionsWatcher({ store, audit: app.services.audit, events: app.events, logger: silent });
    await watcher.start();
  });

  after(async () => {
    await watcher?.stop().catch(() => {});
    if (store?.db) await store.db.dropDatabase().catch(() => {});
    for (const s of extraStores) await s.close().catch(() => {});
    if (app) await app.close().catch(() => {});
  });

  test('apply-sanctions-update -> ACTIVE, RE_SCREENING, SUSPENDED within 15 s; investigation, audit and SSE events', async () => {
    assert.equal((await passport()).status, 'ACTIVE');
    const sse = await openStream(base, adminKey);
    try {
      assert.equal(sse.res.status, 200);
      const env = { ...process.env, MONGODB_URI: uri, MONGODB_DB: dbName, LOG_LEVEL: 'silent' };
      const run = await runScript(env);
      assert.equal(run.code, 0, run.out);
      assert.match(run.out, /upd_2026-09-26 applied/);
      assert.ok(!run.out.includes(uri), 'the script must never print MONGODB_URI');

      const sanctioned = await db().collection('sanctions').findOne({ _id: SDN });
      assert.equal(sanctioned.datasetVersion, '2026-09-26');
      const insertedAt = sanctioned.updatedAt.getTime();
      const p = await waitForStatus('SUSPENDED', DEADLINE_MS + 5_000);
      assert.deepEqual(p.statusHistory.map((h) => h.status), ['ACTIVE', 'RE_SCREENING', 'SUSPENDED']);
      const elapsed = p.statusHistory[2].at.getTime() - insertedAt;
      assert.ok(elapsed >= 0 && elapsed < DEADLINE_MS, `SUSPENDED ${elapsed} ms after the sanctions insert`);
      assert.equal(p.statusReason, 'SANCTIONS_EXACT_MATCH');
      assert.equal(p.statusHistory[1].actor.role, 'system');

      const inv = await db().collection('investigations').findOne({ _id: p.lastInvestigationId });
      assert.ok(inv, 'investigation persisted');
      assert.equal(inv.trigger, 'sanctions_change');
      assert.equal(inv.agentId, DEMO_IDS.agent);
      assert.equal(inv.triggerRef.sanctionsId, SDN);
      assert.equal(inv.triggerRef.datasetVersion, '2026-09-26');
      assert.equal(inv.riskDecision, 'BLOCK');
      assert.equal(inv.reasons[0].code, 'SANCTIONS_EXACT_MATCH');
      assert.equal(inv.transaction.amount, null);
      const sanctionsStage = inv.stages.find((s) => s.name === 'sanctions');
      assert.equal(sanctionsStage.engine, '$search');
      assert.ok(sanctionsStage.result.exactHits.some((h) => h.sanctionsId === SDN && h.address === '0x4b1d000000000000000000000000000000000b02'));
      assert.equal(inv.stages.find((s) => s.name === 'identity').result.mode, 'state');

      const audit = await db().collection('audit_events').find({}).sort({ seq: 1 }).toArray();
      const types = audit.map((e) => e.type);
      assert.ok(types.includes('sanctions.updated'));
      assert.ok(audit.some((e) => e.type === 'investigation.decided' && e.subjectId === inv._id && e.data.trigger === 'sanctions_change'));
      assert.deepEqual(
        audit.filter((e) => e.type === 'passport.status_changed').map((e) => [e.data.fromStatus, e.data.toStatus]),
        [['ACTIVE', 'RE_SCREENING'], ['RE_SCREENING', 'SUSPENDED']],
      );

      const state = await watcherState();
      assert.ok(state.resumeToken, 'resume token persisted');
      assert.equal(state.lastDatasetVersion, '2026-09-26');
      assert.equal(state.lastChangeEventId, inv.triggerRef.changeEventId);

      await waitFor(() => sse.frames().some((f) => f.event === 'passport_suspended'), { timeoutMs: 5_000, what: 'SSE passport_suspended' });
      const events = sse.frames().map((f) => f.event);
      for (const e of ['change_detected', 'affected_agent', 'rescreen_started', 'passport_suspended']) assert.ok(events.includes(e), `SSE ${e}`);
      for (const e of ['sanctions.change_detected', 'passport.status_changed', 'investigation.decided']) assert.ok(events.includes(e), `SSE ${e}`);
      const order = ['change_detected', 'affected_agent', 'rescreen_started', 'passport_suspended'].map((e) => events.indexOf(e));
      assert.deepEqual([...order].sort((a, b) => a - b), order, `Demo 4 steps in order: ${events.join(', ')}`);
      const affected = sse.frames().find((f) => f.event === 'affected_agent').data;
      assert.equal(affected.agentId, DEMO_IDS.agent);
      assert.deepEqual(affected.viaCounterparty, ['0x4b1d000000000000000000000000000000000b02']);
    } finally {
      sse.abort();
    }
  });

  test('re-applying the update is idempotent', async () => {
    const r = await applySanctionsUpdate(store, DEFAULT_UPDATE_ID);
    assert.equal(r.status, 'already_applied');
  });

  test('killing the watcher mid-way and restarting resumes from the persisted token without missing the event', async () => {
    await watcher.stop(); // graceful: its last token is persisted
    await resetScenario();
    const before = await watcherState();

    // Watcher A "crashes" right after moving the passport to RE_SCREENING (the handler hangs, then is killed).
    const storeA = await newStore();
    let reached;
    const reachedP = new Promise((r) => (reached = r));
    const a = newWatcher(storeA, {
      hooks: {
        onStep: (step) => {
          if (step !== 'rescreen_started') return undefined;
          reached();
          return new Promise(() => {}); // never completes
        },
      },
    });
    await a.start();
    const applied = await applySanctionsUpdate(store, DEFAULT_UPDATE_ID);
    assert.equal(applied.status, 'applied');
    await Promise.race([reachedP, sleep(DEADLINE_MS).then(() => assert.fail('watcher A never reached the re-screen'))]);
    assert.equal((await passport()).status, 'RE_SCREENING');
    a.kill();
    await storeA.close();

    // Nothing was checkpointed for the in-flight event.
    const mid = await watcherState();
    assert.equal(mid.lastChangeEventId, before.lastChangeEventId);
    assert.deepEqual(mid.resumeToken, before.resumeToken);
    assert.equal(await db().collection('investigations').countDocuments({ trigger: 'sanctions_change' }), 0);

    // Watcher B (new client, new process state) resumes from the token and finishes the re-screen.
    const storeB = await newStore();
    const b = newWatcher(storeB);
    const t0 = Date.now();
    await b.start();
    try {
      const p = await waitForStatus('SUSPENDED');
      assert.ok(Date.now() - t0 < DEADLINE_MS);
      assert.deepEqual(p.statusHistory.map((h) => h.status), ['ACTIVE', 'RE_SCREENING', 'SUSPENDED']);
      const invs = await db().collection('investigations').find({ trigger: 'sanctions_change' }).toArray();
      assert.equal(invs.length, 1);
      assert.equal(invs[0].triggerRef.sanctionsId, SDN);
      const state = await waitFor(async () => {
        const s = await watcherState();
        return s.lastChangeEventId === invs[0].triggerRef.changeEventId ? s : null;
      }, { timeoutMs: 5_000, what: 'token checkpoint' });
      assert.notDeepEqual(state.resumeToken, before.resumeToken);
      assert.equal(state.lastChangeEventId, changeEventId(state.resumeToken));
    } finally {
      await b.stop();
    }
  });

  test('two consecutive failures inside the running loop are retried in place; the event is processed once', async () => {
    await resetScenario();
    const s = await newStore();
    let calls = 0;
    const w = newWatcher(s, {
      maxAttempts: 3,
      hooks: {
        onStep: (step) => {
          if (step !== 'investigation_recorded') return;
          calls += 1;
          if (calls <= 2) throw new Error(`transient failure ${calls}`);
        },
      },
    });
    await w.start();
    try {
      await sleep(1_500); // the stream is open and idle: the event arrives inside the long-running loop
      await applySanctionsUpdate(store, DEFAULT_UPDATE_ID);
      const p = await waitForStatus('SUSPENDED');
      assert.equal(calls, 3);
      assert.deepEqual(p.statusHistory.map((h) => h.status), ['ACTIVE', 'RE_SCREENING', 'SUSPENDED']);
      assert.equal(await db().collection('investigations').countDocuments({ trigger: 'sanctions_change' }), 1);
      const inv = await db().collection('investigations').findOne({ trigger: 'sanctions_change' });
      await waitFor(async () => (await watcherState()).lastChangeEventId === inv.triggerRef.changeEventId, { timeoutMs: 5_000, what: 'token checkpoint' });
      assert.equal(w.stats.deadLettered, 0);
    } finally {
      await w.stop();
    }
  });

  test('a poison event is dead-lettered (passport failed closed) and later sanctions changes are still processed', async () => {
    await resetScenario();
    const s = await newStore();
    let failures = 0;
    const w = newWatcher(s, {
      maxAttempts: 2,
      hooks: {
        onStep: (step, ctx) => {
          if (step === 'rescreen_started' && ctx.triggerRef.sanctionsId === SDN) {
            failures += 1;
            throw new Error('poison');
          }
        },
      },
    });
    await w.start();
    try {
      await sleep(1_500);
      await applySanctionsUpdate(store, DEFAULT_UPDATE_ID);
      const p = await waitForStatus('SUSPENDED');
      assert.equal(failures, 2);
      assert.deepEqual(p.statusHistory.map((h) => h.status), ['ACTIVE', 'RE_SCREENING', 'SUSPENDED']);
      assert.equal(p.statusReason, 'INTERNAL_ERROR');
      const state = await waitFor(async () => {
        const st = await watcherState();
        return st.deadLetters?.some((d) => d.sanctionsId === SDN) ? st : null;
      }, { timeoutMs: 5_000, what: 'dead letter' });
      const dl = state.deadLetters.find((d) => d.sanctionsId === SDN);
      assert.equal(dl.attempts, 2);
      assert.match(dl.error, /poison/);
      assert.deepEqual(dl.failedClosedAgentIds, [DEMO_IDS.agent]);

      // A later, unrelated sanctions change is processed (the poison event does not block the stream).
      await db().collection('sanctions').insertOne({
        _id: 'sdn_T11_PROBE',
        name: 'T11 Probe Entity',
        aliases: [],
        type: 'entity',
        programs: ['CYBER2'],
        wallets: [{ chain: 'evm', address: '0x9e9e00000000000000000000000000000000e001' }],
        datasetVersion: '2026-09-27',
        source: 'fixture',
        demo: true,
      });
      await waitFor(async () => (await watcherState()).lastDatasetVersion === '2026-09-27', { timeoutMs: DEADLINE_MS, what: 'later event processed' });
      assert.equal(w.stats.processed, 1);
      assert.equal(w.stats.deadLettered, 1);
    } finally {
      await w.stop();
    }
  });
});
