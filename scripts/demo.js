// Live demo (`make demo`): serves the KYAgent API + dashboard on MongoDB Atlas via MongoStore,
// over the judging scenario restored by `make demo-reset` (src/seed/hackathon.js). There is
// no in-memory fallback: without MONGODB_URI, or on a deployment without Atlas Search, it
// exits 1 ("Atlas required").
//
//   make demo            start the API, print the dashboard URL and demo-only API keys
//   make demo CHECK=1    headless: verify the scenario and both search indexes, then exit
//   make demo DEMO=1     run Demo 1 (clean TreasuryBot payment, 1 500 USDC to a known
//                        counterparty) through POST /v1/investigations: ALLOW / CLEAR, persisted
//                        receipt, TreasuryBot's passport ACTIVE
//   make demo DEMO=2     run Demo 2 (30 000 USDC, over the 25 000 USDC delegation maximum):
//                        BLOCK DELEGATION_MAX_EXCEEDED wrapping CONSTRAINT_VIOLATION, with a
//                        receipt; identity VERIFIED, action UNAUTHORIZED
//   make demo DEMO=3     run Demo 3 (verified security memory) through POST /v1/investigations
//                        on Atlas, print signals / memory hits / decision; exit 1 on mismatch
//                        (`make demo CHECK=1 DEMO=n` is the same run, used as the acceptance gate)
//
// Demos 1 and 2 need the pristine scenario (original key, passport ACTIVE): run them after
// `make demo-reset` and before Demo 3 (key rotation) / Demo 4 (sanctions update).
//
// Demo API keys are inserted directly as HMAC hashes tagged `demo: true` (no audit events
// are written for them) and are deleted by the next `make demo` or `make demo-reset`.
import { buildApp } from '../src/app.js';
import { ConfigError, loadConfig } from '../src/config.js';
import { generateApiKey, hashApiKeySecret } from '../src/crypto/apiKeys.js';
import { buildVerifyRequest } from '../src/sdk/agentSigner.js';
import {
  DEMO1_CASE,
  DEMO2_CASE,
  DEMO3_CASE,
  DEMO_IDS,
  buildHackathonDocs,
  collectionCounts,
  expectedCounts,
  probeSearch,
  rotateTreasuryBotKey,
  treasuryBotKey,
} from '../src/seed/hackathon.js';
import { MongoStore } from '../src/store/mongo.js';

const fail = (msg) => {
  process.stderr.write(`${msg}\n`);
  process.exit(1);
};

if (process.env.NODE_ENV === 'production') fail('The demo is not available with NODE_ENV=production');
if (!process.env.MONGODB_URI) {
  fail('Atlas required: set MONGODB_URI to the MongoDB Atlas connection string and run make demo-reset first. The demo never runs on the in-memory store.');
}
const check = process.argv.includes('--check');
const demoIdx = process.argv.indexOf('--demo');
const demoN = demoIdx === -1 ? null : process.argv[demoIdx + 1];
const DEMOS = ['1', '2', '3'];
if (demoN !== null && !DEMOS.includes(demoN)) fail(`Unknown demo "${demoN ?? ''}" (available: ${DEMOS.join(', ')})`);

let config;
try {
  config = loadConfig({
    ...process.env,
    NODE_ENV: 'development',
    HOST: process.env.HOST || '127.0.0.1',
    PORT: process.env.PORT || '8080',
    LOG_LEVEL: process.env.LOG_LEVEL || 'warn',
  });
} catch (err) {
  if (!(err instanceof ConfigError)) throw err;
  fail(`Configuration error: ${err.message}`);
}

const store = new MongoStore(config.mongoUri, config.mongoDb);
const app = buildApp({ config, store });
try {
  await app.init();
} catch (err) {
  await store.close().catch(() => {});
  fail(`Atlas required: could not connect to MongoDB (${err.message})`);
}
if (store.kind !== 'mongo' || !store.capabilities.atlasSearch) {
  await store.close();
  fail('Atlas required: the connected MongoDB deployment does not support Atlas Search / Vector Search');
}

// The judging scenario must be exactly what demo-reset seeds.
const docs = buildHackathonDocs();
const expected = expectedCounts(docs);
const counts = await collectionCounts(store.db);
const seededMismatch = ['operators', 'businesses', 'agents', 'security_memories', 'sanctions_updates'].filter((c) => counts[c] !== expected[c]);
if (seededMismatch.length) {
  await store.close();
  fail(`Demo scenario not loaded (${seededMismatch.map((c) => `${c}=${counts[c]}/${expected[c]}`).join(', ')}): run make demo-reset`);
}

async function installKey(name, role, ownerId) {
  const { keyId, secret, plaintext } = generateApiKey();
  await store.apiKeys.insert({
    id: keyId,
    name,
    role,
    ownerId,
    secretHash: hashApiKeySecret(config.pepper, secret),
    status: 'active',
    createdAt: new Date(),
    lastUsedAt: null,
    revokedAt: null,
    demo: true,
  });
  return { keyId, plaintext };
}

async function postJson(port, path, key, body) {
  const res = await fetch(`http://127.0.0.1:${port}${path}`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${key}`, 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  return { status: res.status, body: await res.json() };
}

const usdc = (n) => (n / 1_000_000).toLocaleString('en-US');

/**
 * Demos 1 and 2: TreasuryBot, signed with its registered (original) key, pays its established
 * counterparty A through POST /v1/investigations on Atlas. The signed identity stage runs the
 * /v1/verify steps 1–8 and the delegation stage carries the /v1/verify reason code it wraps
 * (Demo 2: CONSTRAINT_VIOLATION). /v1/verify itself is not called: its RESOURCE_ID_RE only accepts
 * ULID ids, not the fixed demo ids, and it stays byte-compatible. The investigation, its receipt
 * and the passport issued to TreasuryBot for grt_TB_USDC are read back from Atlas.
 */
async function runDemo12(n, demoCase) {
  const t0 = Date.now();
  const problems = [];
  const expect = (ok, msg) => ok || problems.push(msg);
  const original = treasuryBotKey('original');
  const agent = await store.db.collection('agents').findOne({ _id: DEMO_IDS.agent });
  const passportBefore = await store.db.collection('passports').findOne({ _id: DEMO_IDS.passport });
  if (agent?.keyThumbprint !== original.thumbprint || passportBefore?.status !== 'ACTIVE') {
    return [`Demo ${n} needs the pristine scenario (TreasuryBot original key, passport ACTIVE; found passport ${passportBefore?.status ?? 'missing'}): run make demo-reset`];
  }

  const { port } = await app.listen(0, '127.0.0.1');
  const installed = [];
  try {
    const business = await installKey(`demo ${n} business (CirclePay)`, 'business', DEMO_IDS.business);
    installed.push(business.keyId);
    const signed = () =>
      buildVerifyRequest(original.privateKey, {
        agentId: DEMO_IDS.agent,
        audience: DEMO_IDS.business,
        action: demoCase.action,
        context: { ...demoCase.context },
      });

    const title = n === '1' ? 'clean payment within the delegation' : 'payment over the delegation maximum';
    console.log(`Demo ${n} — ${title} (MongoDB Atlas), db ${config.mongoDb}`);
    console.log(`  case      ${DEMO_IDS.agent} ${demoCase.action} ${usdc(demoCase.context.amount)} USDC -> ${demoCase.context.counterparty} (${demoCase.context.counterpartyName})`);
    const grant = await store.db.collection('grants').findOne({ _id: DEMO_IDS.delegation });
    console.log(`  delegation ${DEMO_IDS.delegation} maxAmount=${grant ? usdc(grant.constraints.maxAmount) : '-'} USDC`);

    // Risk layer: the full pipeline with a receipt.
    const { status, body: inv } = await postJson(port, '/v1/investigations', business.plaintext, signed());
    const stored = inv.id ? await store.db.collection('investigations').findOne({ _id: inv.id }) : null;
    const receipt = stored?.receiptId ? await store.db.collection('receipts').findOne({ _id: stored.receiptId }) : null;
    const identity = inv.stages?.find((s) => s.name === 'identity');
    const delegation = inv.stages?.find((s) => s.name === 'delegation');
    const primary = inv.reasons?.[0];
    console.log(`  HTTP      POST /v1/investigations -> ${status} ${inv.id ?? inv.error?.code ?? ''}`);
    if (inv.stages) console.log(`  stages    ${inv.stages.map((s) => `${s.name}[${s.engine ?? '-'}]=${s.status}`).join(' -> ')}`);
    console.log(`  signals   ${(inv.signals ?? []).join(', ') || '(none)'}`);
    console.log(`  identity  ${identity?.status === 'passed' ? 'VERIFIED' : 'NOT VERIFIED'} (${identity?.result?.reasonCode ?? '-'}) · action ${delegation?.status === 'passed' ? 'AUTHORIZED' : 'UNAUTHORIZED'}`);
    console.log(`  decision  ${inv.riskDecision ?? '-'} (${(inv.reasons ?? []).map((r) => r.code + (r.identityReasonCode ? `<-${r.identityReasonCode}` : '')).join(', ')})  identity=${inv.decision ?? '-'}  status=${inv.status ?? '-'}`);
    console.log(`  receipt   receipts/${receipt?._id ?? '-'} receiptHash=${receipt?.receiptHash ?? '-'} riskDecision=${receipt?.riskDecision ?? '-'}`);

    const e = demoCase.expected;
    expect(status === 201, `HTTP ${status} (expected 201)`);
    expect(identity?.status === 'passed' && identity?.result?.reasonCode === 'ALLOWED', `identity stage ${identity?.status}/${identity?.result?.reasonCode} (expected passed/ALLOWED)`);
    expect(inv.delegationId === DEMO_IDS.delegation, `delegation ${inv.delegationId} (expected ${DEMO_IDS.delegation})`);
    expect(inv.riskDecision === e.riskDecision, `riskDecision ${inv.riskDecision} (expected ${e.riskDecision})`);
    expect(primary?.code === e.reasonCode, `primary reason ${primary?.code} (expected ${e.reasonCode})`);
    if (n === '1') {
      expect(inv.decision === 'ALLOW', `identity-layer decision ${inv.decision} (expected ALLOW)`);
      expect((inv.signals ?? []).length === 0, `signals ${inv.signals} (expected none)`);
      expect(delegation?.status === 'passed', `delegation stage ${delegation?.status} (expected passed)`);
    } else {
      expect(primary?.identityReasonCode === e.identityReasonCode && primary?.invariantId === 'INV_DELEGATION_MAX', `primary reason does not wrap CONSTRAINT_VIOLATION / INV_DELEGATION_MAX (${JSON.stringify(primary)})`);
      expect(delegation?.status === 'failed', `delegation stage ${delegation?.status} (expected failed)`);
    }
    expect(stored?.riskDecision === inv.riskDecision, 'persisted riskDecision differs from the response');
    expect(Boolean(receipt), 'receipt not persisted in receipts');
    expect(receipt?.receiptHash === stored?.receiptHash && receipt?.riskDecision === inv.riskDecision, 'persisted receipt does not match the investigation');
    const anchor = receipt ? await store.db.collection('audit_events').findOne({ type: 'receipt.issued', 'data.receiptHash': receipt.receiptHash }) : null;
    expect(Boolean(anchor), 'no receipt.issued audit event anchors the receipt');
    // The passport issued to TreasuryBot for this delegation (passport.md §3: `— -> ACTIVE`).
    const pp = await store.db.collection('passports').findOne({ _id: DEMO_IDS.passport });
    const issuance = pp?.statusHistory?.[0];
    console.log(`  passport  ${pp?._id ?? '-'} ${pp?.status ?? '-'} agent=${pp?.agentId ?? '-'} delegation=${pp?.delegationId ?? '-'} v${pp?.delegationVersion ?? '-'} harness=v${pp?.harnessVersion ?? '-'} sanctions=${pp?.sanctionsDatasetVersion ?? '-'} issuedAt=${pp?.issuedAt?.toISOString?.() ?? '-'} expiresAt=${pp?.expiresAt?.toISOString?.() ?? '-'}`);
    expect(pp?.status === 'ACTIVE', `passport ${pp?.status} after the demo (expected ACTIVE)`);
    expect(pp?.agentId === DEMO_IDS.agent && pp?.delegationId === DEMO_IDS.delegation, 'passport is not the one issued to TreasuryBot for grt_TB_USDC');
    expect(issuance?.status === 'ACTIVE' && pp?.expiresAt > new Date(), 'passport has no ACTIVE issuance entry or has expired');
    console.log(`  elapsed   ${Date.now() - t0} ms`);
    return problems;
  } finally {
    await store.db.collection('api_keys').deleteMany({ _id: { $in: installed } }).catch(() => {});
  }
}

/**
 * Demo 3: the suspicious TreasuryBot payment through the real HTTP API on Atlas. Returns the
 * list of failed expectations (empty = expected outcome).
 */
async function runDemo3() {
  const t0 = Date.now();
  const rotation = await rotateTreasuryBotKey(store.db);
  const { port } = await app.listen(0, '127.0.0.1');
  const key = await installKey('demo 3 business (CirclePay)', 'business', DEMO_IDS.business);
  try {
    const body = buildVerifyRequest(treasuryBotKey('rotated').privateKey, {
      agentId: DEMO_IDS.agent,
      audience: DEMO_IDS.business,
      action: DEMO3_CASE.action,
      context: { ...DEMO3_CASE.context },
    });
    const res = await fetch(`http://127.0.0.1:${port}/v1/investigations`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${key.plaintext}`, 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    const inv = await res.json();
    // Read back from Atlas: the decision must be what was persisted.
    const stored = inv.id ? await store.db.collection('investigations').findOne({ _id: inv.id }) : null;

    console.log(`Demo 3 — verified security memory (MongoDB Atlas Vector Search), db ${config.mongoDb}`);
    console.log(`  case      ${DEMO_IDS.agent} ${DEMO3_CASE.action} ${usdc(DEMO3_CASE.context.amount)} USDC -> ${DEMO3_CASE.context.counterparty} (${DEMO3_CASE.context.counterpartyName})`);
    console.log(`  key       signed with the rotated key ${rotation.thumbprint}${rotation.rotated ? ' (rotation applied now)' : ''}`);
    console.log(`  HTTP      POST /v1/investigations -> ${res.status} ${inv.id ?? inv.error?.code ?? ''}`);
    if (inv.stages) console.log(`  stages    ${inv.stages.map((s) => `${s.name}[${s.engine}]=${s.status}`).join(' -> ')}`);
    console.log(`  signals   ${(inv.signals ?? []).join(', ') || '(none)'}`);
    const hits = inv.memory?.hits ?? [];
    console.log(`  memory    ${inv.memory?.engine ?? '-'} k=${inv.memory?.k ?? '-'} minScorePpm=${inv.memory?.minScorePpm ?? '-'} hits=${hits.length}`);
    for (const h of hits) {
      console.log(`    - ${h.memoryId}  score=${h.score?.toFixed?.(4) ?? h.score} (${h.scorePpm} ppm)  ${h.status}  ${h.outcome}  precedent=${h.usedAsPrecedent}  "${h.title}"`);
    }
    console.log(`  decision  ${inv.riskDecision ?? '-'} (${(inv.reasons ?? []).map((r) => r.code).join(', ')})  identity=${inv.decision ?? '-'}  status=${inv.status ?? '-'}`);
    console.log(`  persisted investigations/${stored?._id ?? '-'} memory.hits=${JSON.stringify((stored?.memory?.hits ?? []).map((h) => h.memoryId))}`);

    const e = DEMO3_CASE.expected;
    const problems = [];
    const expect = (ok, msg) => ok || problems.push(msg);
    expect(res.status === 201, `HTTP ${res.status} (expected 201)`);
    expect(inv.riskDecision === e.riskDecision, `riskDecision ${inv.riskDecision} (expected ${e.riskDecision})`);
    expect(inv.reasons?.[0]?.code === e.reasonCode, `primary reason ${inv.reasons?.[0]?.code} (expected ${e.reasonCode})`);
    expect(JSON.stringify([...(inv.signals ?? [])].sort()) === JSON.stringify(DEMO3_CASE.expectedSignals), `signals ${inv.signals} (expected ${DEMO3_CASE.expectedSignals})`);
    expect(inv.memory?.engine === '$vectorSearch', 'memory engine is not $vectorSearch');
    expect(hits[0]?.memoryId === e.memoryId && hits[0]?.status === 'VERIFIED', `top memory ${hits[0]?.memoryId}/${hits[0]?.status} (expected ${e.memoryId}/VERIFIED)`);
    expect(hits.every((h) => h.status === 'VERIFIED'), 'a non-VERIFIED memory was returned');
    expect(stored?.riskDecision === inv.riskDecision, 'persisted riskDecision differs from the response');
    expect(stored?.memory?.hits?.[0]?.memoryId === e.memoryId, 'persisted investigation lacks memory.hits');
    console.log(`  elapsed   ${Date.now() - t0} ms`);
    return problems;
  } finally {
    await store.db.collection('api_keys').deleteOne({ _id: key.keyId }).catch(() => {});
  }
}

const DEMO_RUNNERS = {
  1: { run: () => runDemo12('1', DEMO1_CASE), ok: 'ALLOW / CLEAR, passport ACTIVE, receipt persisted' },
  2: { run: () => runDemo12('2', DEMO2_CASE), ok: 'BLOCK / DELEGATION_MAX_EXCEEDED (wraps CONSTRAINT_VIOLATION), identity VERIFIED, receipt persisted' },
  3: { run: runDemo3, ok: 'REVIEW / MEMORY_PRECEDENT_TAKEOVER from a VERIFIED Vector Search precedent' },
};

if (demoN !== null) {
  let problems;
  try {
    problems = await DEMO_RUNNERS[demoN].run();
  } catch (err) {
    problems = [`demo failed: ${err.message}`];
  }
  await app.close().catch(() => {});
  if (problems.length) fail(`DEMO ${demoN} MISMATCH:\n  ${problems.join('\n  ')}`);
  console.log(`DEMO ${demoN} OK: ${DEMO_RUNNERS[demoN].ok}`);
  process.exit(0);
}

if (check) {
  let probe;
  try {
    probe = await probeSearch(store.db, docs);
  } catch (err) {
    probe = { ok: false, error: err.message };
  }
  await store.close();
  if (!probe.ok) fail(`demo check failed: search indexes did not answer as expected ${JSON.stringify(probe)} (run make demo-reset)`);
  console.log(`demo check OK: store=mongo db=${config.mongoDb}`);
  console.log(`  counts ${JSON.stringify(counts)}`);
  console.log(`  $search sanctions_search -> ${probe.search.join(', ')}`);
  console.log(`  $vectorSearch memory_vector (VERIFIED) -> ${probe.vector.join(', ')}`);
  process.exit(0);
}

// Bind the port before writing anything, so a busy port leaves no demo keys behind.
let port;
try {
  ({ port } = await new Promise((resolve, reject) => {
    app.server.once('error', reject);
    app.listen().then(resolve);
  }));
} catch (err) {
  await store.close().catch(() => {});
  fail(`Could not listen on ${config.host}:${config.port} (${err.code ?? err.message}); set PORT to a free port`);
}

// Demo-only API keys. Previous demo keys are dropped first (with an ephemeral pepper they
// could not authenticate anymore anyway).
await store.db.collection('api_keys').deleteMany({ demo: true });
const adminKey = (await installKey('demo admin', 'admin', null)).plaintext;
const operatorKey = (await installKey('demo operator (Northwind)', 'operator', DEMO_IDS.principal)).plaintext;
const businessKey = (await installKey('demo business (CirclePay)', 'business', DEMO_IDS.business)).plaintext;

const base = `http://127.0.0.1:${port}`;
console.log(`KYAgent demo on MongoDB Atlas (db ${config.mongoDb}); store=${store.kind}`);
console.log(`  principal ${DEMO_IDS.principal} · agent ${DEMO_IDS.agent} · delegation ${DEMO_IDS.delegation} · passport ${DEMO_IDS.passport}`);
console.log(`  scenario  ${JSON.stringify(counts)}`);
console.log(`\nDashboard: ${base}/dashboard/`);
console.log('Demo-only API keys (hashes tagged demo:true; deleted by the next make demo / make demo-reset):');
console.log(`  admin    ${adminKey}`);
console.log(`  operator ${operatorKey}`);
console.log(`  business ${businessKey}`);
console.log('Press Ctrl+C to stop.');

const shutdown = async () => {
  await app.close().catch(() => {});
  process.exit(0);
};
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
