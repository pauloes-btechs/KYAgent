// Live demo (`make demo`): serves the KYAgent API + dashboard on MongoDB Atlas via MongoStore,
// over the judging scenario restored by `make demo-reset` (src/seed/hackathon.js). There is
// no in-memory fallback: without MONGODB_URI, or on a deployment without Atlas Search, it
// exits 1 ("Atlas required").
//
//   make demo            start the API, print the dashboard URL and demo-only API keys
//   make demo CHECK=1    headless: verify the scenario and both search indexes, then exit
//   make demo DEMO=3     run Demo 3 (verified security memory) through POST /v1/investigations
//                        on Atlas, print signals / memory hits / decision; exit 1 on mismatch
//                        (`make demo CHECK=1 DEMO=3` is the same run, used as the acceptance gate)
//
// Demo API keys are inserted directly as HMAC hashes tagged `demo: true` (no audit events
// are written for them) and are deleted by the next `make demo` or `make demo-reset`.
import { buildApp } from '../src/app.js';
import { ConfigError, loadConfig } from '../src/config.js';
import { generateApiKey, hashApiKeySecret } from '../src/crypto/apiKeys.js';
import { buildVerifyRequest } from '../src/sdk/agentSigner.js';
import {
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
const DEMOS = ['3'];
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

    const usdc = (n) => (n / 1_000_000).toLocaleString('en-US');
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

if (demoN !== null) {
  let problems;
  try {
    problems = await runDemo3();
  } catch (err) {
    problems = [`demo failed: ${err.message}`];
  }
  await app.close().catch(() => {});
  if (problems.length) fail(`DEMO 3 MISMATCH:\n  ${problems.join('\n  ')}`);
  console.log('DEMO 3 OK: REVIEW / MEMORY_PRECEDENT_TAKEOVER from a VERIFIED Vector Search precedent');
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
