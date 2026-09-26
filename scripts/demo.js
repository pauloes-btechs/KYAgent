// Live demo (`make demo`): serves the KYAgent API + dashboard on MongoDB Atlas via MongoStore,
// over the judging scenario restored by `make demo-reset` (src/seed/hackathon.js). There is
// no in-memory fallback: without MONGODB_URI, or on a deployment without Atlas Search, it
// exits 1 ("Atlas required").
//
//   make demo            start the API, print the dashboard URL and demo-only API keys
//   make demo CHECK=1    headless: verify the scenario and both search indexes, then exit
//
// Demo API keys are inserted directly as HMAC hashes tagged `demo: true` (no audit events
// are written for them) and are deleted by the next `make demo` or `make demo-reset`.
import { buildApp } from '../src/app.js';
import { ConfigError, loadConfig } from '../src/config.js';
import { generateApiKey, hashApiKeySecret } from '../src/crypto/apiKeys.js';
import { DEMO_IDS, buildHackathonDocs, collectionCounts, expectedCounts, probeSearch } from '../src/seed/hackathon.js';
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
  return plaintext;
}
const adminKey = await installKey('demo admin', 'admin', null);
const operatorKey = await installKey('demo operator (Northwind)', 'operator', DEMO_IDS.principal);
const businessKey = await installKey('demo business (CirclePay)', 'business', DEMO_IDS.business);

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
