// `make demo-reset`: restore the exact hackathon judging scenario on MongoDB Atlas
// (DELIVERY_PLAN §5, mongo-collections.md §4). Idempotent. Steps:
//   1. remove the demo docs and empty investigations / harness_events / watcher_state /
//      passports / receipts / harness_versions (src/seed/hackathon.js clearHackathon);
//   2. run migrations (validators + indexes);
//   3. ensureSearchIndexes() and poll until both indexes are queryable;
//   4. re-seed the 12 demo documents/sets, harness_versions = v1 only;
//   5. prove $search and $vectorSearch answer over the seeded data;
//   6. check the document counts equal the fixture-derived expectation.
// Exits 0 only when every step passed. Never prints MONGODB_URI.
import { ConfigError, loadConfig } from '../src/config.js';
import {
  buildHackathonDocs,
  clearHackathon,
  collectionCounts,
  expectedCounts,
  seedHackathon,
  waitForSearchReady,
} from '../src/seed/hackathon.js';
import { runMigrations } from '../src/store/migrations.js';
import { ensureSearchIndexes } from '../src/store/searchIndexes.js';

const fail = (msg) => {
  process.stderr.write(`${msg}\n`);
  process.exit(1);
};
const log = (msg) => process.stdout.write(`${msg}\n`);

if (!process.env.MONGODB_URI) fail('Atlas required: set MONGODB_URI to the MongoDB Atlas connection string, then run make demo-reset');
let config;
try {
  config = loadConfig({ ...process.env, LOG_LEVEL: 'silent' });
} catch (err) {
  if (!(err instanceof ConfigError)) throw err;
  fail(`Configuration error: ${err.message}`);
}
if (config.production) fail('Refusing to reset demo data with NODE_ENV=production');

const { MongoClient } = await import('mongodb');
const client = new MongoClient(config.mongoUri, { serverSelectionTimeoutMS: 10_000 });
try {
  await client.connect();
  const db = client.db(config.mongoDb);
  log(`demo-reset: database ${config.mongoDb}`);

  const deleted = await clearHackathon(db);
  log(`  cleared   ${JSON.stringify(deleted)}`);

  const { applied, skipped } = await runMigrations(db);
  log(`  migrations ${applied.length} applied, ${skipped.length} up to date`);

  const indexes = await ensureSearchIndexes(db);
  log(`  indexes   ${indexes.map((i) => `${i.collection}.${i.name}=${i.status}`).join(', ')}`);

  const docs = buildHackathonDocs();
  const written = await seedHackathon(db, { docs });
  log(`  seeded    ${JSON.stringify(written)}`);

  const probe = await waitForSearchReady(db, { docs });
  log(`  $search sanctions_search -> ${probe.search.join(', ')}`);
  log(`  $vectorSearch memory_vector (VERIFIED) -> ${probe.vector.join(', ')}`);

  const counts = await collectionCounts(db);
  const expected = expectedCounts(docs);
  log(`  counts    ${JSON.stringify(counts)}`);
  const diff = Object.keys(expected).filter((c) => counts[c] !== expected[c]);
  if (diff.length) {
    throw new Error(`document counts differ from the scenario: ${diff.map((c) => `${c}=${counts[c]} (expected ${expected[c]})`).join(', ')}`);
  }
  log('demo-reset: OK (scenario restored, both search indexes queryable)');
} catch (err) {
  process.stderr.write(`demo-reset failed: ${err.message}\n`);
  process.exitCode = 1;
} finally {
  await client.close().catch(() => {});
}
