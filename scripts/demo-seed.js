// Upserts the hackathon demo documents (src/seed/hackathon.js) into MongoDB Atlas without
// clearing anything first. Idempotent. Use `make demo-reset` to restore the exact scenario
// (it also empties runtime collections and waits for the search indexes).
import { ConfigError, loadConfig } from '../src/config.js';
import { seedHackathon } from '../src/seed/hackathon.js';
import { runMigrations } from '../src/store/migrations.js';

const fail = (msg) => {
  process.stderr.write(`${msg}\n`);
  process.exit(1);
};

if (!process.env.MONGODB_URI) fail('Atlas required: set MONGODB_URI to the MongoDB Atlas connection string');
let config;
try {
  config = loadConfig({ ...process.env, LOG_LEVEL: 'silent' });
} catch (err) {
  if (!(err instanceof ConfigError)) throw err;
  fail(`Configuration error: ${err.message}`);
}
if (config.production) fail('Refusing to seed demo data with NODE_ENV=production');

const { MongoClient } = await import('mongodb');
const client = new MongoClient(config.mongoUri, { serverSelectionTimeoutMS: 10_000 });
try {
  await client.connect();
  const db = client.db(config.mongoDb);
  await runMigrations(db);
  const written = await seedHackathon(db);
  process.stdout.write(`demo-seed: ${JSON.stringify(written)}\n`);
} catch (err) {
  const hint = err?.code === 11000 ? ' (runtime state conflicts with the seed, e.g. a newer active harness version: run make demo-reset)' : '';
  process.stderr.write(`demo-seed failed: ${err.message}${hint}\n`);
  process.exitCode = 1;
} finally {
  await client.close().catch(() => {});
}
