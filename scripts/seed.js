// Loads demo seed data (verified operator, business, API keys, agent, grant) into
// the configured MongoDB. Idempotent. The API keys and the demo agent's private-key
// seed are printed ONCE to stdout — only hashes / the public key are stored.
// They are demo credentials for a local stack; never seed a real deployment.
//
//   npm run seed                                   (MONGODB_URI set, NODE_ENV != production)
//   docker compose --profile seed run --rm seed    (compose passes --allow-production)
import { buildApp } from '../src/app.js';
import { ConfigError, loadConfig } from '../src/config.js';
import { seedDemo } from '../src/seed.js';
import { MongoStore } from '../src/store/mongo.js';

const fail = (msg) => {
  process.stderr.write(`${msg}\n`);
  process.exit(1);
};

let config;
try {
  config = loadConfig({ ...process.env, LOG_LEVEL: process.env.LOG_LEVEL || 'warn' });
} catch (err) {
  if (!(err instanceof ConfigError)) throw err;
  fail(`Configuration error: ${err.message}`);
}
if (!config.mongoUri) fail('MONGODB_URI is not set: seeding the in-memory store of another process has no effect');
if (config.production && !process.argv.includes('--allow-production')) {
  fail('Refusing to seed with NODE_ENV=production (pass --allow-production for a local Docker stack)');
}
if (config.sources.pepper === 'ephemeral') {
  fail('KYA_API_KEY_PEPPER is not set: seeded API keys would not work against the running API');
}

const app = buildApp({ config, store: new MongoStore(config.mongoUri, config.mongoDb) });
try {
  await app.init();
  const r = await seedDemo(app);
  if (r.alreadySeeded) {
    process.stdout.write(`Already seeded (business ${r.businessId}); nothing written. Keys are only shown on first seed.\n`);
  } else {
    process.stdout.write(
      [
        'Seed data created:',
        `  operator  ${r.operatorId} (verified)`,
        `  business  ${r.businessId}`,
        `  agent     ${r.agentId}`,
        `  grant     ${r.grantId}`,
        '',
        'Demo secrets — shown once, not stored in plaintext. Keep them out of git:',
        `  operator API key        ${r.secrets.operatorApiKey}`,
        `  business API key        ${r.secrets.businessApiKey}`,
        `  agent private key seed  ${r.secrets.agentPrivateKeySeed}  (hex; agentKeyFromSeed() in src/sdk/agentSigner.js)`,
        '',
      ].join('\n'),
    );
  }
} catch (err) {
  process.stderr.write(`seed failed: ${err.message}\n`);
  process.exitCode = 1;
} finally {
  await app.store.close();
}
