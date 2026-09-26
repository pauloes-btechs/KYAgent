// REQ-020: Docker Compose local deployment, migrations, seed data and .env.example.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { loadConfig } from '../src/config.js';
import { SEED_BUSINESS_NAME, seedDemo } from '../src/seed.js';
import { agentKeyFromSeed, buildVerifyRequest } from '../src/sdk/agentSigner.js';
import { MIGRATIONS, MIGRATIONS_COLLECTION, runMigrations } from '../src/store/migrations.js';
import { GENERATED_SECRETS, renderEnv } from '../scripts/init-env.js';
import { startApp } from './helpers.js';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const read = (p) => readFileSync(resolve(root, p), 'utf8');

/** Minimal in-memory stand-in for a mongodb Db: records createIndex calls. */
function fakeDb() {
  const indexes = [];
  const cols = new Map();
  const collection = (name) => {
    if (!cols.has(name)) {
      const docs = new Map();
      cols.set(name, {
        docs,
        async createIndex(keys, opts = {}) {
          indexes.push({ name, keys, opts });
          return 'ok';
        },
        find: () => ({ toArray: async () => [...docs.values()] }),
        async insertOne(d) {
          if (docs.has(d._id)) throw Object.assign(new Error('dup'), { code: 11000 });
          docs.set(d._id, d);
        },
      });
    }
    return cols.get(name);
  };
  return { collection, indexes };
}

test('migrations: ids are unique and ordered', () => {
  const ids = MIGRATIONS.map((m) => m.id);
  assert.equal(new Set(ids).size, ids.length);
  assert.deepEqual([...ids].sort(), ids);
  for (const m of MIGRATIONS) assert.match(m.id, /^\d{3}_[a-z0-9_]+$/);
});

test('migrations: applied once, recorded, re-run is a no-op', async () => {
  const db = fakeDb();
  const first = await runMigrations(db);
  assert.deepEqual(first.applied, MIGRATIONS.map((m) => m.id));
  assert.deepEqual(first.skipped, []);
  const recorded = [...db.collection(MIGRATIONS_COLLECTION).docs.keys()];
  assert.deepEqual(recorded, first.applied);
  const indexCount = db.indexes.length;

  const second = await runMigrations(db);
  assert.deepEqual(second.applied, []);
  assert.deepEqual(second.skipped, first.applied);
  assert.equal(db.indexes.length, indexCount, 'no index work on re-run');
});

test('migrations: create the security-critical unique and TTL indexes', async () => {
  const db = fakeDb();
  await runMigrations(db);
  const has = (name, key, opt) =>
    db.indexes.some((i) => i.name === name && Object.keys(i.keys).join() === key && Object.entries(opt).every(([k, v]) => i.opts[k] === v));
  assert.ok(has('agents', 'publicKey', { unique: true }));
  assert.ok(has('agents', 'keyThumbprint', { unique: true }));
  assert.ok(has('nonces', 'expiresAt', { expireAfterSeconds: 0 }));
  assert.ok(has('audit_events', 'seq', { unique: true }));
});

test('migrations: a failing migration stops the run and is not recorded', async () => {
  const db = fakeDb();
  const ms = [
    { id: '001_ok', up: async () => {} },
    { id: '002_boom', up: async () => { throw new Error('boom'); } },
    { id: '003_never', up: async () => assert.fail('must not run') },
  ];
  await assert.rejects(runMigrations(db, { migrations: ms }), /boom/);
  assert.deepEqual([...db.collection(MIGRATIONS_COLLECTION).docs.keys()], ['001_ok']);
  await assert.rejects(runMigrations(db, { migrations: [ms[0], ms[0]] }), /duplicate migration id/);
});

test('seed: creates a working demo world through the API services, idempotently', async (t) => {
  const app = await startApp();
  t.after(() => app.close());
  const r = await seedDemo(app.app);
  assert.equal(r.alreadySeeded, false);

  // Only hashes / public keys are stored.
  const stored = JSON.stringify([...(await app.store.apiKeys.list({ limit: 50 })).data, await app.store.agents.findById(r.agentId)]);
  for (const s of Object.values(r.secrets)) assert.ok(!stored.includes(s), 'secret must not be persisted in plaintext');

  const op = await app.call(r.secrets.operatorApiKey, 'GET', `/v1/operators/${r.operatorId}`);
  assert.equal(op.status, 200);
  assert.equal(op.body.status, 'verified');

  // The printed agent seed + business key produce an ALLOW on /v1/verify.
  const { privateKey } = agentKeyFromSeed(r.secrets.agentPrivateKeySeed);
  const body = buildVerifyRequest(privateKey, {
    agentId: r.agentId,
    audience: r.businessId,
    action: 'payments:create',
    context: { amount: 2500, currency: 'USD' },
    timestamp: app.nowSec(),
  });
  const res = await app.call(r.secrets.businessApiKey, 'POST', '/v1/verify', body);
  assert.equal(res.body.decision, 'ALLOW', JSON.stringify(res.body));
  assert.equal(res.body.grantId, r.grantId);

  const over = buildVerifyRequest(privateKey, {
    agentId: r.agentId,
    audience: r.businessId,
    action: 'payments:create',
    context: { amount: 20000, currency: 'USD' },
    timestamp: app.nowSec(),
  });
  assert.equal((await app.call(r.secrets.businessApiKey, 'POST', '/v1/verify', over)).body.reasons[0].code, 'CONSTRAINT_VIOLATION');

  const again = await seedDemo(app.app);
  assert.deepEqual(again, { alreadySeeded: true, businessId: r.businessId });
  const named = await app.store.businesses.list({ filter: { name: SEED_BUSINESS_NAME }, limit: 5 });
  assert.equal(named.data.length, 1);
});

test('.env.example: documents every config variable, with empty secrets only', () => {
  const example = read('.env.example');
  const envDoc = read('docs/contracts/environment.md');
  const assigned = new Map(
    [...example.matchAll(/^#?\s*([A-Z][A-Z0-9_]+)=(.*)$/gm)].map((m) => [m[1], m[2].trim()]),
  );
  const documented = [...envDoc.matchAll(/^\| `([A-Z][A-Z0-9_]+)`/gm)].map((m) => m[1]);
  assert.ok(documented.length > 10);
  for (const name of documented) assert.ok(assigned.has(name), `${name} missing from .env.example`);
  for (const name of Object.keys(GENERATED_SECRETS)) assert.equal(assigned.get(name), '', `${name} must be a blank placeholder`);
  assert.equal(assigned.get('MONGODB_URI'), '');
  assert.doesNotMatch(example, /BEGIN [A-Z ]*PRIVATE KEY|kya_[A-Za-z0-9]+_[A-Za-z0-9_-]{20,}/);
});

test('env:init renders a .env that passes production config checks', () => {
  const rendered = renderEnv(read('.env.example'));
  const env = Object.fromEntries(
    rendered
      .split('\n')
      .filter((l) => /^[A-Z][A-Z0-9_]*=/.test(l))
      .map((l) => [l.slice(0, l.indexOf('=')), l.slice(l.indexOf('=') + 1)]),
  );
  for (const name of Object.keys(GENERATED_SECRETS)) assert.ok(env[name], `${name} generated`);
  // Mirror docker-compose.yml overrides.
  const config = loadConfig({ ...env, NODE_ENV: 'production', MONGODB_URI: 'mongodb://mongo:27017', LOG_LEVEL: 'silent' });
  assert.equal(config.production, true);
  assert.equal(config.sources.signingKey, 'env');
  assert.equal(config.sources.pepper, 'env');
  assert.equal(config.sources.bootstrapAdmin, 'env');
  // Fresh secrets every run; existing non-secret lines are preserved verbatim.
  assert.notEqual(renderEnv(read('.env.example')), rendered);
  assert.equal(renderEnv('FOO=bar\nKYA_API_KEY_PEPPER=keep', GENERATED_SECRETS), 'FOO=bar\nKYA_API_KEY_PEPPER=keep');
});

test('docker-compose.yml: mongo -> migrate -> api ordering, seed profile, no inline secrets', () => {
  const compose = read('docker-compose.yml');
  const services = compose.slice(compose.indexOf('\nservices:'), compose.indexOf('\nvolumes:'));
  const block = (name) => {
    const start = services.indexOf(`\n  ${name}:\n`);
    assert.ok(start >= 0, `service ${name} present`);
    const rest = services.slice(start + 1);
    const next = rest.slice(1).search(/\n {2}[a-z][\w-]*:\n/);
    return next < 0 ? rest : rest.slice(0, next + 1);
  };
  assert.match(block('mongo'), /healthcheck:/);
  assert.doesNotMatch(block('mongo'), /ports:/, 'mongo must not be published on the host');
  assert.match(block('migrate'), /scripts\/migrate\.js/);
  assert.match(block('migrate'), /mongo:\s*\n\s*condition: service_healthy/);
  assert.match(block('api'), /migrate:\s*\n\s*condition: service_completed_successfully/);
  assert.match(block('api'), /"127\.0\.0\.1:8080:8080"/);
  assert.match(block('seed'), /profiles: \["seed"\]/);
  assert.match(block('seed'), /scripts\/seed\.js/);
  assert.match(compose, /env_file: \.env/);
  assert.match(compose, /NODE_ENV: production/);
  assert.doesNotMatch(compose, /KYA_(SIGNING_PRIVATE_KEY|API_KEY_PEPPER|BOOTSTRAP_ADMIN_API_KEY)\s*[:=]/);

  const dockerfile = read('Dockerfile');
  assert.match(dockerfile, /COPY scripts \.\/scripts/);
  assert.match(dockerfile, /^USER node$/m);
  const dockerignore = read('.dockerignore').split('\n');
  for (const p of ['.env', '*.pem', 'secrets']) assert.ok(dockerignore.includes(p), `.dockerignore excludes ${p}`);

  const pkg = JSON.parse(read('package.json'));
  for (const s of ['env:init', 'migrate', 'seed']) assert.ok(pkg.scripts[s], `npm run ${s}`);
});
