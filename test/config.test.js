import assert from 'node:assert/strict';
import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { rmSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';
import { ConfigError, loadConfig, TEST_VECTOR_SEED_HEX } from '../src/config.js';
import { generateApiKey } from '../src/crypto/apiKeys.js';
import { privateKeyFromSeed } from '../src/crypto/ed25519.js';

const derB64 = (key) => key.export({ format: 'der', type: 'pkcs8' }).toString('base64');
const pem = (key) => key.export({ format: 'pem', type: 'pkcs8' });

function prodEnv() {
  return {
    NODE_ENV: 'production',
    MONGODB_URI: 'mongodb://example.invalid:27017',
    KYA_SIGNING_PRIVATE_KEY: derB64(generateKeyPairSync('ed25519').privateKey),
    KYA_API_KEY_PEPPER: randomBytes(32).toString('base64url'),
  };
}

test('production refuses to start without secrets or a database', () => {
  assert.ok(loadConfig(prodEnv()).production);
  for (const name of ['KYA_SIGNING_PRIVATE_KEY', 'KYA_API_KEY_PEPPER', 'MONGODB_URI']) {
    const env = prodEnv();
    delete env[name];
    assert.throws(() => loadConfig(env), (err) => err instanceof ConfigError && err.message.includes(name));
  }
});

test('dev/test generate ephemeral secrets with warnings', () => {
  const c = loadConfig({ NODE_ENV: 'test' });
  assert.equal(c.sources.signingKey, 'ephemeral');
  assert.equal(c.sources.pepper, 'ephemeral');
  assert.ok(c.warnings.some((w) => w.includes('KYA_SIGNING_PRIVATE_KEY')));
  assert.ok(c.warnings.some((w) => w.includes('KYA_API_KEY_PEPPER')));
});

test('secrets are never enumerable on the config object', () => {
  const env = prodEnv();
  const c = loadConfig(env);
  const dump = JSON.stringify(c);
  assert.ok(!dump.includes(env.KYA_API_KEY_PEPPER));
  assert.ok(!dump.includes(env.KYA_SIGNING_PRIVATE_KEY));
  assert.ok(!dump.includes('example.invalid'));
  assert.ok(c.signingKey && c.pepper);
});

test('signing key formats: base64 DER, PEM with escaped newlines; non-Ed25519 rejected', () => {
  const key = generateKeyPairSync('ed25519').privateKey;
  assert.equal(loadConfig({ NODE_ENV: 'test', KYA_SIGNING_PRIVATE_KEY: pem(key).replace(/\n/g, '\\n') }).sources.signingKey, 'env');
  const rsa = generateKeyPairSync('rsa', { modulusLength: 1024 }).privateKey;
  assert.throws(() => loadConfig({ NODE_ENV: 'test', KYA_SIGNING_PRIVATE_KEY: derB64(rsa) }), /Ed25519/);
  const secretish = 'not-a-key-SECRETVALUE';
  assert.throws(
    () => loadConfig({ NODE_ENV: 'test', KYA_SIGNING_PRIVATE_KEY: secretish }),
    (err) => err instanceof ConfigError && !err.message.includes(secretish),
  );
});

test('the public test-vector key cannot be the production signing key', () => {
  const env = { ...prodEnv(), KYA_SIGNING_PRIVATE_KEY: derB64(privateKeyFromSeed(TEST_VECTOR_SEED_HEX)) };
  assert.throws(() => loadConfig(env), /test-vector/);
});

test('*_FILE secrets, and both set is an error', () => {
  const path = fileURLToPath(new URL('./.pepper.test.tmp', import.meta.url));
  writeFileSync(path, `${randomBytes(32).toString('base64url')}\n`);
  try {
    const c = loadConfig({ NODE_ENV: 'test', KYA_API_KEY_PEPPER_FILE: path });
    assert.equal(c.sources.pepper, 'file');
    assert.equal(c.pepper.length, 43);
    assert.throws(() => loadConfig({ NODE_ENV: 'test', KYA_API_KEY_PEPPER_FILE: path, KYA_API_KEY_PEPPER: 'x'.repeat(43) }), /both set/);
    assert.throws(() => loadConfig({ NODE_ENV: 'test', KYA_API_KEY_PEPPER_FILE: `${path}.missing` }), /could not be read/);
  } finally {
    rmSync(path, { force: true });
  }
});

test('invalid values are always config errors', () => {
  assert.throws(() => loadConfig({ NODE_ENV: 'test', KYA_SIGNATURE_MAX_SKEW_SECONDS: '5' }), ConfigError);
  assert.throws(() => loadConfig({ NODE_ENV: 'test', KYA_SIGNATURE_MAX_SKEW_SECONDS: 'abc' }), ConfigError);
  assert.throws(() => loadConfig({ NODE_ENV: 'test', KYA_API_KEY_PEPPER: 'short' }), ConfigError);
  assert.throws(() => loadConfig({ NODE_ENV: 'test', KYA_BOOTSTRAP_ADMIN_API_KEY: 'kya_bad' }), ConfigError);
  assert.throws(() => loadConfig({ NODE_ENV: 'staging' }), ConfigError);
  assert.ok(loadConfig({ NODE_ENV: 'test', KYA_BOOTSTRAP_ADMIN_API_KEY: generateApiKey().plaintext }));
  const c = loadConfig({ NODE_ENV: 'test', CHAIN_MODE: 'on', LLM_MODE: 'on', SANCTIONS_MODE: 'live' });
  assert.equal(c.sanctionsMode, 'mock');
  assert.equal(c.warnings.filter((w) => /ignored|unsupported/.test(w)).length, 3);
});
