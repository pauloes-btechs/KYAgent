// REQ-018: client SDK for agents (sign) and businesses (verify), plus example code.
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { dirname, resolve } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { exportAgentKey, generateAgentKey, importAgentKey, KYA_HEADERS, signedHeaders, signRequest } from '../src/sdk/agentSigner.js';
import { createVerifier, isAllowed, KyaSdkError, readSignedHeaders } from '../src/sdk/businessVerifier.js';
import { createGrant, registerAgent, world } from './helpers.js';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const PASS = 'correct horse battery staple';

async function setup() {
  const w = await world();
  const kya = createVerifier({ baseUrl: w.t.base, apiKey: w.business.key });
  const headers = (opts = {}) =>
    signedHeaders(opts.privateKey ?? w.agent.privateKey, {
      agentId: w.agent.agent.id,
      audience: opts.audience ?? w.business.biz.id,
      action: opts.action ?? 'payments:create',
      resource: opts.resource,
      context: opts.context ?? { amount: 1500, currency: 'USD' },
      credential: opts.credential,
      timestamp: w.t.nowSec(),
    });
  return { ...w, kya, headers };
}

test('agent signs headers, business verifies them: ALLOW', async () => {
  const w = await setup();
  try {
    const d = await w.kya.verifyIncoming({ headers: w.headers(), action: 'payments:create', context: { amount: 1500, currency: 'USD' } });
    assert.equal(d.decision, 'ALLOW');
    assert.ok(isAllowed(d));
    assert.equal(d.grantId, w.grant.id);
    assert.equal(d.agentId, w.agent.agent.id);
  } finally {
    await w.t.close();
  }
});

test('works with Fetch Headers objects and presented credentials', async () => {
  const w = await setup();
  try {
    const cred = await w.t.call(w.operator.key, 'POST', `/v1/agents/${w.agent.agent.id}/credentials`, { grantId: w.grant.id });
    assert.equal(cred.status, 201, cred.text);
    const h = new Headers(w.headers({ credential: cred.body.credential }));
    const d = await w.kya.verifyIncoming({ headers: h, action: 'payments:create', context: { amount: 1500, currency: 'USD' } });
    assert.equal(d.decision, 'ALLOW');
    assert.equal(d.credentialId, cred.body.record.id);
  } finally {
    await w.t.close();
  }
});

test('business-derived values that differ from what was signed are denied', async () => {
  const w = await setup();
  try {
    const tampered = await w.kya.verifyIncoming({ headers: w.headers(), action: 'payments:create', context: { amount: 9000, currency: 'USD' } });
    assert.equal(tampered.decision, 'DENY');
    assert.equal(tampered.reasons[0].code, 'MALFORMED_REQUEST');
    const otherAction = await w.kya.verifyIncoming({ headers: w.headers(), action: 'payments:refund', context: { amount: 1500, currency: 'USD' } });
    assert.equal(otherAction.reasons[0].code, 'MALFORMED_REQUEST');
  } finally {
    await w.t.close();
  }
});

test('replayed headers, wrong audience, wrong key and revocation are denied', async () => {
  const w = await setup();
  try {
    const ctx = { amount: 1500, currency: 'USD' };
    const h = w.headers();
    assert.equal((await w.kya.verifyIncoming({ headers: h, action: 'payments:create', context: ctx })).decision, 'ALLOW');
    assert.equal((await w.kya.verifyIncoming({ headers: h, action: 'payments:create', context: ctx })).reasons[0].code, 'NONCE_REPLAYED');
    const aud = await w.kya.verifyIncoming({ headers: w.headers({ audience: 'biz_01J8ZQ4Y5N3V6K2M7P9R0S1T2U' }), action: 'payments:create', context: ctx });
    assert.equal(aud.reasons[0].code, 'AUDIENCE_MISMATCH');
    const forged = await w.kya.verifyIncoming({ headers: w.headers({ privateKey: generateAgentKey().privateKey }), action: 'payments:create', context: ctx });
    assert.equal(forged.reasons[0].code, 'SIGNATURE_INVALID');
    await w.t.call(w.operator.key, 'POST', `/v1/agents/${w.agent.agent.id}/revoke`, { reason: 'compromised' });
    const revoked = await w.kya.verifyIncoming({ headers: w.headers(), action: 'payments:create', context: ctx });
    assert.equal(revoked.reasons[0].code, 'AGENT_REVOKED');
    assert.ok(!isAllowed(revoked));
  } finally {
    await w.t.close();
  }
});

test('missing or malformed signature headers are denied locally', async () => {
  const w = await setup();
  try {
    for (const headers of [{}, { [KYA_HEADERS.signedRequest]: 'not base64!' }, { [KYA_HEADERS.signedRequest]: Buffer.from('[1]').toString('base64url') }, { [KYA_HEADERS.signedRequest]: 'A'.repeat(5000) }]) {
      const d = await w.kya.verifyIncoming({ headers, action: 'payments:create' });
      assert.equal(d.decision, 'DENY');
      assert.equal(d.reasons[0].code, 'MALFORMED_REQUEST');
      assert.equal(d.local, true);
    }
    assert.throws(() => readSignedHeaders({}), KyaSdkError);
    assert.throws(() => readSignedHeaders({ [KYA_HEADERS.signedRequest]: ['a', 'b'] }), KyaSdkError);
  } finally {
    await w.t.close();
  }
});

test('verifier fails closed: unreachable, timeout, bad key, garbage, forged ALLOW', async () => {
  const w = await setup();
  try {
    const body = { agentId: w.agent.agent.id, action: 'payments:create', signedRequest: signRequest(w.agent.privateKey, { agentId: w.agent.agent.id, audience: w.business.biz.id, action: 'payments:create' }) };
    const fake = (status, payload) => async () => new Response(typeof payload === 'string' ? payload : JSON.stringify(payload), { status });
    const cases = [
      createVerifier({ baseUrl: 'http://127.0.0.1:1', apiKey: w.business.key }),
      createVerifier({ baseUrl: w.t.base, apiKey: w.business.key, fetch: () => new Promise(() => {}), timeoutMs: 50 }),
      createVerifier({ baseUrl: w.t.base, apiKey: w.business.key.slice(0, -1) + (w.business.key.endsWith('A') ? 'B' : 'A') }),
      createVerifier({ baseUrl: w.t.base, apiKey: w.business.key, fetch: fake(200, 'not json') }),
      createVerifier({ baseUrl: w.t.base, apiKey: w.business.key, fetch: fake(502, { decision: 'ALLOW', reasons: [{ code: 'ALLOWED' }] }) }),
      createVerifier({ baseUrl: w.t.base, apiKey: w.business.key, fetch: fake(200, { decision: 'ALLOW', reasons: [{ code: 'ALLOWED' }], agentId: 'agt_other', action: 'payments:create' }) }),
      createVerifier({ baseUrl: w.t.base, apiKey: w.business.key, fetch: fake(200, { decision: 'MAYBE', reasons: [{ code: 'ALLOWED' }] }) }),
    ];
    for (const kya of cases) {
      const d = await kya.verify(body);
      assert.equal(d.decision, 'DENY');
      assert.equal(d.reasons[0].code, 'INTERNAL_ERROR');
      assert.ok(!isAllowed(d));
      assert.ok(!JSON.stringify(d).includes(w.business.key.slice(35)), 'api key secret leaked into decision');
    }
  } finally {
    await w.t.close();
  }
});

test('verifier config is strict: https only (except loopback), well-formed key', () => {
  const key = `kya_key_${'0'.repeat(26)}_${'A'.repeat(43)}`;
  assert.throws(() => createVerifier({ baseUrl: 'http://kya.example.com', apiKey: key }), KyaSdkError);
  assert.throws(() => createVerifier({ baseUrl: 'https://u:p@kya.example.com', apiKey: key }), KyaSdkError);
  assert.throws(() => createVerifier({ baseUrl: 'https://kya.example.com', apiKey: 'Bearer nope' }), KyaSdkError);
  assert.throws(() => createVerifier({ baseUrl: 'not a url', apiKey: key }), KyaSdkError);
  assert.doesNotThrow(() => createVerifier({ baseUrl: 'https://kya.example.com/', apiKey: key }));
  assert.doesNotThrow(() => createVerifier({ baseUrl: 'http://localhost:8080', apiKey: key }));
  const kya = createVerifier({ baseUrl: 'https://kya.example.com', apiKey: key });
  assert.deepEqual(Object.keys(kya).sort(), ['verify', 'verifyIncoming']);
  assert.ok(!JSON.stringify(kya).includes(key));
});

test('a second agent from the same business uses its own grants', async () => {
  const w = await setup();
  try {
    const other = await registerAgent(w.t, w.operator, 'Refund Bot');
    await createGrant(w.t, w.business, other.agent.id, { actions: ['orders:*'], constraints: {} });
    const h = signedHeaders(other.privateKey, { agentId: other.agent.id, audience: w.business.biz.id, action: 'orders:refund', timestamp: w.t.nowSec() });
    assert.equal((await w.kya.verifyIncoming({ headers: h, action: 'orders:refund' })).decision, 'ALLOW');
    const h2 = signedHeaders(other.privateKey, { agentId: other.agent.id, audience: w.business.biz.id, action: 'payments:create', timestamp: w.t.nowSec() });
    assert.equal((await w.kya.verifyIncoming({ headers: h2, action: 'payments:create' })).reasons[0].code, 'ACTION_NOT_PERMITTED');
  } finally {
    await w.t.close();
  }
});

test('agent keys export only as encrypted PKCS#8 and round-trip', () => {
  const { privateKey, publicKey } = generateAgentKey();
  const pem = exportAgentKey(privateKey, PASS);
  assert.match(pem, /-----BEGIN ENCRYPTED PRIVATE KEY-----/);
  assert.equal(importAgentKey(pem, PASS).publicKey, publicKey);
  assert.throws(() => importAgentKey(pem, 'wrong passphrase!!'));
  assert.throws(() => exportAgentKey(privateKey, 'short'));
  assert.throws(() => exportAgentKey(privateKey, undefined));
  const plain = privateKey.export({ type: 'pkcs8', format: 'pem' });
  assert.throws(() => importAgentKey(plain, PASS), /encrypted/);
});

test('examples/sdk-quickstart.js runs and exits 0', async () => {
  const { stdout } = await promisify(execFile)(process.execPath, [resolve(root, 'examples/sdk-quickstart.js')], {
    env: { ...process.env, NODE_ENV: 'test' },
    timeout: 30000,
  });
  assert.match(stdout, /201 +ALLOWED/);
  assert.match(stdout, /403 +CONSTRAINT_VIOLATION/);
  assert.match(stdout, /403 +MALFORMED_REQUEST/);
  assert.doesNotMatch(stdout, /kya_key_/);
});
