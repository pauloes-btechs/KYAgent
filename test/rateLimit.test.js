// REQ-016: rate limiting on verification and registration endpoints.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { ConfigError, loadConfig } from '../src/config.js';
import { buildVerifyRequest, generateAgentKey, proofOfPossession } from '../src/sdk/agentSigner.js';
import { RateLimiter } from '../src/rateLimit.js';
import { createBusiness, createGrant, createOperator, registerAgent, startApp } from './helpers.js';

function fakeClock() {
  const s = { ms: 1_700_000_000_000 };
  return { now: () => new Date(s.ms), advance: (sec) => (s.ms += sec * 1000) };
}

test('RateLimiter: fixed window, per key, resets after the window', () => {
  const clock = fakeClock();
  const rl = new RateLimiter({ limit: 2, windowSeconds: 10, clock });
  assert.equal(rl.hit('a').allowed, true);
  assert.equal(rl.hit('a').remaining, 0);
  const denied = rl.hit('a');
  assert.equal(denied.allowed, false);
  assert.equal(denied.retryAfter, 10);
  assert.equal(rl.hit('b').allowed, true, 'keys are independent');
  clock.advance(4);
  assert.equal(rl.hit('a').retryAfter, 6);
  clock.advance(6);
  assert.equal(rl.hit('a').allowed, true, 'new window');
});

test('RateLimiter: bounded memory under many distinct keys', () => {
  const clock = fakeClock();
  const rl = new RateLimiter({ limit: 1, windowSeconds: 60, clock, maxKeys: 100 });
  for (let i = 0; i < 1000; i++) rl.hit(`k${i}`);
  assert.ok(rl.buckets.size <= 100);
  assert.throws(() => new RateLimiter({ limit: 0, windowSeconds: 1, clock }), TypeError);
});

test('config: rate limit defaults, overrides and validation', () => {
  const d = loadConfig({ NODE_ENV: 'test' }).rateLimit;
  assert.deepEqual(d, { enabled: true, windowSeconds: 60, ipPerWindow: 1200, verifyPerWindow: 600, registerPerWindow: 30 });
  const c = loadConfig({ NODE_ENV: 'test', KYA_RATE_LIMIT_VERIFY_PER_WINDOW: '5', KYA_RATE_LIMIT_ENABLED: 'false' });
  assert.equal(c.rateLimit.verifyPerWindow, 5);
  assert.equal(c.rateLimit.enabled, false);
  assert.ok(c.warnings.some((w) => w.includes('KYA_RATE_LIMIT_ENABLED')));
  assert.throws(() => loadConfig({ NODE_ENV: 'test', KYA_RATE_LIMIT_ENABLED: 'yes' }), ConfigError);
  assert.throws(() => loadConfig({ NODE_ENV: 'test', KYA_RATE_LIMIT_REGISTER_PER_WINDOW: '0' }), ConfigError);
  assert.throws(() => loadConfig({ NODE_ENV: 'test', KYA_RATE_LIMIT_WINDOW_SECONDS: 'abc' }), ConfigError);
});

test('POST /v1/verify: per-business limit returns 429 with Retry-After, isolated per tenant, resets', async (tc) => {
  const t = await startApp({ env: { KYA_RATE_LIMIT_VERIFY_PER_WINDOW: '3', KYA_RATE_LIMIT_WINDOW_SECONDS: '60' } });
  tc.after(t.close);
  const operator = await createOperator(t);
  const b1 = await createBusiness(t, 'One');
  const b2 = await createBusiness(t, 'Two');
  const agent = await registerAgent(t, operator);
  await createGrant(t, b1, agent.agent.id);
  const body = (aud) =>
    buildVerifyRequest(agent.privateKey, { agentId: agent.agent.id, audience: aud, action: 'payments:create', context: { amount: 1, currency: 'USD' }, timestamp: t.nowSec() });

  for (let i = 0; i < 3; i++) {
    const r = await t.call(b1.key, 'POST', '/v1/verify', body(b1.biz.id));
    assert.equal(r.status, 200);
    assert.equal(r.body.decision, 'ALLOW');
  }
  const limited = await t.call(b1.key, 'POST', '/v1/verify', body(b1.biz.id));
  assert.equal(limited.status, 429);
  assert.equal(limited.body.error.code, 'RATE_LIMITED');
  assert.equal(limited.body.decision, undefined, 'no decision is produced');
  assert.equal(limited.headers.get('retry-after'), '60');
  assert.equal(limited.body.error.requestId, limited.headers.get('x-request-id'));

  // rate-limited requests are not recorded as decisions
  assert.equal((await t.call(b1.key, 'GET', '/v1/verifications')).body.data.length, 3);

  // another tenant has its own budget
  assert.equal((await t.call(b2.key, 'POST', '/v1/verify', body(b2.biz.id))).status, 200);

  t.advance(60);
  const again = await t.call(b1.key, 'POST', '/v1/verify', body(b1.biz.id));
  assert.equal(again.status, 200);
  assert.equal(again.body.decision, 'ALLOW');
});

test('POST /v1/agents: per-operator registration limit', async (tc) => {
  const t = await startApp({ env: { KYA_RATE_LIMIT_REGISTER_PER_WINDOW: '4' } });
  tc.after(t.close);
  // admin's own register budget is separate: two operator creations use 2 of its 4
  const operator = await createOperator(t);
  const other = await createOperator(t, { legalName: 'Other Ltd' });
  await registerAgent(t, operator, 'a1');
  await registerAgent(t, operator, 'a2');
  await registerAgent(t, operator, 'a3');
  await registerAgent(t, operator, 'a4');
  const k = generateAgentKey();
  const res = await t.call(operator.key, 'POST', '/v1/agents', {
    name: 'a5',
    publicKey: k.publicKey,
    proofOfPossession: proofOfPossession(k.privateKey, operator.op.id, k.publicKey),
  });
  assert.equal(res.status, 429);
  assert.equal(res.body.error.code, 'RATE_LIMITED');
  assert.ok(Number(res.headers.get('retry-after')) >= 1);
  // other operators are unaffected
  await registerAgent(t, other, 'b1');
  // non-limited routes are unaffected
  assert.equal((await t.call(operator.key, 'GET', '/v1/agents')).status, 200);
});

test('per-IP limit applies before authentication (unauthenticated floods / key guessing)', async (tc) => {
  const t = await startApp({ env: { KYA_RATE_LIMIT_IP_PER_WINDOW: '5' } });
  tc.after(t.close);
  const bogus = 'kya_AAAAAAAAAAAAAAAAAAAAAAAAAA_notarealsecretnotarealsecretnotareal';
  for (let i = 0; i < 5; i++) assert.equal((await t.call(bogus, 'POST', '/v1/verify', {})).status, 401);
  const r = await t.call(bogus, 'POST', '/v1/verify', {});
  assert.equal(r.status, 429);
  assert.equal(r.body.error.code, 'RATE_LIMITED');
  assert.equal((await t.call(null, 'POST', '/v1/agents', {})).status, 429, 'IP budget is shared by limited routes');
  // non-limited endpoints still reachable
  assert.equal((await t.call(null, 'GET', '/healthz')).status, 200);
  assert.equal((await t.call(t.admin, 'GET', '/v1/operators')).status, 200);
});

test('KYA_RATE_LIMIT_ENABLED=false disables limiting', async (tc) => {
  const t = await startApp({ env: { KYA_RATE_LIMIT_ENABLED: 'false', KYA_RATE_LIMIT_IP_PER_WINDOW: '1' } });
  tc.after(t.close);
  for (let i = 0; i < 3; i++) assert.equal((await t.call(null, 'POST', '/v1/verify', {})).status, 401);
});
