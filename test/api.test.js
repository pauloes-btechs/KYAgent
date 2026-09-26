// Management API: onboarding, registration, grants, API keys, RBAC and tenancy.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { generateEd25519, signMessage, b64u } from '../src/crypto/ed25519.js';
import { proofOfPossession } from '../src/sdk/agentSigner.js';
import { createBusiness, createGrant, createOperator, registerAgent, startApp, world } from './helpers.js';

test('public endpoints: healthz, JWKS, dashboard with CSP', async (tc) => {
  const t = await startApp();
  tc.after(t.close);
  const health = await t.call(null, 'GET', '/healthz');
  assert.deepEqual(health.body, { status: 'ok', store: 'memory' });
  const jwks = await t.call(null, 'GET', '/.well-known/jwks.json');
  assert.equal(jwks.body.keys.length, 1);
  const [k] = jwks.body.keys;
  assert.deepEqual({ ...k, x: undefined }, { kty: 'OKP', crv: 'Ed25519', x: undefined, kid: t.config.kid, alg: 'EdDSA', use: 'sig' });
  assert.equal(k.d, undefined, 'private key material must never be published');
  const dash = await t.call(null, 'GET', '/dashboard/');
  assert.equal(dash.status, 200);
  assert.match(dash.headers.get('content-security-policy'), /script-src 'self'/);
  assert.match(dash.text, /KYAgent/);
  assert.equal((await t.call(null, 'GET', '/dashboard/app.js')).status, 200);
  assert.equal((await t.call(null, 'GET', '/dashboard/../package.json')).status, 404);
  assert.equal((await t.call(null, 'GET', '/dashboard/__proto__')).status, 404);
  const missing = await t.call(t.admin, 'GET', '/v1/nope');
  assert.equal(missing.status, 404);
  assert.equal(missing.body.error.code, 'NOT_FOUND');
  assert.equal(missing.body.error.requestId, missing.headers.get('x-request-id'));
});

test('operator onboarding: mock KYC and sanctions screening', async (tc) => {
  const t = await startApp();
  tc.after(t.close);
  const ok = await createOperator(t);
  const op = (await t.call(t.admin, 'GET', `/v1/operators/${ok.op.id}`)).body;
  assert.equal(op.status, 'verified');
  assert.equal(op.contactEmail, 'ops@acme.example');
  assert.deepEqual({ ...op.verification, checkedAt: undefined }, { method: 'mock', kycResult: 'pass', sanctionsMode: 'mock', sanctionsResult: 'clear', checkedAt: undefined });
  assert.equal((await t.call(t.admin, 'POST', `/v1/operators/${op.id}/verification`)).status, 409);

  const kycFail = await createOperator(t, { legalName: 'fail_kyc Ltd' });
  assert.equal((await t.call(t.admin, 'GET', `/v1/operators/${kycFail.op.id}`)).body.status, 'rejected');
  // rejected operators cannot authenticate
  assert.equal((await t.call(kycFail.key, 'GET', `/v1/operators/${kycFail.op.id}`)).status, 401);

  const sanctioned = await createOperator(t, { legalName: 'Sanctioned Holdings' });
  const s = (await t.call(t.admin, 'GET', `/v1/operators/${sanctioned.op.id}`)).body;
  assert.equal(s.status, 'rejected');
  assert.equal(s.verification.sanctionsResult, 'hit');

  const bad = await t.call(t.admin, 'POST', '/v1/operators', { type: 'robot', legalName: '', contactEmail: 'x', country: 'gb', extra: 1 });
  assert.equal(bad.status, 400);
  assert.equal(bad.body.error.code, 'VALIDATION_ERROR');
  assert.ok(bad.body.error.details.some((d) => d.path === '/extra'));
});

test('SANCTIONS_MODE=off skips screening; unknown modes fail safe to mock', async (tc) => {
  const off = await startApp({ env: { SANCTIONS_MODE: 'off' } });
  tc.after(off.close);
  const a = await createOperator(off, { legalName: 'Sanctioned Holdings' });
  const op = (await off.call(off.admin, 'GET', `/v1/operators/${a.op.id}`)).body;
  assert.equal(op.verification.sanctionsResult, 'skipped');
  assert.equal(op.status, 'verified');

  const live = await startApp({ env: { SANCTIONS_MODE: 'live' } });
  tc.after(live.close);
  assert.equal(live.config.sanctionsMode, 'mock');
});

test('agent registration requires a valid proof of possession', async (tc) => {
  const t = await startApp();
  tc.after(t.close);
  const operator = await createOperator(t);
  const other = await createOperator(t, { legalName: 'Other Ops' });
  const key = generateEd25519();

  const noPop = await t.call(operator.key, 'POST', '/v1/agents', { name: 'a', publicKey: key.publicKey, proofOfPossession: 'A'.repeat(86) });
  assert.equal(noPop.status, 400);
  assert.equal(noPop.body.error.details[0].path, '/proofOfPossession');

  // PoP bound to another operator id cannot be replayed here
  const foreignPop = proofOfPossession(key.privateKey, other.op.id, key.publicKey);
  assert.equal((await t.call(operator.key, 'POST', '/v1/agents', { name: 'a', publicKey: key.publicKey, proofOfPossession: foreignPop })).status, 400);

  // Non-canonical base64url encoding of the same key is rejected
  const last = key.publicKey.at(-1);
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  const alt = key.publicKey.slice(0, -1) + alphabet[(alphabet.indexOf(last) & ~3) | ((alphabet.indexOf(last) + 1) & 3)];
  assert.equal((await t.call(operator.key, 'POST', '/v1/agents', { name: 'a', publicKey: alt, proofOfPossession: proofOfPossession(key.privateKey, operator.op.id, alt) })).status, 400);

  const ok = await t.call(operator.key, 'POST', '/v1/agents', { name: 'a', publicKey: key.publicKey, proofOfPossession: proofOfPossession(key.privateKey, operator.op.id, key.publicKey) });
  assert.equal(ok.status, 201);
  assert.equal(ok.body.operatorId, operator.op.id);
  assert.equal(ok.body.status, 'active');
  assert.match(ok.body.keyThumbprint, /^[A-Za-z0-9_-]{43}$/);

  // duplicate key (even from another operator)
  const dup = await t.call(other.key, 'POST', '/v1/agents', { name: 'b', publicKey: key.publicKey, proofOfPossession: proofOfPossession(key.privateKey, other.op.id, key.publicKey) });
  assert.equal(dup.status, 409);
  assert.equal(dup.body.error.code, 'CONFLICT');

  // server never stores private keys
  const stored = await t.store.agents.findById(ok.body.id);
  assert.deepEqual(Object.keys(stored).sort(), ['createdAt', 'description', 'id', 'keyThumbprint', 'name', 'operatorId', 'publicKey', 'revokedAt', 'status', 'statusReason', 'updatedAt']);
  assert.ok(signMessage(key.privateKey, 'x'));
});

test('RBAC and tenant isolation (cross-tenant reads return 404)', async (tc) => {
  const w = await world();
  const { t } = w;
  tc.after(t.close);
  const opB = await createOperator(t, { legalName: 'Operator B' });
  const agentB = await registerAgent(t, opB, 'B bot');
  const bizB = await createBusiness(t, 'Business B');
  const grantB = await createGrant(t, bizB, agentB.agent.id);

  // role gates
  assert.equal((await t.call(w.business.key, 'POST', '/v1/agents', {})).status, 403);
  assert.equal((await t.call(w.business.key, 'GET', '/v1/agents')).status, 403);
  assert.equal((await t.call(w.operator.key, 'POST', '/v1/grants', {})).status, 403);
  assert.equal((await t.call(w.operator.key, 'GET', '/v1/api-keys')).status, 403);
  assert.equal((await t.call(w.business.key, 'POST', '/v1/operators', {})).status, 403);
  assert.equal((await t.call(w.operator.key, 'POST', `/v1/grants/${w.grant.id}/revoke`, { reason: 'x' })).status, 403);

  // ownership
  assert.equal((await t.call(w.operator.key, 'GET', `/v1/agents/${agentB.agent.id}`)).status, 404);
  assert.equal((await t.call(w.operator.key, 'POST', `/v1/agents/${agentB.agent.id}/revoke`, { reason: 'x' })).status, 404);
  assert.equal((await t.call(w.operator.key, 'GET', `/v1/operators/${opB.op.id}`)).status, 404);
  assert.equal((await t.call(w.business.key, 'GET', `/v1/grants/${grantB.id}`)).status, 404);
  assert.equal((await t.call(w.business.key, 'POST', `/v1/grants/${grantB.id}/revoke`, { reason: 'x' })).status, 404);
  assert.equal((await t.call(w.business.key, 'GET', `/v1/businesses/${bizB.biz.id}`)).status, 404);
  assert.equal((await t.call(w.operator.key, 'POST', `/v1/agents/${agentB.agent.id}/credentials`, { grantId: grantB.id })).status, 404);
  // cannot issue a credential for another agent's grant
  assert.equal((await t.call(w.operator.key, 'POST', `/v1/agents/${w.agent.agent.id}/credentials`, { grantId: grantB.id })).status, 404);

  // operator list is forced to own agents even with a filter
  const list = await t.call(w.operator.key, 'GET', `/v1/agents?operatorId=${opB.op.id}`);
  assert.deepEqual(list.body.data.map((a) => a.id), [w.agent.agent.id]);
  // operators see grants to their agents; businesses see their own
  assert.deepEqual((await t.call(w.operator.key, 'GET', '/v1/grants')).body.data.map((g) => g.id), [w.grant.id]);
  assert.deepEqual((await t.call(bizB.key, 'GET', '/v1/grants')).body.data.map((g) => g.id), [grantB.id]);

  // businesses: public identity lookups
  const agentView = await t.call(w.business.key, 'GET', `/v1/agents/${agentB.agent.id}`);
  assert.equal(agentView.status, 200);
  const opView = (await t.call(w.business.key, 'GET', `/v1/operators/${opB.op.id}`)).body;
  assert.deepEqual(Object.keys(opView).sort(), ['country', 'id', 'legalName', 'status', 'type']);

  // invalid ids and queries
  assert.equal((await t.call(t.admin, 'GET', '/v1/agents/nope')).status, 400);
  assert.equal((await t.call(t.admin, 'GET', '/v1/agents?limit=0')).status, 400);
  assert.equal((await t.call(t.admin, 'GET', '/v1/agents?cursor=%%%')).status, 400);
});

test('pagination with cursors', async (tc) => {
  const t = await startApp();
  tc.after(t.close);
  for (let i = 0; i < 5; i++) {
    await t.call(t.admin, 'POST', '/v1/businesses', { name: `b${i}` });
    t.advance(1);
  }
  const p1 = (await t.call(t.admin, 'GET', '/v1/businesses?limit=2')).body;
  assert.deepEqual(p1.data.map((b) => b.name), ['b4', 'b3']);
  const p2 = (await t.call(t.admin, 'GET', `/v1/businesses?limit=2&cursor=${p1.nextCursor}`)).body;
  assert.deepEqual(p2.data.map((b) => b.name), ['b2', 'b1']);
  const p3 = (await t.call(t.admin, 'GET', `/v1/businesses?limit=2&cursor=${p2.nextCursor}`)).body;
  assert.deepEqual(p3.data.map((b) => b.name), ['b0']);
  assert.equal(p3.nextCursor, null);
});

test('API keys are hashed at rest, shown once, and revocable', async (tc) => {
  const t = await startApp();
  tc.after(t.close);
  const biz = (await t.call(t.admin, 'POST', '/v1/businesses', { name: 'Acme' })).body;
  const created = await t.call(t.admin, 'POST', '/v1/api-keys', { name: 'k', role: 'business', ownerId: biz.id });
  assert.equal(created.status, 201);
  assert.equal(created.headers.get('cache-control'), 'no-store');
  const { secret, apiKey } = created.body;
  assert.match(secret, /^kya_key_[0-9A-HJKMNP-TV-Z]{26}_[A-Za-z0-9_-]{43}$/);
  assert.equal(apiKey.displayPrefix, `kya_${apiKey.id}`);
  assert.equal(apiKey.secretHash, undefined);

  const stored = await t.store.apiKeys.findById(apiKey.id);
  const plainSecret = secret.slice(35);
  assert.match(stored.secretHash, /^[0-9a-f]{64}$/);
  assert.ok(!JSON.stringify(stored).includes(plainSecret), 'plaintext secret must not be stored');

  const listed = await t.call(t.admin, 'GET', '/v1/api-keys');
  assert.ok(!listed.text.includes(plainSecret));
  assert.ok(!listed.text.includes('secretHash'));

  assert.equal((await t.call(secret, 'GET', `/v1/businesses/${biz.id}`)).status, 200);
  // wrong secret with the right key id
  const wrong = `${secret.slice(0, 35)}${'A'.repeat(43)}`;
  assert.equal((await t.call(wrong, 'GET', `/v1/businesses/${biz.id}`)).status, 401);
  assert.equal((await t.call('garbage', 'GET', `/v1/businesses/${biz.id}`)).status, 401);

  assert.equal((await t.call(t.admin, 'POST', `/v1/api-keys/${apiKey.id}/revoke`)).status, 200);
  const after = await t.call(secret, 'GET', `/v1/businesses/${biz.id}`);
  assert.equal(after.status, 401);
  assert.equal(after.body.error.message, 'Missing or invalid API key');
  assert.equal((await t.call(t.admin, 'POST', `/v1/api-keys/${apiKey.id}/revoke`)).status, 409);

  // ownerId rules
  assert.equal((await t.call(t.admin, 'POST', '/v1/api-keys', { name: 'k', role: 'admin', ownerId: biz.id })).status, 400);
  assert.equal((await t.call(t.admin, 'POST', '/v1/api-keys', { name: 'k', role: 'operator' })).status, 400);
  assert.equal((await t.call(t.admin, 'POST', '/v1/api-keys', { name: 'k', role: 'operator', ownerId: 'op_01J8ZQ4Y5N3V6K2M7P9R0S1T2V' })).status, 404);
});

test('grant validation', async (tc) => {
  const w = await world();
  tc.after(w.t.close);
  const post = (body) => w.t.call(w.business.key, 'POST', '/v1/grants', body);
  const future = new Date(w.t.nowSec() * 1000 + 3600_000).toISOString();
  const id = w.agent.agent.id;
  assert.equal((await post({ agentId: id, actions: ['*'], expiresAt: future })).status, 400);
  assert.equal((await post({ agentId: id, actions: ['Orders:Create'], expiresAt: future })).status, 400);
  assert.equal((await post({ agentId: id, actions: ['a', 'a'], expiresAt: future })).status, 400);
  assert.equal((await post({ agentId: id, actions: ['a'], expiresAt: new Date(0).toISOString() })).status, 400);
  assert.equal((await post({ agentId: id, actions: ['a'], expiresAt: new Date(Date.now() + 400 * 86400_000).toISOString() })).status, 400);
  assert.equal((await post({ agentId: id, actions: ['a'], expiresAt: future, constraints: { maxAmount: 1.5 } })).status, 400);
  assert.equal((await post({ agentId: 'agt_01J8ZQ4Y5N3V6K2M7P9R0S1T2V', actions: ['a'], expiresAt: future })).status, 404);
  const unsupported = await w.t.call(w.business.key, 'POST', '/v1/grants', undefined, { raw: 'x', headers: { 'content-type': 'text/plain' } });
  assert.equal(unsupported.status, 415);
  const tooBig = await w.t.call(w.business.key, 'POST', '/v1/grants', { agentId: id, actions: ['a'], expiresAt: future, pad: 'x'.repeat(70000) });
  assert.equal(tooBig.status, 413);

  // grants cannot target a revoked agent
  await w.t.call(w.operator.key, 'POST', `/v1/agents/${id}/revoke`, { reason: 'x' });
  assert.equal((await post({ agentId: id, actions: ['a'], expiresAt: future })).status, 409);
});

test('credential issuance rules', async (tc) => {
  const w = await world();
  tc.after(w.t.close);
  const path = `/v1/agents/${w.agent.agent.id}/credentials`;
  assert.equal((await w.t.call(w.operator.key, 'POST', path, { grantId: w.grant.id, ttlSeconds: 59 })).status, 400);
  assert.equal((await w.t.call(w.operator.key, 'POST', path, { grantId: w.grant.id, ttlSeconds: 3601 })).status, 400);
  // exp is capped by the grant expiry
  const short = await createGrant(w.t, w.business, w.agent.agent.id, { seconds: 100 });
  const res = await w.t.call(w.operator.key, 'POST', path, { grantId: short.id, ttlSeconds: 3600 });
  assert.equal(res.status, 201);
  assert.equal(res.headers.get('cache-control'), 'no-store');
  assert.equal(res.body.record.expiresAt, short.expiresAt);
  // the JWS itself is never persisted
  const stored = await w.t.store.credentials.findById(res.body.record.id);
  assert.ok(!JSON.stringify(stored).includes(res.body.credential.split('.')[2]));
  // listing credentials never returns the JWS
  const list = await w.t.call(w.business.key, 'GET', '/v1/credentials');
  assert.equal(list.body.data.length, 1);
  assert.equal(list.body.data[0].credential, undefined);
});

test('suspending an operator requires admin and a verified operator', async (tc) => {
  const t = await startApp();
  tc.after(t.close);
  const pending = await createOperator(t, { verify: false });
  assert.equal((await t.call(t.admin, 'POST', `/v1/operators/${pending.op.id}/suspend`, { reason: 'x' })).status, 409);
  assert.equal((await t.call(t.admin, 'POST', `/v1/operators/${pending.op.id}/suspend`, {})).status, 400);
  assert.equal(b64u(Buffer.from('ok')), 'b2s');
});
