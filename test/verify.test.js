// End-to-end vertical slice + negative security tests for POST /v1/verify.
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { test } from 'node:test';
import { signCredential } from '../src/crypto/credentials.js';
import { b64u } from '../src/crypto/ed25519.js';
import { createBusiness, createGrant, createOperator, registerAgent, world } from './helpers.js';

const reason = (r) => r.reasons[0].code;

async function issue(w, grantId = w.grant.id, ttlSeconds) {
  const res = await w.t.call(w.operator.key, 'POST', `/v1/agents/${w.agent.agent.id}/credentials`, { grantId, ...(ttlSeconds ? { ttlSeconds } : {}) });
  assert.equal(res.status, 201, res.text);
  return res.body;
}

test('vertical slice: registered agent signed request is ALLOWed and audited', async (tc) => {
  const w = await world();
  tc.after(w.t.close);

  const r = await w.verify(w.signed());
  assert.equal(r.decision, 'ALLOW');
  assert.deepEqual(r.reasons.map((x) => x.code), ['ALLOWED']);
  assert.equal(r.agentId, w.agent.agent.id);
  assert.equal(r.operatorId, w.operator.op.id);
  assert.equal(r.grantId, w.grant.id);
  assert.equal(r.credentialId, null);
  assert.match(r.verificationId, /^vrf_/);

  // audit log (dashboard data source)
  const log = await w.t.call(w.business.key, 'GET', '/v1/verifications');
  assert.equal(log.status, 200);
  assert.equal(log.body.data.length, 1);
  assert.equal(log.body.data[0].verificationId, r.verificationId);
  assert.equal(log.body.data[0].businessId, w.business.biz.id);
  assert.equal((await w.t.call(w.t.admin, 'GET', '/v1/verifications?decision=ALLOW')).body.data.length, 1);
  assert.equal((await w.t.call(w.operator.key, 'GET', '/v1/verifications')).status, 403);
});

test('ALLOW with a signed, scoped, key-bound credential', async (tc) => {
  const w = await world();
  tc.after(w.t.close);
  const { credential, record } = await issue(w);
  assert.equal(record.status, 'active');
  const [h, p] = credential.split('.');
  assert.deepEqual(JSON.parse(Buffer.from(h, 'base64url')), { alg: 'EdDSA', typ: 'kya-credential+jwt', kid: w.t.config.kid });
  const claims = JSON.parse(Buffer.from(p, 'base64url'));
  assert.equal(claims.sub, w.agent.agent.id);
  assert.equal(claims.aud, w.business.biz.id);
  assert.equal(claims.cnf.jkt, w.agent.agent.keyThumbprint);
  assert.equal(claims.exp - claims.iat, w.t.config.credentialDefaultTtlSeconds);
  assert.deepEqual(claims.kya_actions, ['payments:create']);

  const r = await w.verify(w.signed({ credential }));
  assert.equal(r.decision, 'ALLOW', JSON.stringify(r));
  assert.equal(r.credentialId, record.id);
  assert.equal(r.grantId, w.grant.id);
});

test('DENY: tampered signature, and the nonce is not consumed by the failed attempt', async (tc) => {
  const w = await world();
  tc.after(w.t.close);
  const good = w.signed();
  const bad = structuredClone(good);
  const sig = Buffer.from(bad.signedRequest.signature, 'base64url');
  sig[0] ^= 0x01;
  bad.signedRequest.signature = b64u(sig);
  assert.equal(reason(await w.verify(bad)), 'SIGNATURE_INVALID');
  assert.equal((await w.verify(good)).decision, 'ALLOW');
});

test('DENY: tampered signed fields', async (tc) => {
  const w = await world();
  tc.after(w.t.close);

  // Unsigned body disagrees with the signed context hash.
  const ctxTamper = w.signed();
  ctxTamper.context.amount = 9999;
  assert.equal(reason(await w.verify(ctxTamper)), 'MALFORMED_REQUEST');

  // Body and signed action both changed consistently: the signature no longer matches.
  const actionTamper = w.signed();
  actionTamper.action = 'payments:refund';
  actionTamper.signedRequest.action = 'payments:refund';
  assert.equal(reason(await w.verify(actionTamper)), 'SIGNATURE_INVALID');

  // Context tampered in both places, hash recomputed: signature fails.
  const hashTamper = w.signed({ context: { amount: 1, currency: 'USD' } });
  const other = w.signed({ context: { amount: 9000, currency: 'USD' } });
  hashTamper.context = other.context;
  hashTamper.signedRequest.contextSha256 = other.signedRequest.contextSha256;
  assert.equal(reason(await w.verify(hashTamper)), 'SIGNATURE_INVALID');

  // Signed by a different key.
  const impostor = await registerAgent(w.t, w.operator, 'Impostor');
  assert.equal(reason(await w.verify(w.signed({ privateKey: impostor.privateKey }))), 'SIGNATURE_INVALID');
});

test('DENY: timestamp outside the window (expired or future)', async (tc) => {
  const w = await world();
  tc.after(w.t.close);
  const skew = w.t.config.maxSkewSeconds;
  assert.equal(reason(await w.verify(w.signed({ timestamp: w.t.nowSec() - skew - 1 }))), 'TIMESTAMP_OUT_OF_WINDOW');
  assert.equal(reason(await w.verify(w.signed({ timestamp: w.t.nowSec() + skew + 1 }))), 'TIMESTAMP_OUT_OF_WINDOW');
  assert.equal((await w.verify(w.signed({ timestamp: w.t.nowSec() - skew }))).decision, 'ALLOW');
});

test('DENY: replayed request (same nonce)', async (tc) => {
  const w = await world();
  tc.after(w.t.close);
  const body = w.signed();
  assert.equal((await w.verify(body)).decision, 'ALLOW');
  assert.equal(reason(await w.verify(body)), 'NONCE_REPLAYED');
  // Still replayed near the end of the acceptance window.
  w.t.advance(w.t.config.maxSkewSeconds);
  assert.equal(reason(await w.verify(body)), 'NONCE_REPLAYED');
  // After the window it is rejected by timestamp before the nonce is consulted.
  w.t.advance(1);
  assert.equal(reason(await w.verify(body)), 'TIMESTAMP_OUT_OF_WINDOW');
});

test('DENY: out-of-scope action and constraint violations', async (tc) => {
  const w = await world();
  tc.after(w.t.close);
  assert.equal(reason(await w.verify(w.signed({ action: 'payments:refund' }))), 'ACTION_NOT_PERMITTED');
  assert.equal(reason(await w.verify(w.signed({ action: 'payments' }))), 'ACTION_NOT_PERMITTED');
  assert.equal(reason(await w.verify(w.signed({ context: { amount: 10001, currency: 'USD' } }))), 'CONSTRAINT_VIOLATION');
  assert.equal(reason(await w.verify(w.signed({ context: { amount: 100, currency: 'EUR' } }))), 'CONSTRAINT_VIOLATION');
  assert.equal(reason(await w.verify(w.signed({ context: { currency: 'USD' } }))), 'CONSTRAINT_VIOLATION');
  assert.equal(reason(await w.verify(w.signed({ context: { amount: -5, currency: 'USD' } }))), 'CONSTRAINT_VIOLATION');
  assert.equal(reason(await w.verify(w.signed({ context: undefined }))), 'CONSTRAINT_VIOLATION');
  assert.equal((await w.verify(w.signed({ context: { amount: 10000, currency: 'USD' } }))).decision, 'ALLOW');

  // Out of scope for a credential too.
  const { credential } = await issue(w);
  assert.equal(reason(await w.verify(w.signed({ credential, action: 'orders:create' }))), 'ACTION_NOT_PERMITTED');
  assert.equal(reason(await w.verify(w.signed({ credential, context: { amount: 20000, currency: 'USD' } }))), 'CONSTRAINT_VIOLATION');
});

test('wildcard grants and resource constraints', async (tc) => {
  const w = await world();
  tc.after(w.t.close);
  await createGrant(w.t, w.business, w.agent.agent.id, { actions: ['orders:*'], constraints: { resources: ['order-1'] } });
  assert.equal((await w.verify(w.signed({ action: 'orders:refund:partial', resource: 'order-1', context: {} }))).decision, 'ALLOW');
  assert.equal(reason(await w.verify(w.signed({ action: 'orders:create', resource: 'order-2', context: {} }))), 'CONSTRAINT_VIOLATION');
  assert.equal(reason(await w.verify(w.signed({ action: 'orders', resource: 'order-1', context: {} }))), 'ACTION_NOT_PERMITTED');
});

test('DENY: audience mismatch, unknown agent, no grant', async (tc) => {
  const w = await world();
  tc.after(w.t.close);
  const other = await createBusiness(w.t, 'Initech');
  // Request signed for business A replayed to business B.
  assert.equal(reason(await w.verify(w.signed(), other.key)), 'AUDIENCE_MISMATCH');
  // Correct audience but B granted nothing.
  assert.equal(reason(await w.verify(w.signed({ audience: other.biz.id }), other.key)), 'NO_GRANT');
  const unknown = w.signed({ agentId: 'agt_01J8ZQ4Y5N3V6K2M7P9R0S1T2V' });
  const r = await w.verify(unknown);
  assert.equal(reason(r), 'AGENT_NOT_FOUND');
  assert.equal(r.decision, 'DENY');
  assert.equal(reason(await w.verify(w.signed({ agentId: 'not-an-id' }))), 'AGENT_NOT_FOUND');
});

test('DENY (fail closed) on malformed input, never a 400', async (tc) => {
  const w = await world();
  tc.after(w.t.close);
  const post = (opts) => w.t.call(w.business.key, 'POST', '/v1/verify', undefined, opts);

  const cases = [
    await post({ raw: '{not json', headers: { 'content-type': 'application/json' } }),
    await post({ raw: JSON.stringify(w.signed()), headers: { 'content-type': 'text/plain' } }),
    await post({ raw: '[]', headers: { 'content-type': 'application/json' } }),
    await post({ raw: 'null', headers: { 'content-type': 'application/json' } }),
    await post({ raw: JSON.stringify({ ...w.signed(), extra: 1 }), headers: { 'content-type': 'application/json' } }),
    await post({ raw: JSON.stringify({ agentId: w.agent.agent.id, action: 'payments:create' }), headers: { 'content-type': 'application/json' } }),
    await post({ raw: JSON.stringify({ ...w.signed(), padding: 'x'.repeat(70000) }), headers: { 'content-type': 'application/json' } }),
  ];
  const floatBody = w.signed({ context: { amount: 1, currency: 'USD' } });
  floatBody.context.amount = 1.5;
  cases.push(await post({ raw: JSON.stringify(floatBody), headers: { 'content-type': 'application/json' } }));
  let deep = {};
  for (let i = 0; i < 100; i++) deep = { d: deep };
  const deepBody = w.signed({ context: {} });
  deepBody.context = deep;
  cases.push(await post({ raw: JSON.stringify(deepBody), headers: { 'content-type': 'application/json' } }));
  const newlineBody = w.signed();
  newlineBody.signedRequest.nonce = 'short';
  cases.push(await post({ raw: JSON.stringify(newlineBody), headers: { 'content-type': 'application/json' } }));

  for (const res of cases) {
    assert.equal(res.status, 200, res.text);
    assert.equal(res.body.decision, 'DENY');
    assert.equal(res.body.reasons.length, 1);
    assert.equal(res.body.reasons[0].code, 'MALFORMED_REQUEST');
  }
  const log = await w.t.call(w.business.key, 'GET', '/v1/verifications?decision=DENY&limit=100');
  assert.equal(log.body.data.length, cases.length);
});

test('DENY with INTERNAL_ERROR (HTTP 500) when the store fails', async (tc) => {
  const w = await world();
  tc.after(w.t.close);
  w.t.store.agents.findById = async () => {
    throw new Error('store down');
  };
  const res = await w.t.call(w.business.key, 'POST', '/v1/verify', w.signed());
  assert.equal(res.status, 500);
  assert.equal(res.body.decision, 'DENY');
  assert.equal(res.body.reasons[0].code, 'INTERNAL_ERROR');
  assert.ok(!res.text.includes('store down'));
});

test('DENY when the audit event cannot be written (no unaudited ALLOW)', async (tc) => {
  const w = await world();
  tc.after(w.t.close);
  w.t.store.verificationEvents.insert = async () => {
    throw new Error('audit down');
  };
  const res = await w.t.call(w.business.key, 'POST', '/v1/verify', w.signed());
  assert.equal(res.status, 500);
  assert.equal(res.body.decision, 'DENY');
  assert.equal(res.body.reasons[0].code, 'INTERNAL_ERROR');
});

test('DENY: expired, not-yet-valid, tampered and forged credentials', async (tc) => {
  const w = await world();
  tc.after(w.t.close);
  const { credential } = await issue(w, w.grant.id, 60);
  const [h, p, s] = credential.split('.');

  // tampered payload (widen scope) with original signature
  const claims = JSON.parse(Buffer.from(p, 'base64url'));
  claims.kya_actions = ['payments:*'];
  const tampered = `${h}.${b64u(Buffer.from(JSON.stringify(claims)))}.${s}`;
  assert.equal(reason(await w.verify(w.signed({ credential: tampered }))), 'CREDENTIAL_INVALID');

  // alg=none
  const none = `${b64u(Buffer.from(JSON.stringify({ alg: 'none', typ: 'kya-credential+jwt', kid: w.t.config.kid })))}.${p}.`;
  assert.equal(reason(await w.verify(w.signed({ credential: none }))), 'CREDENTIAL_INVALID');
  // HS256 header with the original signature
  const hs = `${b64u(Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'kya-credential+jwt', kid: w.t.config.kid })))}.${p}.${s}`;
  assert.equal(reason(await w.verify(w.signed({ credential: hs }))), 'CREDENTIAL_INVALID');
  // garbage
  assert.equal(reason(await w.verify(w.signed({ credential: 'a.b.c' }))), 'CREDENTIAL_INVALID');

  // Correctly server-signed but bound to another key / unknown jti / wrong issuer.
  const serverSign = (c) => signCredential(c, { privateKey: w.t.config.signingKey, kid: w.t.config.kid });
  const original = JSON.parse(Buffer.from(p, 'base64url'));
  assert.equal(reason(await w.verify(w.signed({ credential: serverSign({ ...original, cnf: { jkt: 'x'.repeat(43) } }) }))), 'CREDENTIAL_KEY_MISMATCH');
  assert.equal(reason(await w.verify(w.signed({ credential: serverSign({ ...original, jti: 'crd_01J8ZQ4Y5N3V6K2M7P9R0S1T2V' }) }))), 'CREDENTIAL_INVALID');
  assert.equal(reason(await w.verify(w.signed({ credential: serverSign({ ...original, iss: 'someone-else' }) }))), 'CREDENTIAL_INVALID');
  // Signed by a key that is not the server key.
  const rogue = signCredential(original, { privateKey: generateKeyPairSync('ed25519').privateKey, kid: w.t.config.kid });
  assert.equal(reason(await w.verify(w.signed({ credential: rogue }))), 'CREDENTIAL_INVALID');

  // not yet valid (verifier clock behind the issue time)
  w.t.advance(-10);
  assert.equal(reason(await w.verify(w.signed({ credential }))), 'CREDENTIAL_NOT_YET_VALID');

  // expired
  w.t.advance(71);
  assert.equal(reason(await w.verify(w.signed({ credential }))), 'CREDENTIAL_EXPIRED');
});

test('DENY: credential presented by the wrong agent or to the wrong business', async (tc) => {
  const w = await world();
  tc.after(w.t.close);
  const { credential } = await issue(w);

  // Another agent (own key, valid signature) presents a stolen credential.
  const thief = await registerAgent(w.t, w.operator, 'Thief');
  const stolen = w.signed({ privateKey: thief.privateKey, agentId: thief.agent.id, credential });
  assert.equal(reason(await w.verify(stolen)), 'CREDENTIAL_SUBJECT_MISMATCH');

  // Credential for business A presented to business B.
  const other = await createBusiness(w.t, 'Initech');
  await createGrant(w.t, other, w.agent.agent.id);
  assert.equal(reason(await w.verify(w.signed({ audience: other.biz.id, credential }), other.key)), 'CREDENTIAL_AUDIENCE_MISMATCH');
});

test('revocation is enforced on the very next verification', async (tc) => {
  const w = await world();
  tc.after(w.t.close);
  const { credential, record } = await issue(w);
  assert.equal((await w.verify(w.signed({ credential }))).decision, 'ALLOW');

  // credential revoked (by the business that is its audience)
  const rev = await w.t.call(w.business.key, 'POST', `/v1/credentials/${record.id}/revoke`, { reason: 'test' });
  assert.equal(rev.status, 200);
  assert.equal(rev.body.status, 'revoked');
  assert.equal(reason(await w.verify(w.signed({ credential }))), 'CREDENTIAL_REVOKED');
  assert.equal((await w.t.call(w.business.key, 'POST', `/v1/credentials/${record.id}/revoke`, { reason: 'again' })).status, 409);

  // grant revoked: derived credentials and direct grant evaluation both deny
  const second = await issue(w);
  assert.equal((await w.t.call(w.business.key, 'POST', `/v1/grants/${w.grant.id}/revoke`, { reason: 'test' })).status, 200);
  assert.equal(reason(await w.verify(w.signed({ credential: second.credential }))), 'GRANT_REVOKED');
  assert.equal(reason(await w.verify(w.signed())), 'NO_GRANT');
  // cannot issue for a revoked grant
  assert.equal((await w.t.call(w.operator.key, 'POST', `/v1/agents/${w.agent.agent.id}/credentials`, { grantId: w.grant.id })).status, 409);
});

test('agent suspend / reactivate / revoke and operator suspension', async (tc) => {
  const w = await world();
  tc.after(w.t.close);
  const path = `/v1/agents/${w.agent.agent.id}`;

  assert.equal((await w.t.call(w.operator.key, 'POST', `${path}/suspend`, { reason: 'maintenance' })).status, 200);
  assert.equal(reason(await w.verify(w.signed())), 'AGENT_SUSPENDED');
  assert.equal((await w.t.call(w.operator.key, 'POST', `${path}/reactivate`)).status, 200);
  assert.equal((await w.verify(w.signed())).decision, 'ALLOW');

  const revoked = await w.t.call(w.operator.key, 'POST', `${path}/revoke`, { reason: 'compromised' });
  assert.equal(revoked.status, 200);
  assert.equal(revoked.body.status, 'revoked');
  assert.ok(revoked.body.revokedAt);
  assert.equal(reason(await w.verify(w.signed())), 'AGENT_REVOKED');
  assert.equal((await w.t.call(w.operator.key, 'POST', `${path}/revoke`, { reason: 'again' })).status, 409);
  assert.equal((await w.t.call(w.operator.key, 'POST', `${path}/reactivate`)).status, 409);

  // operator suspension: all its agents deny, its API keys stop working
  const agent2 = await registerAgent(w.t, w.operator, 'Second');
  await createGrant(w.t, w.business, agent2.agent.id);
  assert.equal((await w.t.call(w.t.admin, 'POST', `/v1/operators/${w.operator.op.id}/suspend`, { reason: 'fraud' })).status, 200);
  assert.equal(reason(await w.verify(w.signed({ privateKey: agent2.privateKey, agentId: agent2.agent.id }))), 'OPERATOR_SUSPENDED');
  assert.equal((await w.t.call(w.operator.key, 'GET', '/v1/agents')).status, 401);
});

test('unverified operator agents are denied', async (tc) => {
  const w = await world();
  tc.after(w.t.close);
  // Simulate an operator whose status regressed (e.g. data fix) — verify re-reads it.
  await w.t.store.operators.update(w.operator.op.id, null, { status: 'pending' });
  assert.equal(reason(await w.verify(w.signed())), 'OPERATOR_NOT_VERIFIED');
});

test('only authenticated businesses can call /v1/verify; no decision or event otherwise', async (tc) => {
  const w = await world();
  tc.after(w.t.close);
  const anon = await w.t.call(null, 'POST', '/v1/verify', w.signed());
  assert.equal(anon.status, 401);
  assert.equal(anon.body.error.code, 'UNAUTHENTICATED');
  assert.equal(anon.headers.get('www-authenticate'), 'Bearer');
  assert.equal((await w.t.call(w.operator.key, 'POST', '/v1/verify', w.signed())).status, 403);
  assert.equal((await w.t.call(w.t.admin, 'POST', '/v1/verify', w.signed())).status, 403);
  assert.equal((await w.t.call(w.t.admin, 'GET', '/v1/verifications')).body.data.length, 0);
});

test('operators pending verification cannot register agents', async (tc) => {
  const w = await world();
  tc.after(w.t.close);
  const pending = await createOperator(w.t, { legalName: 'Pending Co', verify: false });
  await assert.rejects(registerAgent(w.t, pending), /409/);
});
