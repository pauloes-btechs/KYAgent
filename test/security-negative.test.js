// REQ-014 integration tests over real HTTP: negative security cases
// (tampered, expired, revoked, replayed, out-of-scope) not covered elsewhere.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { parseApiKey } from '../src/crypto/apiKeys.js';
import { b64u } from '../src/crypto/ed25519.js';
import { createBusiness, createGrant, createOperator, registerAgent, world } from './helpers.js';

const reason = (r) => r.reasons[0].code;
const claimsOf = (jws) => JSON.parse(Buffer.from(jws.split('.')[1], 'base64url'));

async function issue(w, { agent = w.agent, grantId = w.grant.id, ttlSeconds } = {}) {
  const res = await w.t.call(w.operator.key, 'POST', `/v1/agents/${agent.agent.id}/credentials`, { grantId, ...(ttlSeconds ? { ttlSeconds } : {}) });
  assert.equal(res.status, 201, res.text);
  return res.body;
}

test('REQ-014 [tampered]: credential header kid/typ swaps and signature truncation are CREDENTIAL_INVALID', async (tc) => {
  const w = await world();
  tc.after(w.t.close);
  const { credential } = await issue(w);
  const [h, p, s] = credential.split('.');
  const header = JSON.parse(Buffer.from(h, 'base64url'));
  const enc = (o) => b64u(Buffer.from(JSON.stringify(o)));

  const variants = [
    `${enc({ ...header, kid: 'unknown-kid' })}.${p}.${s}`,
    `${enc({ ...header, typ: 'JWT' })}.${p}.${s}`,
    `${h}.${p}.${s.slice(0, -4)}`,
    `${h}.${p}`,
    `${h}.${p}.${s}.extra`,
    `${h}.${enc({ ...claimsOf(credential), sub: 'agt_01J8ZQ4Y5N3V6K2M7P9R0S1T2V' })}.${s}`,
  ];
  for (const v of variants) {
    const r = await w.verify(w.signed({ credential: v }));
    assert.equal(r.decision, 'DENY', v);
    assert.ok(['CREDENTIAL_INVALID', 'MALFORMED_REQUEST'].includes(reason(r)), `${v} -> ${reason(r)}`);
  }
  // the genuine credential still works afterwards
  assert.equal((await w.verify(w.signed({ credential }))).decision, 'ALLOW');
});

test('REQ-014 [tampered]: a request signed by the right key for a different agent id is rejected', async (tc) => {
  const w = await world();
  tc.after(w.t.close);
  const other = await registerAgent(w.t, w.operator, 'Other');
  await createGrant(w.t, w.business, other.agent.id);
  // Agent A's key signs a request claiming to be agent B.
  const r = await w.verify(w.signed({ agentId: other.agent.id }));
  assert.equal(reason(r), 'SIGNATURE_INVALID');
});

test('REQ-014 [expired]: grant expiry is enforced for direct evaluation and for credentials; credential exp is capped at grant expiry', async (tc) => {
  const w = await world();
  tc.after(w.t.close);
  const short = await createGrant(w.t, w.business, w.agent.agent.id, { actions: ['orders:create'], constraints: {}, seconds: 120 });
  const { credential } = await issue(w, { grantId: short.id, ttlSeconds: 3600 });
  const c = claimsOf(credential);
  assert.equal(c.exp, Math.floor(Date.parse(short.expiresAt) / 1000), 'credential exp must not outlive its grant');

  assert.equal((await w.verify(w.signed({ action: 'orders:create', context: {} }))).decision, 'ALLOW');
  assert.equal((await w.verify(w.signed({ action: 'orders:create', context: {}, credential }))).decision, 'ALLOW');

  w.t.advance(121);
  assert.equal(reason(await w.verify(w.signed({ action: 'orders:create', context: {} }))), 'ACTION_NOT_PERMITTED');
  assert.equal(reason(await w.verify(w.signed({ action: 'orders:create', context: {}, credential }))), 'CREDENTIAL_EXPIRED');
  // cannot issue a new credential for the expired grant
  const res = await w.t.call(w.operator.key, 'POST', `/v1/agents/${w.agent.agent.id}/credentials`, { grantId: short.id });
  assert.equal(res.status, 409);
  // grants cannot be created already expired
  const past = await w.t.call(w.business.key, 'POST', '/v1/grants', {
    agentId: w.agent.agent.id,
    actions: ['orders:create'],
    expiresAt: new Date((w.t.nowSec() - 10) * 1000).toISOString(),
  });
  assert.equal(past.status, 400);
});

test('REQ-014 [expired]: TTL above the configured maximum is refused', async (tc) => {
  const w = await world();
  tc.after(w.t.close);
  const res = await w.t.call(w.operator.key, 'POST', `/v1/agents/${w.agent.agent.id}/credentials`, {
    grantId: w.grant.id,
    ttlSeconds: w.t.config.credentialMaxTtlSeconds + 1,
  });
  assert.equal(res.status, 400);
});

test('REQ-014 [revoked]: revoked agent is denied even with a valid credential, and cannot get new ones', async (tc) => {
  const w = await world();
  tc.after(w.t.close);
  const { credential } = await issue(w);
  assert.equal((await w.t.call(w.operator.key, 'POST', `/v1/agents/${w.agent.agent.id}/revoke`, { reason: 'key leaked' })).status, 200);
  assert.equal(reason(await w.verify(w.signed({ credential }))), 'AGENT_REVOKED');
  const res = await w.t.call(w.operator.key, 'POST', `/v1/agents/${w.agent.agent.id}/credentials`, { grantId: w.grant.id });
  assert.equal(res.status, 409);
  // business cannot grant new permissions to a revoked agent
  await assert.rejects(createGrant(w.t, w.business, w.agent.agent.id), /grant failed/);
});

test('REQ-014 [revoked]: a revoked business API key can no longer call /v1/verify', async (tc) => {
  const w = await world();
  tc.after(w.t.close);
  const keyId = parseApiKey(w.business.key).keyId;
  assert.equal((await w.verify(w.signed())).decision, 'ALLOW');
  assert.equal((await w.t.call(w.t.admin, 'POST', `/v1/api-keys/${keyId}/revoke`)).status, 200);
  const res = await w.t.call(w.business.key, 'POST', '/v1/verify', w.signed());
  assert.equal(res.status, 401);
  assert.equal(res.body.decision, undefined, 'unauthenticated callers never receive a decision');
});

test('REQ-014 [revoked]: only the audience business (or owner) can revoke; other tenants get 404 and state is unchanged', async (tc) => {
  const w = await world();
  tc.after(w.t.close);
  const { record } = await issue(w);
  const intruder = await createBusiness(w.t, 'Intruder');
  assert.equal((await w.t.call(intruder.key, 'POST', `/v1/grants/${w.grant.id}/revoke`, { reason: 'x' })).status, 404);
  assert.equal((await w.t.call(intruder.key, 'POST', `/v1/credentials/${record.id}/revoke`, { reason: 'x' })).status, 404);
  assert.equal((await w.verify(w.signed())).decision, 'ALLOW');
  // the operator owning the agent can revoke the credential
  assert.equal((await w.t.call(w.operator.key, 'POST', `/v1/credentials/${record.id}/revoke`, { reason: 'rotate' })).status, 200);
});

test('REQ-014 [replayed]: concurrent replays over HTTP yield exactly one ALLOW', async (tc) => {
  const w = await world();
  tc.after(w.t.close);
  const body = w.signed();
  const results = await Promise.all(Array.from({ length: 8 }, () => w.verify(body)));
  assert.equal(results.filter((r) => r.decision === 'ALLOW').length, 1);
  assert.ok(results.filter((r) => r.decision === 'DENY').every((r) => reason(r) === 'NONCE_REPLAYED'));
});

test('REQ-014 [replayed]: replay with a credential attached, and nonce reuse with changed content, are both denied', async (tc) => {
  const w = await world();
  tc.after(w.t.close);
  const { credential } = await issue(w);
  const body = w.signed({ credential });
  assert.equal((await w.verify(body)).decision, 'ALLOW');
  assert.equal(reason(await w.verify(body)), 'NONCE_REPLAYED');
  // same nonce, different (validly signed) content is still a replay of the nonce
  const again = w.signed({ nonce: body.signedRequest.nonce, context: { amount: 1, currency: 'USD' } });
  assert.equal(reason(await w.verify(again)), 'NONCE_REPLAYED');
  // nonces are scoped per agent: another agent may use the same nonce value
  const other = await registerAgent(w.t, w.operator, 'Other');
  await createGrant(w.t, w.business, other.agent.id);
  const otherReq = w.signed({ privateKey: other.privateKey, agentId: other.agent.id, nonce: body.signedRequest.nonce });
  assert.equal((await w.verify(otherReq)).decision, 'ALLOW');
});

test('REQ-014 [replayed]: a request captured by business B cannot be replayed to business A after B saw it', async (tc) => {
  const w = await world();
  tc.after(w.t.close);
  const b = await createBusiness(w.t, 'Initech');
  await createGrant(w.t, b, w.agent.agent.id);
  const forB = w.signed({ audience: b.biz.id });
  assert.equal((await w.verify(forB, b.key)).decision, 'ALLOW');
  // B (malicious) forwards the same signed request to A: audience is signed.
  assert.equal(reason(await w.verify(forB, w.business.key)), 'AUDIENCE_MISMATCH');
});

test('REQ-014 [out-of-scope]: permissions granted by one business do not leak to another', async (tc) => {
  const w = await world();
  tc.after(w.t.close);
  const b = await createBusiness(w.t, 'Initech');
  await createGrant(w.t, b, w.agent.agent.id, { actions: ['orders:*'], constraints: {} });
  // A granted payments only; B's orders:* grant must not be used for A.
  assert.equal(reason(await w.verify(w.signed({ action: 'orders:create', context: {} }))), 'ACTION_NOT_PERMITTED');
  // B granted orders only; A's payments grant must not be used for B.
  assert.equal(reason(await w.verify(w.signed({ audience: b.biz.id }), b.key)), 'ACTION_NOT_PERMITTED');
  // A's credential cannot be presented to B.
  const { credential } = await issue(w);
  assert.equal(reason(await w.verify(w.signed({ audience: b.biz.id, credential, action: 'orders:create', context: {} }), b.key)), 'CREDENTIAL_AUDIENCE_MISMATCH');
});

test('REQ-014 [out-of-scope]: role scope — operators cannot grant, businesses cannot issue credentials, bare * is rejected', async (tc) => {
  const w = await world();
  tc.after(w.t.close);
  const expiresAt = new Date((w.t.nowSec() + 3600) * 1000).toISOString();
  const opGrant = await w.t.call(w.operator.key, 'POST', '/v1/grants', { agentId: w.agent.agent.id, actions: ['payments:*'], expiresAt });
  assert.equal(opGrant.status, 403);
  const bizIssue = await w.t.call(w.business.key, 'POST', `/v1/agents/${w.agent.agent.id}/credentials`, { grantId: w.grant.id });
  assert.equal(bizIssue.status, 403);
  const star = await w.t.call(w.business.key, 'POST', '/v1/grants', { agentId: w.agent.agent.id, actions: ['*'], expiresAt });
  assert.equal(star.status, 400);

  // An operator cannot mint a credential for an agent it does not own.
  const rival = await createOperator(w.t, { legalName: 'Rival Ltd' });
  const res = await w.t.call(rival.key, 'POST', `/v1/agents/${w.agent.agent.id}/credentials`, { grantId: w.grant.id });
  assert.equal(res.status, 404);
});
