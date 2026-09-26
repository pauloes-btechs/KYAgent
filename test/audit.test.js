// REQ-008: append-only, hash-chained audit log of registration, issuance,
// verification and revocation events.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { AUDIT_EVENT_TYPES, GENESIS_HASH, auditHash } from '../src/services/audit.js';
import { world } from './helpers.js';

const listAll = async (w, query = '') => {
  const res = await w.t.call(w.t.admin, 'GET', `/v1/audit-events?limit=100${query}`);
  assert.equal(res.status, 200);
  return res.body.data;
};

async function issue(w) {
  const res = await w.t.call(w.operator.key, 'POST', `/v1/agents/${w.agent.agent.id}/credentials`, { grantId: w.grant.id, ttlSeconds: 600 });
  assert.equal(res.status, 201);
  return res.body;
}

test('registration, issuance, verification and revocation are all audited', async (tc) => {
  const w = await world();
  tc.after(w.t.close);
  const { credential, record } = await issue(w);
  const decision = await w.verify(w.signed({ credential }));
  assert.equal(decision.decision, 'ALLOW');
  const denied = await w.verify(w.signed({ action: 'refunds:create' }));
  assert.equal(denied.decision, 'DENY');
  assert.equal((await w.t.call(w.business.key, 'POST', `/v1/credentials/${record.id}/revoke`, { reason: 'rotated' })).status, 200);
  assert.equal((await w.t.call(w.business.key, 'POST', `/v1/grants/${w.grant.id}/revoke`, { reason: 'ended' })).status, 200);
  assert.equal((await w.t.call(w.operator.key, 'POST', `/v1/agents/${w.agent.agent.id}/revoke`, { reason: 'compromised' })).status, 200);

  const events = await listAll(w);
  const types = events.map((e) => e.type).reverse();
  for (const t of [
    'operator.created',
    'operator.verification_completed',
    'api_key.created',
    'business.created',
    'agent.registered',
    'grant.created',
    'credential.issued',
    'verification.decided',
    'credential.revoked',
    'grant.revoked',
    'agent.revoked',
  ]) {
    assert.ok(types.includes(t), `missing ${t}`);
  }
  // Newest first; sequence numbers are contiguous.
  const seqs = events.map((e) => e.seq);
  assert.deepEqual(seqs, [...seqs].sort((a, b) => b - a));
  assert.deepEqual([...seqs].reverse(), seqs.map((_, i) => i + 1));

  const reg = events.find((e) => e.type === 'agent.registered');
  assert.equal(reg.subjectType, 'agent');
  assert.equal(reg.subjectId, w.agent.agent.id);
  assert.deepEqual(reg.actor, { role: 'operator', apiKeyId: reg.actor.apiKeyId, ownerId: w.operator.op.id });
  assert.equal(reg.data.keyThumbprint, w.agent.agent.keyThumbprint);
  assert.match(reg.requestId, /^req_/);

  const issued = events.find((e) => e.type === 'credential.issued');
  assert.equal(issued.subjectId, record.id);
  assert.equal(issued.data.grantId, w.grant.id);

  const decisions = events.filter((e) => e.type === 'verification.decided');
  assert.equal(decisions.length, 2);
  const allow = decisions.find((e) => e.data.decision === 'ALLOW');
  assert.equal(allow.subjectId, decision.verificationId);
  assert.equal(allow.data.credentialId, record.id);
  assert.equal(allow.actor.ownerId, w.business.biz.id);
  assert.equal(decisions.find((e) => e.data.decision === 'DENY').data.reasonCode, 'ACTION_NOT_PERMITTED');

  const agentRevoked = events.find((e) => e.type === 'agent.revoked');
  assert.deepEqual(
    { from: agentRevoked.data.fromStatus, to: agentRevoked.data.toStatus, reason: agentRevoked.data.reason },
    { from: 'active', to: 'revoked', reason: 'compromised' },
  );

  // filters
  const onlyAgent = await listAll(w, `&subjectId=${w.agent.agent.id}`);
  assert.deepEqual(onlyAgent.map((e) => e.type), ['agent.revoked', 'agent.registered']);
  const onlyIssued = await listAll(w, '&type=credential.issued');
  assert.equal(onlyIssued.length, 1);
  assert.equal((await w.t.call(w.t.admin, 'GET', '/v1/audit-events?type=bogus')).status, 400);

  const integrity = await w.t.call(w.t.admin, 'GET', '/v1/audit-events/integrity');
  assert.deepEqual(integrity.body, { valid: true, count: events.length, headHash: events[0].hash, brokenAtSeq: null });
});

test('audit events never contain secrets, credentials, signatures or context', async (tc) => {
  const w = await world();
  tc.after(w.t.close);
  const { credential } = await issue(w);
  const signed = w.signed({ credential, context: { amount: 4242, currency: 'USD' } });
  await w.verify(signed);
  const apiKey = await w.t.call(w.t.admin, 'POST', '/v1/api-keys', { name: 'extra', role: 'business', ownerId: w.business.biz.id });

  const raw = JSON.stringify(w.t.store._auditLog);
  for (const secret of [credential, signed.signedRequest.signature, signed.signedRequest.nonce, apiKey.body.secret, w.operator.key, w.business.key, w.t.admin]) {
    assert.ok(!raw.includes(secret), 'secret material leaked into audit log');
  }
  assert.ok(!raw.includes('4242'), 'context values must not be logged');
  assert.ok(!raw.includes('secretHash'));
  assert.ok(!raw.includes('ops@acme.example'), 'operator PII is not copied into the log');
});

test('audit log is RBAC-restricted to admins', async (tc) => {
  const w = await world();
  tc.after(w.t.close);
  for (const key of [w.operator.key, w.business.key]) {
    assert.equal((await w.t.call(key, 'GET', '/v1/audit-events')).status, 403);
    assert.equal((await w.t.call(key, 'GET', '/v1/audit-events/integrity')).status, 403);
  }
  assert.equal((await w.t.call(null, 'GET', '/v1/audit-events')).status, 401);
});

test('append-only: store exposes no mutation path and tampering breaks the chain', async (tc) => {
  const w = await world();
  tc.after(w.t.close);
  const repo = w.t.store.auditEvents;
  assert.deepEqual(Object.keys(repo).sort(), ['append', 'last', 'list', 'range']);

  // Out-of-sequence appends (e.g. rewriting history) are rejected.
  const tail = await repo.last();
  await assert.rejects(repo.append({ ...tail, id: 'aud_forged' }));

  const first = w.t.store._auditLog[0];
  assert.equal(first.seq, 1);
  assert.equal(first.prevHash, GENESIS_HASH);
  assert.equal(auditHash(first), first.hash);

  // Edit a stored event behind the API's back (simulating DB tampering).
  const victim = w.t.store._auditLog[2];
  victim.data = { ...victim.data, tampered: true };
  let integrity = (await w.t.call(w.t.admin, 'GET', '/v1/audit-events/integrity')).body;
  assert.equal(integrity.valid, false);
  assert.equal(integrity.brokenAtSeq, 3);

  // Deleting an event is also detected.
  w.t.store._auditLog[2] = structuredClone(victim);
  delete w.t.store._auditLog[2].data.tampered;
  assert.equal((await w.t.call(w.t.admin, 'GET', '/v1/audit-events/integrity')).body.valid, true);
  w.t.store._auditLog.splice(1, 1);
  integrity = (await w.t.call(w.t.admin, 'GET', '/v1/audit-events/integrity')).body;
  assert.equal(integrity.valid, false);
  assert.equal(integrity.brokenAtSeq, 2);
});

test('fail closed: unaudited ALLOW and unaudited credential issuance are refused', async (tc) => {
  const w = await world();
  tc.after(w.t.close);
  const original = w.t.store.auditEvents.append;
  w.t.store.auditEvents.append = async () => {
    throw new Error('audit store down');
  };

  const res = await w.t.call(w.business.key, 'POST', '/v1/verify', w.signed());
  assert.equal(res.status, 500);
  assert.equal(res.body.decision, 'DENY');
  assert.equal(res.body.reasons[0].code, 'INTERNAL_ERROR');
  // the verification record matches what the caller was told
  const vrf = (await w.t.call(w.business.key, 'GET', '/v1/verifications')).body.data[0];
  assert.equal(vrf.verificationId, res.body.verificationId);
  assert.equal(vrf.decision, 'DENY');

  const issued = await w.t.call(w.operator.key, 'POST', `/v1/agents/${w.agent.agent.id}/credentials`, { grantId: w.grant.id });
  assert.equal(issued.status, 500);
  assert.ok(!issued.text.includes('audit store down'));
  assert.equal(issued.body.credential, undefined, 'no JWS is released without an audit record');
  const creds = (await w.t.call(w.operator.key, 'GET', '/v1/credentials')).body.data;
  assert.equal(creds.length, 1);
  assert.equal(creds[0].status, 'revoked', 'unaudited credential record is revoked');

  w.t.store.auditEvents.append = original;
  assert.equal((await w.t.call(w.t.admin, 'GET', '/v1/audit-events/integrity')).body.valid, true);
});

test('concurrent writes keep a single linear chain', async (tc) => {
  const w = await world();
  tc.after(w.t.close);
  await Promise.all(Array.from({ length: 20 }, () => w.verify(w.signed())));
  const integrity = (await w.t.call(w.t.admin, 'GET', '/v1/audit-events/integrity')).body;
  assert.equal(integrity.valid, true);
  const decided = await listAll(w, '&type=verification.decided');
  assert.equal(decided.length, 20);
  assert.ok(decided.every((e) => e.data.decision === 'ALLOW'));
});

test('event types are a closed set', () => {
  assert.ok(AUDIT_EVENT_TYPES.includes('agent.registered'));
  assert.ok(AUDIT_EVENT_TYPES.includes('credential.issued'));
  assert.ok(AUDIT_EVENT_TYPES.includes('verification.decided'));
  assert.ok(AUDIT_EVENT_TYPES.includes('agent.revoked'));
});
