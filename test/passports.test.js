// T10: passport model + transitions (docs/contracts/passport.md).
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { auditService } from '../src/services/audit.js';
import { PASSPORT_STATUSES, PASSPORT_TRANSITIONS, SYSTEM_ACTOR, isLegalTransition, passportService } from '../src/services/passports.js';
import { scoreAgent } from '../src/services/trust.js';
import { MemoryStore } from '../src/store/memory.js';
import { world } from './helpers.js';

const ADMIN = Object.freeze({ role: 'admin', apiKeyId: 'key_ADMIN', operatorId: null, businessId: null });
const OPERATOR = Object.freeze({ role: 'operator', apiKeyId: 'key_OP', operatorId: 'op_NORTHWIND' });
const BUSINESS = Object.freeze({ role: 'business', apiKeyId: 'key_BIZ', businessId: 'biz_ACME' });
const AGENT = Object.freeze({ role: 'agent', apiKeyId: null, agentId: 'agt_TB' });

function setup() {
  const store = new MemoryStore();
  const clock = { now: () => new Date('2026-09-26T12:00:00Z') };
  const audit = auditService({ store, clock });
  const passports = passportService({ store, clock, audit });
  return { store, audit, passports };
}

const issueArgs = (over = {}) => ({
  id: 'pp_TREASURYBOT',
  agentId: 'agt_TB',
  principalId: 'op_NORTHWIND',
  delegationId: 'grt_TB_USDC',
  delegationVersion: 1,
  wallet: '0xABCDEF0000000000000000000000000000000001',
  sanctionsDatasetVersion: '2026-09-01',
  harnessVersion: 1,
  expiresAt: new Date('2026-12-31T00:00:00Z'),
  ...over,
});

async function issued() {
  const s = setup();
  const p = await s.passports.issue(SYSTEM_ACTOR, issueArgs());
  return { ...s, p };
}

const expectStatus = (code) => (err) => {
  assert.equal(err.code, code);
  return true;
};

test('issue creates an ACTIVE passport with one history entry and a passport.issued audit event', async () => {
  const { store, p } = await issued();
  assert.equal(p.status, 'ACTIVE');
  assert.equal(p.wallet, '0xabcdef0000000000000000000000000000000001');
  const doc = await store.passports.findById('pp_TREASURYBOT');
  assert.deepEqual(doc.statusHistory.map((h) => h.status), ['ACTIVE']);
  assert.deepEqual(doc.statusHistory[0].actor, { role: 'system', apiKeyId: null, ownerId: null });
  assert.deepEqual(store._auditLog.map((e) => e.type), ['passport.issued']);
});

test('issue is restricted to system/admin and one passport per agent', async () => {
  const { passports } = setup();
  for (const who of [OPERATOR, BUSINESS, AGENT]) {
    await assert.rejects(passports.issue(who, issueArgs()), expectStatus('FORBIDDEN'));
  }
  await passports.issue(ADMIN, issueArgs());
  await assert.rejects(passports.issue(SYSTEM_ACTOR, issueArgs({ id: 'pp_OTHER' })), expectStatus('INVALID_STATE'));
});

test('Demo 4 path: ACTIVE -> RE_SCREENING -> SUSPENDED by the system actor', async () => {
  const { store, passports } = await issued();
  await passports.transition('pp_TREASURYBOT', ['ACTIVE', 'REVIEW'], 'RE_SCREENING', 'sanctions dataset changed', SYSTEM_ACTOR);
  const after = await passports.transition('pp_TREASURYBOT', ['RE_SCREENING'], 'SUSPENDED', 'SANCTIONS_EXACT_MATCH', SYSTEM_ACTOR, {
    investigationId: 'inv_1',
  });
  assert.equal(after.status, 'SUSPENDED');
  assert.equal(after.statusReason, 'SANCTIONS_EXACT_MATCH');
  assert.equal(after.lastInvestigationId, 'inv_1');
  assert.deepEqual(after.statusHistory.map((h) => h.status), ['ACTIVE', 'RE_SCREENING', 'SUSPENDED']);
  assert.equal(after.statusHistory[2].investigationId, 'inv_1');
  const changes = store._auditLog.filter((e) => e.type === 'passport.status_changed');
  assert.deepEqual(changes.map((e) => [e.data.fromStatus, e.data.toStatus]), [
    ['ACTIVE', 'RE_SCREENING'],
    ['RE_SCREENING', 'SUSPENDED'],
  ]);
  assert.ok(changes.every((e) => e.actor.role === 'system' && e.subjectId === 'pp_TREASURYBOT'));
});

test('every (from, to, actor) combination: only the passport.md §3 table succeeds', async () => {
  const expected = new Set(PASSPORT_TRANSITIONS.flatMap((t) => t.actors.map((a) => `${t.from}>${t.to}>${a}`)));
  assert.equal(expected.size, 16);
  for (const from of PASSPORT_STATUSES) {
    for (const to of PASSPORT_STATUSES) {
      for (const actor of [SYSTEM_ACTOR, ADMIN]) {
        const { store, passports } = setup();
        await store.passports.insert({ ...issueArgs(), status: from, statusHistory: [{ status: from }] });
        const legal = expected.has(`${from}>${to}>${actor.role}`);
        assert.equal(isLegalTransition(from, to, actor.role), legal);
        if (legal) {
          const out = await passports.transition('pp_TREASURYBOT', [from], to, 'test', actor);
          assert.equal(out.status, to);
        } else {
          await assert.rejects(passports.transition('pp_TREASURYBOT', [from], to, 'test', actor), expectStatus('INVALID_STATE'));
          const doc = await store.passports.findById('pp_TREASURYBOT');
          assert.equal(doc.status, from, `${from}->${to} by ${actor.role} must not write`);
          assert.equal(doc.statusHistory.length, 1);
        }
      }
    }
  }
});

test('stale precondition: passport not in `from` => 409 and no write; unknown id => 404', async () => {
  const { store, passports } = await issued();
  await assert.rejects(passports.transition('pp_TREASURYBOT', ['RE_SCREENING'], 'SUSPENDED', 'x', SYSTEM_ACTOR), expectStatus('INVALID_STATE'));
  assert.equal((await store.passports.findById('pp_TREASURYBOT')).status, 'ACTIVE');
  await assert.rejects(passports.transition('pp_NOPE', ['ACTIVE'], 'REVIEW', 'x', SYSTEM_ACTOR), expectStatus('NOT_FOUND'));
  await assert.rejects(passports.transition('pp_TREASURYBOT', ['ACTIVE'], 'DELETED', 'x', SYSTEM_ACTOR), expectStatus('INVALID_STATE'));
  await assert.rejects(passports.transition('pp_TREASURYBOT', [], 'REVIEW', 'x', SYSTEM_ACTOR), expectStatus('INVALID_STATE'));
});

test('REVOKED is terminal', async () => {
  const { passports } = await issued();
  await passports.transition('pp_TREASURYBOT', ['ACTIVE'], 'SUSPENDED', 'admin hold', ADMIN);
  await passports.transition('pp_TREASURYBOT', ['SUSPENDED'], 'REVOKED', 'terminal', ADMIN);
  for (const to of PASSPORT_STATUSES) {
    await assert.rejects(passports.transition('pp_TREASURYBOT', ['REVOKED'], to, 'x', ADMIN), expectStatus('INVALID_STATE'));
    await assert.rejects(passports.transition('pp_TREASURYBOT', ['REVOKED'], to, 'x', SYSTEM_ACTOR), expectStatus('INVALID_STATE'));
  }
});

test('INV_NO_SELF_PASSPORT_MODIFICATION: operator, business and agent principals get 403, even for their own passport', async () => {
  const { store, passports } = await issued();
  for (const who of [OPERATOR, BUSINESS, AGENT, { role: 'System' }, { role: 'root' }, {}]) {
    for (const [from, to] of [
      ['ACTIVE', 'REVIEW'],
      ['ACTIVE', 'SUSPENDED'],
      ['ACTIVE', 'RE_SCREENING'],
    ]) {
      await assert.rejects(passports.transition('pp_TREASURYBOT', [from], to, 'self', who), (err) => {
        assert.equal(err.code, 'FORBIDDEN');
        assert.equal(err.status, 403);
        return true;
      });
    }
  }
  const doc = await store.passports.findById('pp_TREASURYBOT');
  assert.equal(doc.status, 'ACTIVE');
  assert.equal(doc.statusHistory.length, 1);
  assert.equal(store._auditLog.filter((e) => e.type === 'passport.status_changed').length, 0);
});

test('the actor is required (no implicit system default) and a reason is required', async () => {
  const { passports } = await issued();
  await assert.rejects(passports.transition('pp_TREASURYBOT', ['ACTIVE'], 'REVIEW', 'x'), TypeError);
  await assert.rejects(passports.transition('pp_TREASURYBOT', ['ACTIVE'], 'REVIEW', 'x', null), TypeError);
  await assert.rejects(passports.transition('pp_TREASURYBOT', ['ACTIVE'], 'REVIEW', '', ADMIN), expectStatus('VALIDATION_ERROR'));
  await assert.rejects(passports.transition('pp_TREASURYBOT', ['ACTIVE'], 'REVIEW', undefined, ADMIN), expectStatus('VALIDATION_ERROR'));
});

test('admin-only and system-only edges are enforced by role', async () => {
  const { passports } = await issued();
  // Only system may start a re-screen; only admin may clear a review.
  await assert.rejects(passports.transition('pp_TREASURYBOT', ['ACTIVE'], 'RE_SCREENING', 'x', ADMIN), expectStatus('INVALID_STATE'));
  await passports.transition('pp_TREASURYBOT', ['ACTIVE'], 'REVIEW', 'hold', SYSTEM_ACTOR);
  await assert.rejects(passports.transition('pp_TREASURYBOT', ['REVIEW'], 'ACTIVE', 'x', SYSTEM_ACTOR), expectStatus('INVALID_STATE'));
  const cleared = await passports.transition('pp_TREASURYBOT', ['REVIEW'], 'ACTIVE', 'human cleared', ADMIN);
  assert.equal(cleared.status, 'ACTIVE');
  assert.deepEqual(cleared.statusHistory.at(-1).actor, { role: 'admin', apiKeyId: 'key_ADMIN', ownerId: null });
});

test('reads: admin full, operator own only, business public view only for delegated agents', async () => {
  const { store, passports } = await issued();
  const full = await passports.get(ADMIN, 'agt_TB');
  assert.equal(full.id, 'pp_TREASURYBOT');
  assert.equal(full.statusHistory[0].at, '2026-09-26T12:00:00.000Z');
  assert.equal((await passports.get(OPERATOR, 'agt_TB')).wallet, '0xabcdef0000000000000000000000000000000001');
  await assert.rejects(passports.get({ ...OPERATOR, operatorId: 'op_OTHER' }, 'agt_TB'), expectStatus('NOT_FOUND'));
  await assert.rejects(passports.get(BUSINESS, 'agt_TB'), expectStatus('NOT_FOUND'));
  await store.grants.insert({ id: 'grt_TB_USDC', agentId: 'agt_TB', businessId: 'biz_ACME', status: 'active', createdAt: new Date() });
  assert.deepEqual(Object.keys(await passports.get(BUSINESS, 'agt_TB')).sort(), [
    'agentId',
    'harnessVersion',
    'principalId',
    'sanctionsDatasetVersion',
    'status',
    'updatedAt',
  ]);
});

test('credentials for a delegation with a passport carry kya_passport, kya_delegation_v, kya_harness_v', async (tc) => {
  const w = await world();
  tc.after(w.t.close);
  const store = w.t.store;
  const clock = { now: () => new Date() };
  const passports = passportService({ store, clock, audit: auditService({ store, clock }) });
  const decode = (jws) => JSON.parse(Buffer.from(jws.split('.')[1], 'base64url').toString('utf8'));
  const issue = async () => {
    const res = await w.t.call(w.operator.key, 'POST', `/v1/agents/${w.agent.agent.id}/credentials`, { grantId: w.grant.id, ttlSeconds: 600 });
    assert.equal(res.status, 201);
    return res.body;
  };

  // No passport: claims unchanged.
  const plain = decode((await issue()).credential);
  assert.equal('kya_passport' in plain, false);

  await passports.issue(SYSTEM_ACTOR, issueArgs({ agentId: w.agent.agent.id, principalId: w.operator.op.id, delegationId: w.grant.id, delegationVersion: 3, harnessVersion: 1 }));
  const withPassport = await issue();
  let claims = decode(withPassport.credential);
  assert.deepEqual([claims.kya_passport, claims.kya_delegation_v, claims.kya_harness_v], ['pp_TREASURYBOT', 3, 1]);
  assert.equal((await store.passports.findById('pp_TREASURYBOT')).credentialId, withPassport.record.id);
  // /v1/verify still ALLOWs the credential (extra claims are ignored).
  assert.equal((await w.verify(w.signed({ credential: withPassport.credential }))).decision, 'ALLOW');

  // kya_harness_v follows the active harness version.
  await store.harnessVersions.insert({ id: 2, version: 2, status: 'active', createdAt: new Date() });
  claims = decode((await issue()).credential);
  assert.equal(claims.kya_harness_v, 2);
});

test('trust: sanctions_exposure factor reads the passport; SUSPENDED/REVOKED gate the score', () => {
  const now = new Date('2026-09-26T00:00:00Z');
  const agent = { id: 'agt_TB', operatorId: 'op_NORTHWIND', status: 'active', createdAt: new Date('2026-01-01T00:00:00Z') };
  const operator = { status: 'verified', verification: { kycResult: 'pass', sanctionsResult: 'clear', method: 'mock' } };
  const base = scoreAgent({ agent, operator, now });
  assert.equal(base.factors.some((f) => f.code === 'sanctions_exposure'), false);

  const active = scoreAgent({ agent, operator, now, passport: { id: 'pp_TREASURYBOT', status: 'ACTIVE', sanctionsDatasetVersion: '2026-09-01' } });
  const f = active.factors.find((x) => x.code === 'sanctions_exposure');
  assert.equal(f.inputs.passportStatus, 'ACTIVE');
  assert.equal(active.score, base.score);
  assert.equal(active.factors.reduce((s, x) => s + x.maxPoints, 0), 100);

  for (const status of ['SUSPENDED', 'REVOKED']) {
    const r = scoreAgent({ agent, operator, now, passport: { id: 'pp_TREASURYBOT', status, statusReason: 'SANCTIONS_EXACT_MATCH' } });
    assert.deepEqual([r.score, r.level], [0, 'untrusted']);
    assert.ok(r.gates.includes(`Passport is ${status}.`));
  }
});
