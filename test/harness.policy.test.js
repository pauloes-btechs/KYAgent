// T13 unit tests (offline, MemoryStore): adaptive policy loading, adaptation proposals and their
// validation boundary, the signing_key_history_check step, and investigations#confirm
// (INV_NO_SELF_APPROVAL, memory promotion, harness vN+1 + harness_events). The Atlas end-to-end
// acceptance is test/atlas/harness.adapt.test.js.
import assert from 'node:assert/strict';
import test from 'node:test';
import {
  applyPatch,
  checkPatchShape,
  evaluateProposal,
  llmPrompt,
  proposeFromOutcome,
  templateDiff,
} from '../src/harness/adaptation.js';
import { INVARIANTS, INVARIANTS_HASH } from '../src/harness/invariants.js';
import { HARNESS_V1_POLICY, HarnessPolicyError, adaptiveSteps, loadActiveHarness, policyHash } from '../src/harness/policy.js';
import { ADAPTIVE_STEP_RUNNERS } from '../src/investigation/adaptiveSteps.js';
import { HARNESS_V1_POLICY as SEED_V1_POLICY } from '../src/seed/hackathon.js';
import { auditService } from '../src/services/audit.js';
import { caseMemoryId, investigationService } from '../src/services/investigations.js';
import { MemoryStore } from '../src/store/memory.js';
import { startApp } from './helpers.js';

const v1 = () => structuredClone(HARNESS_V1_POLICY);
const TAKEOVER_SIGNALS = ['AMOUNT_ANOMALY', 'NEW_COUNTERPARTY', 'SIGNING_KEY_CHANGED'];
const verifiedMemory = (outcome = 'CONFIRMED_ACCOUNT_TAKEOVER') => ({ id: 'mem_inv_X', status: 'VERIFIED', outcome, signals: TAKEOVER_SIGNALS });
const caseInv = { id: 'inv_X', signals: TAKEOVER_SIGNALS, riskDecision: 'REVIEW' };

function versionDoc(version, policy = v1(), extra = {}) {
  return {
    id: version,
    version,
    status: 'active',
    parentVersion: null,
    invariantsHash: INVARIANTS_HASH,
    policy,
    policyHash: policyHash(policy),
    createdAt: new Date(),
    approvedBy: { role: 'system', apiKeyId: null, ownerId: null, label: 'seed' },
    sourceEventId: null,
    ...extra,
  };
}

// ------------------------------------------------------------ policy loading

test('HARNESS_V1_POLICY is the harness.md §3.2 seed policy (same as the demo seed) and validates', () => {
  assert.deepEqual(v1(), structuredClone(SEED_V1_POLICY));
  assert.deepEqual(evaluateProposal(v1(), [{ op: 'replace', path: '/memoryRetrieval/k', value: 3 }]).errors, []);
  assert.deepEqual(adaptiveSteps(v1()), []);
});

test('loadActiveHarness: no document => v1 seed policy, not persisted', async () => {
  const h = await loadActiveHarness(new MemoryStore());
  assert.equal(h.version, 1);
  assert.equal(h.persisted, false);
  assert.equal(h.invariantsMatch, true);
  assert.deepEqual(h.policy, v1());
});

test('loadActiveHarness: reads the single active version; flags an invariants-hash mismatch', async () => {
  const store = new MemoryStore();
  await store.harnessVersions.insert({ ...versionDoc(1), status: 'superseded' });
  await store.harnessVersions.insert(versionDoc(2, v1(), { invariantsHash: 'f'.repeat(64) }));
  const h = await loadActiveHarness(store);
  assert.equal(h.version, 2);
  assert.equal(h.persisted, true);
  assert.equal(h.invariantsMatch, false);
});

test('loadActiveHarness: an invalid stored policy or two active versions fail closed', async () => {
  const bad = new MemoryStore();
  await bad.harnessVersions.insert(versionDoc(1, { ...v1(), skipInvariants: true }));
  await assert.rejects(loadActiveHarness(bad), (e) => e instanceof HarnessPolicyError && e.code === 'HARNESS_POLICY_INVALID');
  const two = new MemoryStore();
  await two.harnessVersions.insert(versionDoc(1));
  await two.harnessVersions.insert(versionDoc(2));
  await assert.rejects(loadActiveHarness(two), (e) => e.code === 'HARNESS_MULTIPLE_ACTIVE');
});

// ------------------------------------------------------------ proposals

test('fixture template: CONFIRMED_ACCOUNT_TAKEOVER adds signing_key_history_check after memory and sets k=5', async () => {
  const p = await proposeFromOutcome(caseInv, verifiedMemory(), { policy: v1(), mode: 'fixture' });
  assert.deepEqual(p.proposer, { kind: 'template', llmMode: 'fixture', model: null });
  assert.deepEqual(p.diff, [
    { op: 'add', path: '/steps/5', value: 'signing_key_history_check' },
    { op: 'replace', path: '/memoryRetrieval/k', value: 5 },
  ]);
  const r = evaluateProposal(v1(), p.diff);
  assert.equal(r.ok, true, JSON.stringify(r.errors));
  assert.deepEqual(r.newPolicy.steps, ['identity', 'delegation', 'sanctions', 'signals', 'memory', 'signing_key_history_check', 'policy']);
  assert.equal(r.newPolicy.memoryRetrieval.k, 5);
  assert.deepEqual(r.newPolicy.memoryRetrieval.filter, { status: 'VERIFIED' });
  // Deterministic, and idempotent once applied.
  assert.deepEqual((await proposeFromOutcome(caseInv, verifiedMemory(), { policy: v1() })).diff, p.diff);
  assert.deepEqual(templateDiff('CONFIRMED_ACCOUNT_TAKEOVER', r.newPolicy), []);
  assert.equal(await proposeFromOutcome(caseInv, verifiedMemory(), { policy: r.newPolicy }), null);
});

test('no proposal for other outcomes or for a memory that is not VERIFIED', async () => {
  for (const outcome of ['FALSE_POSITIVE', 'SANCTIONS_MATCH', 'CLEAN']) {
    assert.equal(await proposeFromOutcome(caseInv, verifiedMemory(outcome), { policy: v1() }), null);
  }
  for (const status of ['UNVERIFIED', 'REJECTED', undefined]) {
    assert.equal(await proposeFromOutcome(caseInv, { ...verifiedMemory(), status }, { policy: v1() }), null);
  }
});

test('adaptation boundary: proposals touching invariants or weakening fixed rules are rejected', () => {
  const rejects = (diff, why) => {
    const r = evaluateProposal(v1(), diff);
    assert.equal(r.ok, false, `${why} should be rejected`);
    assert.equal(r.newPolicy, null);
    assert.ok(r.errors.length > 0);
  };
  rejects([{ op: 'add', path: '/invariants', value: [] }], 'invariants key');
  rejects([{ op: 'add', path: '/skipInvariants', value: true }], 'skipInvariants key');
  rejects([{ op: 'replace', path: '', value: {} }], 'root replace');
  rejects([{ op: 'replace', path: '/memoryRetrieval/filter', value: {} }], 'memory filter');
  rejects([{ op: 'replace', path: '/memoryRetrieval/minScorePpm', value: 1 }], 'lowering minScorePpm');
  rejects([{ op: 'remove', path: '/steps/2' }], 'removing the sanctions stage');
  rejects([{ op: 'add', path: '/steps/1', value: 'signing_key_history_check' }], 'adaptive step before memory');
  rejects([{ op: 'add', path: '/steps/5', value: 'drop_sanctions' }], 'unregistered step');
  rejects([{ op: 'remove', path: '/escalation/0' }], 'removing an escalation rule');
  rejects([{ op: 'add', path: '/escalation/-', value: { id: 'x', when: { signalsAll: ['NEW_WALLET'] }, then: { riskDecision: 'ALLOW', reasonCode: 'BEHAVIOR_ESCALATION' } } }], 'ALLOW escalation');
  rejects([{ op: 'add', path: '/escalation/-', value: { id: 'x', when: { signalsAll: ['NEW_WALLET'] }, then: { riskDecision: 'REVIEW', reasonCode: 'BEHAVIOR_ESCALATION' }, overrides: ['INV_SANCTIONS_EXACT_BLOCK'] } }], 'nested overrides');
  rejects([{ op: 'add', path: '/sanctionsFuzzy', value: { minScorePpm: 1, limit: 1 } }], 'sanctionsFuzzy');
  rejects([{ op: 'add', path: '/__proto__/polluted', value: true }], 'prototype path');
  rejects([], 'empty diff');
  rejects('not a patch', 'non-array diff');
  assert.equal({}.polluted, undefined);
  // Allowed: raising minScorePpm and adding a REVIEW escalation.
  const ok = evaluateProposal(v1(), [
    { op: 'replace', path: '/memoryRetrieval/minScorePpm', value: 800_000 },
    { op: 'add', path: '/escalation/-', value: { id: 'key_and_cp', when: { signalsAll: ['SIGNING_KEY_CHANGED', 'NEW_COUNTERPARTY'] }, then: { riskDecision: 'REVIEW', reasonCode: 'BEHAVIOR_ESCALATION' } } },
  ]);
  assert.equal(ok.ok, true, JSON.stringify(ok.errors));
});

test('applyPatch never mutates its input; checkPatchShape rejects unknown op keys', () => {
  const base = v1();
  applyPatch(base, [{ op: 'replace', path: '/memoryRetrieval/k', value: 7 }]);
  assert.equal(base.memoryRetrieval.k, 3);
  assert.ok(checkPatchShape([{ op: 'move', path: '/memoryRetrieval/k', from: '/x' }]).length >= 2);
});

test('live mode: LLM output is data — schema-validated, and cannot alter invariants', async () => {
  const seen = [];
  const llm = (text) => ({ model: 'test-model', complete: async (prompt) => (seen.push(prompt), text) });
  const hostile = await proposeFromOutcome(caseInv, verifiedMemory(), {
    policy: v1(),
    mode: 'live',
    llm: llm(JSON.stringify({ diff: [{ op: 'add', path: '/invariants', value: [] }, { op: 'remove', path: '/steps/2' }] })),
  });
  assert.deepEqual(hostile.proposer, { kind: 'llm', llmMode: 'live', model: 'test-model' });
  assert.equal(evaluateProposal(v1(), hostile.diff).ok, false);
  // The prompt carries the adaptive policy and evidence only — never the invariants module.
  for (const i of INVARIANTS) assert.ok(!seen[0].includes(i.id), `prompt leaks ${i.id}`);
  assert.deepEqual(JSON.parse(seen[0]).policy, v1());

  const good = await proposeFromOutcome(caseInv, verifiedMemory(), {
    policy: v1(),
    mode: 'live',
    llm: llm(JSON.stringify({ diff: [{ op: 'replace', path: '/memoryRetrieval/k', value: 4 }] })),
  });
  assert.equal(evaluateProposal(v1(), good.diff).ok, true);

  const garbage = await proposeFromOutcome(caseInv, verifiedMemory(), { policy: v1(), mode: 'live', llm: llm('not json') });
  assert.equal(garbage.error.code, 'LLM_OUTPUT_INVALID');
  const none = await proposeFromOutcome(caseInv, verifiedMemory(), { policy: v1(), mode: 'live' });
  assert.equal(none.error.code, 'LLM_UNAVAILABLE');
  assert.match(llmPrompt({ policy: v1(), investigation: caseInv, memory: verifiedMemory() }), /signing_key_history_check/);
});

// ------------------------------------------------------------ adaptive step

test('signing_key_history_check reports the rotation and settled payments signed with the current key', async () => {
  const store = new MemoryStore();
  const now = new Date('2026-09-28T12:00:00Z');
  const agent = {
    id: 'agt_T',
    keyThumbprint: 'new',
    signingKeyHistory: [
      { thumbprint: 'old', from: new Date('2026-01-01T00:00:00Z'), to: new Date('2026-09-28T09:00:00Z') },
      { thumbprint: 'new', from: new Date('2026-09-28T09:00:00Z'), to: null },
    ],
  };
  for (const [i, thumb] of ['old', 'old', 'new'].entries()) {
    await store.transactions.insert({ id: `tx_${i}`, agentId: 'agt_T', status: i === 2 ? 'blocked' : 'settled', signingKeyThumbprint: thumb, at: now });
  }
  const out = await ADAPTIVE_STEP_RUNNERS.signing_key_history_check.run({ store, agent, agentId: 'agt_T', now });
  assert.deepEqual(out.result, {
    currentThumbprint: 'new',
    previousThumbprint: 'old',
    rotatedAt: '2026-09-28T09:00:00.000Z',
    rotatedWithinHours: 3,
    settledTxWithCurrentKey: 0,
  });
  assert.equal(out.status, 'flagged');
  assert.deepEqual(out.reasons, [], 'adaptive steps add evidence only');
  assert.equal(out.evidence[0].kind, 'step');

  const stable = await ADAPTIVE_STEP_RUNNERS.signing_key_history_check.run({
    store,
    agent: { id: 'agt_T', keyThumbprint: 'old', signingKeyHistory: [{ thumbprint: 'old', from: new Date('2026-01-01T00:00:00Z'), to: null }] },
    agentId: 'agt_T',
    now,
  });
  assert.equal(stable.status, 'passed');
  assert.equal(stable.result.previousThumbprint, null);
  assert.equal(stable.result.settledTxWithCurrentKey, 2);
});

// ------------------------------------------------------------ confirm (service)

async function confirmWorld({ seedHarness = true } = {}) {
  const store = new MemoryStore();
  const clock = { now: () => new Date('2026-09-28T12:00:00Z') };
  const audit = auditService({ store, clock });
  const svc = investigationService({ store, clock, config: { modes: { llm: 'fixture' } }, audit });
  if (seedHarness) await store.harnessVersions.insert(versionDoc(1));
  const inv = {
    id: 'inv_01JAAAAAAAAAAAAAAAAAAAAAAA',
    trigger: 'api',
    initiatedBy: { role: 'business', apiKeyId: 'key_biz', ownerId: 'biz_1' },
    agentId: 'agt_1',
    principalId: 'op_1',
    businessId: 'biz_1',
    harnessVersion: 1,
    stages: [],
    signals: TAKEOVER_SIGNALS,
    riskDecision: 'REVIEW',
    decision: 'DENY',
    reasons: [{ code: 'MEMORY_PRECEDENT_TAKEOVER', riskDecision: 'REVIEW' }],
    status: 'AWAITING_REVIEW',
    outcome: null,
    createdAt: clock.now(),
  };
  await store.investigations.insert(inv);
  return { store, svc, inv };
}
const admin = (apiKeyId = 'key_admin', extra = {}) => ({ role: 'admin', apiKeyId, ...extra });
const takeover = { outcome: 'CONFIRMED_ACCOUNT_TAKEOVER', approveAdaptation: true };

async function assertNothingWritten(store, inv) {
  assert.deepEqual((await store.investigations.findById(inv.id)).status, inv.status);
  assert.equal(await store.securityMemories.findById(caseMemoryId(inv.id)), null);
  assert.equal((await store.harnessVersions.find({})).length, 1);
  assert.equal((await store.harnessEvents.find({})).length, 0);
  assert.equal(store._auditLog.length, 0);
}

test('confirm: INV_NO_SELF_APPROVAL — the initiating key or a party of the case gets 403 and nothing is written', async () => {
  const { store, svc, inv } = await confirmWorld();
  await assert.rejects(svc.confirm(admin('key_biz'), inv.id, takeover), (e) => e.status === 403 && /INV_NO_SELF_APPROVAL/.test(e.message));
  await assert.rejects(svc.confirm({ role: 'admin', apiKeyId: 'key_other', operatorId: 'op_1' }, inv.id, takeover), (e) => e.status === 403);
  await assert.rejects(svc.confirm({ role: 'business', apiKeyId: 'key_other', businessId: 'biz_9' }, inv.id, takeover), (e) => e.status === 403);
  await assertNothingWritten(store, inv);
});

test('confirm: validation and 404 happen before any write', async () => {
  const { store, svc, inv } = await confirmWorld();
  await assert.rejects(svc.confirm(admin(), 'inv_01JBBBBBBBBBBBBBBBBBBBBBBB', takeover), (e) => e.status === 404);
  for (const body of [{}, { outcome: 'PWNED', approveAdaptation: true }, { ...takeover, approveAdaptation: 'yes' }, { ...takeover, invariants: [] }]) {
    await assert.rejects(svc.confirm(admin(), inv.id, body), (e) => e.status === 400);
  }
  await assertNothingWritten(store, inv);
});

test('confirm CONFIRMED_ACCOUNT_TAKEOVER: memory VERIFIED, harness v2 + adaptation event with old/new/evidence/approval', async () => {
  const { store, svc, inv } = await confirmWorld();
  const r = await svc.confirm(admin(), inv.id, { ...takeover, note: 'attacker controlled the rotated key' });
  assert.equal(r.investigation.status, 'CONFIRMED');
  assert.equal(r.investigation.outcome, 'CONFIRMED_ACCOUNT_TAKEOVER');
  assert.deepEqual(r.memory, { id: caseMemoryId(inv.id), status: 'VERIFIED' });
  assert.equal(r.adaptation.proposed, true);
  assert.equal(r.adaptation.applied, true);
  assert.equal(r.adaptation.fromVersion, 1);
  assert.equal(r.adaptation.toVersion, 2);

  const mem = await store.securityMemories.findById(caseMemoryId(inv.id));
  assert.equal(mem.status, 'VERIFIED');
  assert.equal(mem.outcome, 'CONFIRMED_ACCOUNT_TAKEOVER');
  assert.deepEqual(mem.verifiedBy, { role: 'admin', apiKeyId: 'key_admin', ownerId: null });
  assert.equal(mem.embedding.length, 1024);

  const [old, v2] = (await store.harnessVersions.find({})).sort((a, b) => a.version - b.version);
  assert.equal(old.status, 'superseded');
  assert.deepEqual(old.policy, v1(), 'the old version is never edited beyond its status');
  assert.equal(v2.status, 'active');
  assert.equal(v2.parentVersion, 1);
  assert.equal(v2.invariantsHash, old.invariantsHash);
  assert.equal(v2.invariantsHash, INVARIANTS_HASH);
  assert.equal(v2.policyHash, policyHash(v2.policy));
  assert.ok(v2.policy.steps.includes('signing_key_history_check'));
  assert.equal(v2.policy.memoryRetrieval.k, 5);
  assert.deepEqual(v2.approvedBy, { role: 'admin', apiKeyId: 'key_admin', ownerId: null });

  const [ev] = await store.harnessEvents.find({});
  assert.equal(ev.id, r.adaptation.eventId);
  assert.equal(v2.sourceEventId, ev.id);
  assert.equal(ev.type, 'adaptation.applied');
  assert.deepEqual([ev.fromVersion, ev.toVersion], [1, 2]);
  assert.deepEqual(ev.oldPolicy, old.policy);
  assert.deepEqual(ev.newPolicy, v2.policy);
  assert.deepEqual(ev.evidence, [{ type: 'investigation', id: inv.id }, { type: 'memory', id: mem.id }]);
  assert.deepEqual(ev.proposer, { kind: 'template', llmMode: 'fixture', model: null });
  assert.ok(ev.at instanceof Date && ev.approvedAt instanceof Date);
  const types = store._auditLog.map((e) => e.type);
  assert.deepEqual(types, ['memory.promoted', 'investigation.confirmed', 'harness.adapted']);
  assert.equal(store._auditLog.find((e) => e.type === 'harness.adapted').id, ev.auditEventId);

  // Already confirmed ⇒ 409, nothing else written.
  await assert.rejects(svc.confirm(admin('key_admin2'), inv.id, takeover), (e) => e.status === 409);
  assert.equal((await store.harnessVersions.find({})).length, 2);
  assert.equal((await loadActiveHarness(store)).version, 2);
});

test('confirm without approveAdaptation: memory VERIFIED, adaptation.rejected event, no new version', async () => {
  const { store, svc, inv } = await confirmWorld();
  const r = await svc.confirm(admin(), inv.id, { ...takeover, approveAdaptation: false });
  assert.equal(r.memory.status, 'VERIFIED');
  assert.equal(r.adaptation.proposed, true);
  assert.equal(r.adaptation.applied, false);
  assert.equal(r.adaptation.toVersion, null);
  const [ev] = await store.harnessEvents.find({});
  assert.equal(ev.type, 'adaptation.rejected');
  assert.equal(ev.newPolicy, null);
  assert.deepEqual((await store.harnessVersions.find({})).map((v) => [v.version, v.status]), [[1, 'active']]);
  assert.ok(store._auditLog.some((e) => e.type === 'harness.adaptation_rejected'));
});

test('confirm CLEAN: memory REJECTED, no proposal; no persisted harness => proposal rejected, never applied', async () => {
  const clean = await confirmWorld();
  const r = await clean.svc.confirm(admin(), clean.inv.id, { outcome: 'CLEAN', approveAdaptation: true });
  assert.deepEqual(r.memory, { id: caseMemoryId(clean.inv.id), status: 'REJECTED' });
  assert.equal(r.adaptation.proposed, false);
  assert.equal((await clean.store.harnessEvents.find({})).length, 0);

  const bare = await confirmWorld({ seedHarness: false });
  const r2 = await bare.svc.confirm(admin(), bare.inv.id, takeover);
  assert.equal(r2.adaptation.applied, false);
  assert.equal((await bare.store.harnessVersions.find({})).length, 0);
  assert.equal((await bare.store.harnessEvents.find({}))[0].type, 'adaptation.rejected');
});

// ------------------------------------------------------------ HTTP routes

test('HTTP: confirm is admin-only; GET /v1/harness/versions returns versions + runtime INVARIANTS_HASH', async (t) => {
  const h = await startApp();
  t.after(() => h.close());
  const adminPrincipal = await h.app.services.apiKeys.authenticate(`Bearer ${h.admin}`);
  await h.store.harnessVersions.insert(versionDoc(1));
  const id = 'inv_01JCCCCCCCCCCCCCCCCCCCCCCC';
  await h.store.investigations.insert({
    id,
    trigger: 'api',
    initiatedBy: { role: 'admin', apiKeyId: adminPrincipal.apiKeyId, ownerId: null },
    agentId: 'agt_1',
    principalId: 'op_1',
    businessId: 'biz_1',
    harnessVersion: 1,
    stages: [],
    signals: TAKEOVER_SIGNALS,
    riskDecision: 'REVIEW',
    reasons: [],
    status: 'AWAITING_REVIEW',
    outcome: null,
    createdAt: new Date(),
  });
  // The admin that initiated the case cannot approve it.
  const self = await h.call(h.admin, 'POST', `/v1/investigations/${id}/confirm`, takeover);
  assert.equal(self.status, 403);
  assert.equal(self.body.error.code, 'FORBIDDEN');
  assert.equal((await h.store.investigations.findById(id)).status, 'AWAITING_REVIEW');

  const biz = (await h.call(h.admin, 'POST', '/v1/businesses', { name: 'Globex' })).body;
  const bizKey = (await h.call(h.admin, 'POST', '/v1/api-keys', { name: 'b', role: 'business', ownerId: biz.id })).body.secret;
  assert.equal((await h.call(bizKey, 'POST', `/v1/investigations/${id}/confirm`, takeover)).status, 403);

  const list = await h.call(bizKey, 'GET', '/v1/harness/versions');
  assert.equal(list.status, 200);
  assert.equal(list.body.invariantsHash, INVARIANTS_HASH);
  assert.deepEqual(list.body.data.map((v) => [v.version, v.status]), [[1, 'active']]);
  const events = await h.call(h.admin, 'GET', '/v1/harness/events');
  assert.equal(events.status, 200);
  assert.deepEqual(events.body.data, []);
});
