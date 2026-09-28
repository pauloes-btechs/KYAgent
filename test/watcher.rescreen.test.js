// T11: sanctions_change re-screen (src/watchers/sanctionsWatcher.js rescreenService) on the
// MemoryStore CRUD double. The change stream itself is Atlas-only: test/atlas/sanctions.watch.test.js.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createEventHub } from '../src/events.js';
import { runInvestigation } from '../src/investigation/pipeline.js';
import { auditService } from '../src/services/audit.js';
import { isLegalTransition, passportService, SYSTEM_ACTOR } from '../src/services/passports.js';
import { MemoryStore } from '../src/store/memory.js';
import { changeEventId, investigationIdFor, PASSPORT_BY_DECISION, rescreenService, sanctionedAddresses } from '../src/watchers/sanctionsWatcher.js';

const NOW = new Date('2026-09-26T12:00:00Z');
const WALLET = '0x7a3f00000000000000000000000000000000c001';
const CP_A = '0x4b1d000000000000000000000000000000000a01';
const CP_B = '0x4b1d000000000000000000000000000000000b02';
const CP_OLD = '0x4b1d000000000000000000000000000000000c03';
const DAY = 86_400_000;

async function setup() {
  const store = new MemoryStore();
  const clock = { now: () => NOW };
  const audit = auditService({ store, clock });
  const events = createEventHub({ clock });
  const published = [];
  events.subscribe((e) => published.push(e));
  await store.operators.insert({ id: 'op_NW', type: 'organization', legalName: 'Northwind', status: 'verified', createdAt: NOW });
  await store.agents.insert({ id: 'agt_TB', name: 'TreasuryBot', operatorId: 'op_NW', status: 'active', keyThumbprint: 'thumb', wallets: [{ chain: 'evm', address: WALLET }], createdAt: NOW });
  await store.grants.insert({
    id: 'grt_TB',
    agentId: 'agt_TB',
    businessId: 'biz_CP',
    operatorId: 'op_NW',
    actions: ['payments:create'],
    constraints: { maxAmount: 25_000_000_000, currency: 'USDC' },
    asset: 'USDC',
    status: 'active',
    version: 1,
    expiresAt: new Date(NOW.getTime() + 30 * DAY),
    createdAt: NOW,
  });
  const txs = [
    ['txn_1', CP_A, 5],
    ['txn_2', CP_B, 3],
    ['txn_3', CP_OLD, 200], // outside the 90-day window
  ];
  for (const [id, cp, daysAgo] of txs) {
    await store.transactions.insert({ id, agentId: 'agt_TB', wallet: WALLET, asset: 'USDC', amount: 2_000_000_000, counterparty: { address: cp, name: null }, signingKeyThumbprint: 'thumb', status: 'settled', at: new Date(NOW.getTime() - daysAgo * DAY) });
  }
  await store.sanctions.insert({ id: 'sdn_OTHER', name: 'Other', aliases: [], type: 'entity', wallets: [{ chain: 'evm', address: '0x5a5a000000000000000000000000000000000001' }], datasetVersion: '2026-09-01' });
  const passports = passportService({ store, clock, audit });
  await passports.issue(SYSTEM_ACTOR, { id: 'pp_TB', agentId: 'agt_TB', principalId: 'op_NW', delegationId: 'grt_TB', delegationVersion: 1, wallet: WALLET, sanctionsDatasetVersion: '2026-09-01', harnessVersion: 1, expiresAt: new Date(NOW.getTime() + 30 * DAY) });
  const rescreen = rescreenService({ store, clock, audit, events });
  return { store, rescreen, published };
}

const ref = (n = 1) => ({ sanctionsId: 'sdn_NEW', datasetVersion: '2026-09-26', changeEventId: changeEventId({ _data: `token-${n}` }) });

test('every riskDecision maps to a legal RE_SCREENING transition for the system actor', () => {
  assert.deepEqual(PASSPORT_BY_DECISION, { BLOCK: 'SUSPENDED', REVIEW: 'REVIEW', ALLOW: 'ACTIVE' });
  for (const to of Object.values(PASSPORT_BY_DECISION)) assert.ok(isLegalTransition('RE_SCREENING', to, 'system'));
});

test('sanctionedAddresses lowercases and drops malformed wallets; ids are deterministic', () => {
  assert.deepEqual(sanctionedAddresses({ wallets: [{ address: CP_B.toUpperCase().replace('0X', '0x') }, { address: 'nope' }, { address: CP_B }] }), [CP_B]);
  assert.equal(changeEventId({ _data: 'abc' }), changeEventId({ _data: 'abc' }));
  assert.notEqual(changeEventId({ _data: 'abc' }), changeEventId({ _data: 'abd' }));
  assert.match(investigationIdFor('chg_1', 'agt_TB'), /^inv_[0-9A-F]{26}$/);
});

test('exact hit on a counterparty: ACTIVE -> RE_SCREENING -> SUSPENDED, sanctions_change investigation, events', async () => {
  const { store, rescreen, published } = await setup();
  await store.sanctions.insert({ id: 'sdn_NEW', name: 'Meridian OTC Desk', aliases: [], type: 'entity', wallets: [{ chain: 'evm', address: CP_B }], datasetVersion: '2026-09-26' });
  const r = await rescreen.rescreenAgent({ agentId: 'agt_TB', triggerRef: ref(), matched: { viaWallet: [], viaCounterparty: [{ address: CP_B, name: null }] } });
  assert.equal(r.riskDecision, 'BLOCK');
  assert.equal(r.passportStatus, 'SUSPENDED');
  const p = await store.passports.findById('pp_TB');
  assert.deepEqual(p.statusHistory.map((h) => h.status), ['ACTIVE', 'RE_SCREENING', 'SUSPENDED']);
  assert.equal(p.statusReason, 'SANCTIONS_EXACT_MATCH');
  assert.equal(p.lastInvestigationId, r.investigationId);

  const inv = await store.investigations.findById(r.investigationId);
  assert.equal(inv.trigger, 'sanctions_change');
  assert.deepEqual(inv.triggerRef, ref());
  assert.equal(inv.transaction.amount, null);
  assert.equal(inv.reasons[0].code, 'SANCTIONS_EXACT_MATCH');
  assert.equal(inv.reasons[0].invariantId, 'INV_SANCTIONS_EXACT_BLOCK');
  const stage = (n) => inv.stages.find((s) => s.name === n);
  assert.equal(stage('identity').result.mode, 'state');
  assert.equal(stage('delegation').result.withinMax, 'not_applicable');
  assert.equal(stage('signals').status, 'skipped');
  assert.equal(stage('signals').result.notApplicable, true);
  assert.equal(stage('memory').status, 'skipped');
  // 90-day window, plus the matched counterparty; the 200-day-old one is out of scope.
  assert.deepEqual(stage('sanctions').result.screened.map((s) => s.address).sort(), [WALLET, CP_A, CP_B].sort());
  assert.ok(store._auditLog.some((e) => e.type === 'investigation.decided' && e.subjectId === r.investigationId && e.actor.role === 'system'));
  assert.deepEqual(
    published.map((e) => e.type),
    ['passport.status_changed', 'rescreen_started', 'investigation.decided', 'passport.status_changed', 'passport_suspended'],
  );
});

test('the matched counterparty is screened even when it is older than the 90-day window', async () => {
  const { store, rescreen } = await setup();
  await store.sanctions.insert({ id: 'sdn_NEW', name: 'Old Desk', aliases: [], type: 'entity', wallets: [{ chain: 'evm', address: CP_OLD }], datasetVersion: '2026-09-26' });
  const r = await rescreen.rescreenAgent({ agentId: 'agt_TB', triggerRef: ref(), matched: { viaWallet: [], viaCounterparty: [{ address: CP_OLD, name: null }] } });
  assert.equal(r.riskDecision, 'BLOCK');
  assert.equal(r.passportStatus, 'SUSPENDED');
});

test('clean re-screen: RE_SCREENING -> ACTIVE (ALLOW)', async () => {
  const { store, rescreen } = await setup();
  const r = await rescreen.rescreenAgent({ agentId: 'agt_TB', triggerRef: ref(), matched: { viaWallet: [], viaCounterparty: [] } });
  assert.equal(r.riskDecision, 'ALLOW');
  const p = await store.passports.findById('pp_TB');
  assert.deepEqual(p.statusHistory.map((h) => h.status), ['ACTIVE', 'RE_SCREENING', 'ACTIVE']);
});

test('replaying the same change event is idempotent; an interrupted re-screen resumes from RE_SCREENING', async () => {
  const { store, rescreen } = await setup();
  await store.sanctions.insert({ id: 'sdn_NEW', name: 'Meridian', aliases: [], type: 'entity', wallets: [{ chain: 'evm', address: CP_B }], datasetVersion: '2026-09-26' });
  const matched = { viaWallet: [], viaCounterparty: [{ address: CP_B, name: null }] };
  // Crash right after RE_SCREENING (before the investigation was written).
  const crashing = rescreenService({
    store,
    clock: { now: () => NOW },
    audit: auditService({ store, clock: { now: () => NOW } }),
    hooks: {
      onStep: (step) => {
        if (step === 'rescreen_started') throw new Error('simulated crash');
      },
    },
  });
  await assert.rejects(crashing.rescreenAgent({ agentId: 'agt_TB', triggerRef: ref(), matched }), /simulated crash/);
  assert.equal((await store.passports.findById('pp_TB')).status, 'RE_SCREENING');
  const r1 = await rescreen.rescreenAgent({ agentId: 'agt_TB', triggerRef: ref(), matched });
  const r2 = await rescreen.rescreenAgent({ agentId: 'agt_TB', triggerRef: ref(), matched });
  assert.equal(r1.investigationId, r2.investigationId);
  const p = await store.passports.findById('pp_TB');
  assert.deepEqual(p.statusHistory.map((h) => h.status), ['ACTIVE', 'RE_SCREENING', 'SUSPENDED']);
  assert.equal((await store.investigations.find({ trigger: 'sanctions_change' })).length, 1);
  assert.equal(store._auditLog.filter((e) => e.type === 'investigation.decided').length, 1);
});

test('failClosed moves a passport stuck in RE_SCREENING to SUSPENDED (INTERNAL_ERROR) and ignores others', async () => {
  const { store, rescreen } = await setup();
  assert.equal(await rescreen.failClosed('agt_TB', ref()), null); // ACTIVE: untouched
  await rescreen.passports.transition('pp_TB', ['ACTIVE'], 'RE_SCREENING', 'test', SYSTEM_ACTOR);
  const p = await rescreen.failClosed('agt_TB', ref());
  assert.equal(p.status, 'SUSPENDED');
  assert.equal(p.statusReason, 'INTERNAL_ERROR');
});

test('the not-applicable amount path is gated on the trigger: a missing amount elsewhere still BLOCKs', async () => {
  const { store } = await setup();
  const r = await runInvestigation({ store, agentId: 'agt_TB', delegationId: 'grt_TB', trigger: 'manual', now: NOW, tx: { asset: 'USDC', wallet: WALLET, counterparty: { address: CP_A, name: null }, signingKeyThumbprint: 'thumb' } });
  assert.equal(r.riskDecision, 'BLOCK');
  const delegation = r.stages.find((s) => s.name === 'delegation');
  assert.equal(delegation.result.withinMax, false);
  assert.ok(r.reasons.some((x) => x.code === 'DELEGATION_MAX_EXCEEDED'));
});
