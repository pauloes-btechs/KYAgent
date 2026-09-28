import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import {
  INVARIANTS,
  INVARIANTS_HASH,
  INVARIANTS_SOURCE_SHA256,
  holds,
  invariant,
  precedentMemories,
  validatePolicy,
} from '../src/harness/invariants.js';
import { constraintsSatisfied } from '../src/services/authz.js';

const SEED_POLICY = {
  steps: ['identity', 'delegation', 'sanctions', 'signals', 'memory', 'policy'],
  memoryRetrieval: { k: 3, numCandidates: 100, minScorePpm: 780000, filter: { status: 'VERIFIED' } },
  contextAssembly: { maxMemories: 3, includeSignalStats: true, includeSanctionsEvidence: true },
  evidenceRequests: [],
  escalation: [
    {
      id: 'precedent_takeover',
      when: { precedentOutcomeIn: ['CONFIRMED_ACCOUNT_TAKEOVER'] },
      then: { riskDecision: 'REVIEW', reasonCode: 'MEMORY_PRECEDENT_TAKEOVER' },
    },
  ],
};
const policy = (patch = {}) => ({ ...structuredClone(SEED_POLICY), ...patch });

const IDS = [
  'INV_SANCTIONS_EXACT_BLOCK',
  'INV_DELEGATION_MAX',
  'INV_DAILY_LIMIT',
  'INV_NO_SELF_APPROVAL',
  'INV_NO_SELF_PASSPORT_MODIFICATION',
  'INV_UNVERIFIED_MEMORY_NOT_PRECEDENT',
];

// ------------------------------------------------------------ immutability
test('INVARIANTS lists exactly the six contract ids, in order', () => {
  assert.deepEqual(INVARIANTS.map((i) => i.id), IDS);
});

test('INVARIANTS array, every element and every check are frozen', () => {
  assert.ok(Object.isFrozen(INVARIANTS));
  for (const i of INVARIANTS) assert.ok(Object.isFrozen(i), i.id);
  assert.throws(() => INVARIANTS.push({ id: 'INV_EVIL' }), TypeError);
  assert.throws(() => INVARIANTS.pop(), TypeError);
  assert.throws(() => {
    INVARIANTS[0] = {};
  }, TypeError);
  assert.throws(() => {
    INVARIANTS[1].check = () => true;
  }, TypeError);
  assert.throws(() => {
    delete INVARIANTS[2].check;
  }, TypeError);
  assert.equal(INVARIANTS.length, 6);
});

test('INVARIANTS_HASH is the pinned canonical-metadata hash (harness.md §1)', () => {
  assert.equal(INVARIANTS_HASH, 'f88ecf79577c9d3810e286772d14e0a3124be9b450127cc2859d6d49bac3348d');
});

test('INVARIANTS_SOURCE_SHA256 is sha256 of the module source', () => {
  const src = readFileSync(new URL('../src/harness/invariants.js', import.meta.url));
  assert.equal(INVARIANTS_SOURCE_SHA256, createHash('sha256').update(src).digest('hex'));
  assert.match(INVARIANTS_SOURCE_SHA256, /^[0-9a-f]{64}$/);
});

test('unknown invariant ids throw instead of passing', () => {
  assert.throws(() => invariant('INV_NOPE'));
  assert.throws(() => holds('__proto__', {}));
});

test('a throwing check fails closed', () => {
  const evil = {
    get addresses() {
      throw new Error('boom');
    },
  };
  assert.equal(holds('INV_SANCTIONS_EXACT_BLOCK', evil), false);
});

// ------------------------------------------------------------ INV_SANCTIONS_EXACT_BLOCK
test('INV_SANCTIONS_EXACT_BLOCK holds when no address is sanctioned', () => {
  assert.equal(
    holds('INV_SANCTIONS_EXACT_BLOCK', {
      addresses: ['0x' + 'a'.repeat(40), '0x' + 'b'.repeat(40)],
      sanctionedAddresses: ['0x' + 'c'.repeat(40)],
    }),
    true,
  );
  assert.equal(holds('INV_SANCTIONS_EXACT_BLOCK', { addresses: [], sanctionedAddresses: [] }), true);
});

test('INV_SANCTIONS_EXACT_BLOCK breaches on an exact (case-insensitive) hit', () => {
  const hit = '0x' + 'AbC1'.repeat(10);
  assert.equal(
    holds('INV_SANCTIONS_EXACT_BLOCK', { addresses: ['0x' + 'a'.repeat(40), hit], sanctionedAddresses: new Set([hit.toLowerCase()]) }),
    false,
  );
  assert.equal(holds('INV_SANCTIONS_EXACT_BLOCK', { addresses: [hit.toLowerCase()], sanctionedAddresses: [hit] }), false);
  assert.equal(invariant('INV_SANCTIONS_EXACT_BLOCK').reasonCode, 'SANCTIONS_EXACT_MATCH');
  // malformed input fails closed
  assert.equal(holds('INV_SANCTIONS_EXACT_BLOCK', {}), false);
  assert.equal(holds('INV_SANCTIONS_EXACT_BLOCK', { addresses: [42], sanctionedAddresses: [] }), false);
});

// ------------------------------------------------------------ INV_DELEGATION_MAX
test('INV_DELEGATION_MAX holds within maxAmount and matches authz.constraintsSatisfied', () => {
  const input = { constraints: { maxAmount: 1000, currency: 'USD' }, resource: '', context: { amount: 1000, currency: 'USD' } };
  assert.equal(holds('INV_DELEGATION_MAX', input), true);
  assert.equal(holds('INV_DELEGATION_MAX', { constraints: undefined, resource: '', context: {} }), true);
});

test('INV_DELEGATION_MAX breaches above maxAmount, on missing/negative amounts, and agrees with authz for every case', () => {
  const cases = [
    [{ maxAmount: 1000 }, '', { amount: 1001 }],
    [{ maxAmount: 1000 }, '', {}],
    [{ maxAmount: 1000 }, '', { amount: -1 }],
    [{ maxAmount: 1000 }, '', { amount: 10.5 }],
    [{ currency: 'USD' }, '', { currency: 'EUR' }],
    [{ resources: ['r1'] }, 'r2', {}],
    [{ resources: ['r1'] }, 'r1', {}],
    [{ maxAmount: 5 }, '', { amount: 5 }],
  ];
  for (const [constraints, resource, context] of cases) {
    assert.equal(
      holds('INV_DELEGATION_MAX', { constraints, resource, context }),
      constraintsSatisfied(constraints, resource, context),
      JSON.stringify({ constraints, resource, context }),
    );
  }
  assert.equal(holds('INV_DELEGATION_MAX', { constraints: { maxAmount: 1000 }, resource: '', context: { amount: 1001 } }), false);
  assert.equal(invariant('INV_DELEGATION_MAX').reasonCode, 'DELEGATION_MAX_EXCEEDED');
});

// ------------------------------------------------------------ INV_DAILY_LIMIT
test('INV_DAILY_LIMIT holds when spent24h + amount <= dailyLimit (or no limit)', () => {
  assert.equal(holds('INV_DAILY_LIMIT', { dailyLimit: 1000, spent24h: 600, amount: 400 }), true);
  assert.equal(holds('INV_DAILY_LIMIT', { spent24h: 1e9, amount: 1 }), true);
});

test('INV_DAILY_LIMIT breaches when the rolling total exceeds the limit or inputs are malformed', () => {
  assert.equal(holds('INV_DAILY_LIMIT', { dailyLimit: 1000, spent24h: 600, amount: 401 }), false);
  assert.equal(holds('INV_DAILY_LIMIT', { dailyLimit: 1000, amount: 1 }), false);
  assert.equal(holds('INV_DAILY_LIMIT', { dailyLimit: 1000, spent24h: 0, amount: -5 }), false);
  assert.equal(holds('INV_DAILY_LIMIT', { dailyLimit: '1000', spent24h: 0, amount: 1 }), false);
  assert.equal(invariant('INV_DAILY_LIMIT').reasonCode, 'DAILY_LIMIT_EXCEEDED');
});

// ------------------------------------------------------------ INV_NO_SELF_APPROVAL
const CASE = { initiatedBy: { apiKeyId: 'key_initiator' }, agentId: 'agt_1', principalId: 'op_1', businessId: 'biz_1', conflictKeyIds: ['key_initiator', 'key_root1'] };

test('INV_NO_SELF_APPROVAL holds for an independent admin', () => {
  assert.equal(holds('INV_NO_SELF_APPROVAL', { approver: { role: 'admin', apiKeyId: 'key_admin2', ownerId: null, keyLineage: ['key_admin2', 'key_root2'] }, subject: CASE }), true);
});

test('INV_NO_SELF_APPROVAL breaches for the initiator, a case party, or a non-admin', () => {
  const approve = (approver) => holds('INV_NO_SELF_APPROVAL', { approver, subject: CASE });
  assert.equal(approve({ role: 'admin', apiKeyId: 'key_initiator', ownerId: null }), false);
  assert.equal(approve({ role: 'admin', apiKeyId: 'key_x', ownerId: 'op_1' }), false);
  assert.equal(approve({ role: 'admin', apiKeyId: 'key_x', ownerId: 'biz_1' }), false);
  assert.equal(approve({ role: 'admin', apiKeyId: 'key_x', ownerId: 'agt_1' }), false);
  assert.equal(approve({ role: 'operator', apiKeyId: 'key_x', ownerId: 'op_2' }), false);
  assert.equal(approve({ role: 'business', apiKeyId: 'key_x', ownerId: 'biz_2' }), false);
  assert.equal(approve({ role: 'system', apiKeyId: null, ownerId: null }), false);
  assert.equal(approve(undefined), false);
});

// ------------------------------------------------------------ INV_NO_SELF_PASSPORT_MODIFICATION
test('INV_NO_SELF_PASSPORT_MODIFICATION holds for system and admin actors', () => {
  assert.equal(holds('INV_NO_SELF_PASSPORT_MODIFICATION', { actor: { role: 'system', apiKeyId: null, ownerId: null } }), true);
  assert.equal(holds('INV_NO_SELF_PASSPORT_MODIFICATION', { actor: { role: 'admin', apiKeyId: 'key_a', ownerId: null } }), true);
});

test('INV_NO_SELF_PASSPORT_MODIFICATION breaches for operator, business, agent or missing actor', () => {
  for (const role of ['operator', 'business', 'agent', undefined]) {
    assert.equal(holds('INV_NO_SELF_PASSPORT_MODIFICATION', { actor: { role, apiKeyId: 'key_o', ownerId: 'op_1' } }), false, String(role));
  }
  assert.equal(holds('INV_NO_SELF_PASSPORT_MODIFICATION', {}), false);
});

// ------------------------------------------------------------ INV_UNVERIFIED_MEMORY_NOT_PRECEDENT
test('INV_UNVERIFIED_MEMORY_NOT_PRECEDENT holds for VERIFIED memories', () => {
  assert.equal(holds('INV_UNVERIFIED_MEMORY_NOT_PRECEDENT', { memory: { _id: 'mem_1', status: 'VERIFIED' } }), true);
});

test('INV_UNVERIFIED_MEMORY_NOT_PRECEDENT breaches for UNVERIFIED/REJECTED/missing status and post-filters hits', () => {
  for (const status of ['UNVERIFIED', 'REJECTED', 'verified', undefined]) {
    assert.equal(holds('INV_UNVERIFIED_MEMORY_NOT_PRECEDENT', { memory: { status } }), false, String(status));
  }
  const hits = [
    { _id: 'mem_a', status: 'VERIFIED' },
    { _id: 'mem_b', status: 'UNVERIFIED' },
    { _id: 'mem_c', status: 'REJECTED' },
    null,
  ];
  assert.deepEqual(precedentMemories(hits).map((h) => h._id), ['mem_a']);
  assert.deepEqual(precedentMemories(undefined), []);
});

// ------------------------------------------------------------ validatePolicy boundary
test('validatePolicy accepts the seed v1 policy and the v2 adaptation', () => {
  assert.deepEqual(validatePolicy(policy()), []);
  const v2 = policy({ steps: ['identity', 'delegation', 'sanctions', 'signals', 'memory', 'signing_key_history_check', 'policy'] });
  v2.memoryRetrieval.k = 5;
  assert.deepEqual(validatePolicy(v2), []);
});

test('validatePolicy rejects policy documents containing invariants or skipInvariants (any depth)', () => {
  for (const key of ['invariants', 'skipInvariants', 'overrides', 'allow', 'block']) {
    assert.ok(validatePolicy({ ...policy(), [key]: [] }).length > 0, key);
  }
  assert.ok(validatePolicy({ ...policy(), invariants: INVARIANTS.map((i) => i.id) }).some((e) => e.path === '/invariants'));
  assert.ok(validatePolicy({ ...policy(), skipInvariants: true }).some((e) => e.path === '/skipInvariants'));
  const nested = policy();
  nested.escalation[0].then.skipInvariants = ['INV_SANCTIONS_EXACT_BLOCK'];
  assert.ok(validatePolicy(nested).some((e) => e.path === '/escalation/0/then/skipInvariants'));
  const nested2 = policy();
  nested2.contextAssembly.invariants = {};
  assert.ok(validatePolicy(nested2).length > 0);
});

test('validatePolicy rejects policies that could emit ALLOW/BLOCK or weaken the memory filter', () => {
  const block = policy();
  block.escalation[0].then.riskDecision = 'BLOCK';
  assert.ok(validatePolicy(block).length > 0);
  const unverified = policy();
  unverified.memoryRetrieval.filter = { status: 'UNVERIFIED' };
  assert.ok(validatePolicy(unverified).length > 0);
  const noFilter = policy();
  delete noFilter.memoryRetrieval.filter;
  assert.ok(validatePolicy(noFilter).length > 0);
});

test('validatePolicy enforces core stage order and adaptive step placement', () => {
  assert.ok(validatePolicy(policy({ steps: ['identity', 'sanctions', 'delegation', 'signals', 'memory', 'policy'] })).length > 0);
  assert.ok(validatePolicy(policy({ steps: ['identity', 'delegation', 'sanctions', 'signals', 'memory'] })).length > 0);
  assert.ok(
    validatePolicy(policy({ steps: ['identity', 'signing_key_history_check', 'delegation', 'sanctions', 'signals', 'memory', 'policy'] }))
      .length > 0,
  );
  assert.ok(validatePolicy(policy({ steps: ['identity', 'delegation', 'sanctions', 'signals', 'memory', 'llm_step', 'policy'] })).length > 0);
  assert.ok(validatePolicy(null).length > 0);
  assert.ok(validatePolicy([]).length > 0);
});
