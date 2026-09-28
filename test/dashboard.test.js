// REQ-015 dashboard: trust-score derivation, audit-log summary, static
// serving, and security invariants of the browser code.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import {
  addedSteps,
  createSseParser,
  fromReceipt,
  kyaStripApply,
  kyaStripInit,
  PROVENANCE_NOTE,
  renderInvestigation,
  renderKyaStrip,
} from '../dashboard/investigations.js';
import { denyCountsByReason, trustAssessment } from '../dashboard/trust.js';
import { createOperator, registerAgent, world } from './helpers.js';

const NOW = new Date('2026-09-26T12:00:00Z');
const agent = { id: 'agt_1', operatorId: 'op_1', status: 'active', createdAt: '2026-09-01T00:00:00Z' };
const operator = {
  id: 'op_1',
  status: 'verified',
  verification: { method: 'mock', kycResult: 'pass', sanctionsMode: 'mock', sanctionsResult: 'clear' },
};
const ev = (decision, code, agentId = 'agt_1') => ({ agentId, decision, reasons: [{ code }] });

test('trust: active agent + verified operator with clean history scores 100/high', () => {
  const t = trustAssessment({ agent, operator, verifications: [ev('ALLOW', 'ALLOWED')], now: NOW });
  assert.equal(t.score, 100);
  assert.equal(t.level, 'high');
  assert.match(t.verdict, /Identity verified/);
});

test('trust: hard gates mirror verify checks and yield 0/untrusted', () => {
  for (const s of ['revoked', 'suspended']) {
    const t = trustAssessment({ agent: { ...agent, status: s }, operator, now: NOW });
    assert.deepEqual([t.score, t.level], [0, 'untrusted']);
    assert.match(t.verdict, new RegExp(s));
  }
  for (const s of ['pending', 'rejected', 'suspended']) {
    const t = trustAssessment({ agent, operator: { ...operator, status: s }, now: NOW });
    assert.deepEqual([t.score, t.level], [0, 'untrusted']);
  }
  assert.equal(trustAssessment({ agent, operator: null, now: NOW }).level, 'untrusted');
  assert.equal(trustAssessment({ agent: null, now: NOW }).level, 'untrusted');
  assert.equal(trustAssessment({ agent, operator: { ...operator, id: 'op_other' }, now: NOW }).level, 'untrusted');
  // Unknown / hostile status values are never echoed verbatim.
  const odd = trustAssessment({ agent: { ...agent, status: '<img src=x>' }, operator, now: NOW });
  assert.equal(odd.level, 'untrusted');
  assert.doesNotMatch(odd.verdict, /</);
});

test('trust: penalties for skipped sanctions, new key, denies and security signals', () => {
  const skipped = trustAssessment({ agent, operator: { ...operator, verification: { ...operator.verification, sanctionsResult: 'skipped' } }, now: NOW });
  assert.equal(skipped.score, 85);
  const fresh = trustAssessment({ agent: { ...agent, createdAt: '2026-09-26T11:00:00Z' }, operator, now: NOW });
  assert.equal(fresh.score, 90);
  // 2 of 4 denies => -10; one is a security signal => -10
  const history = [ev('ALLOW', 'ALLOWED'), ev('ALLOW', 'ALLOWED'), ev('DENY', 'NO_GRANT'), ev('DENY', 'SIGNATURE_INVALID'), ev('DENY', 'NONCE_REPLAYED', 'agt_other')];
  const t = trustAssessment({ agent, operator, verifications: history, now: NOW });
  assert.equal(t.score, 80);
  assert.ok(t.factors.some((f) => f.label === 'Security signals' && f.impact === -10));
  // Many signals: bounded, never reaches 0 (0 is reserved for hard-gate failures).
  const attack = Array.from({ length: 20 }, () => ev('DENY', 'NONCE_REPLAYED'));
  const a = trustAssessment({ agent: { ...agent, createdAt: NOW.toISOString() }, operator, verifications: attack, now: NOW });
  assert.equal(a.level, 'low');
  assert.ok(a.score >= 1 && a.score < 50);
  // Business view: public operator profile without verification detail is not penalised.
  const pub = trustAssessment({ agent, operator: { id: 'op_1', status: 'verified' }, now: NOW });
  assert.equal(pub.score, 100);
});

test('denyCountsByReason groups DENY decisions only, sorted by count', () => {
  const rows = [ev('DENY', 'NO_GRANT'), ev('ALLOW', 'ALLOWED'), ev('DENY', 'AGENT_REVOKED'), ev('DENY', 'NO_GRANT'), { decision: 'DENY', reasons: [] }];
  assert.deepEqual(denyCountsByReason(rows), [
    { code: 'NO_GRANT', count: 2 },
    { code: 'AGENT_REVOKED', count: 1 },
    { code: 'UNKNOWN', count: 1 },
  ]);
  assert.deepEqual(denyCountsByReason(null), []);
});

test('dashboard serves trust module with CSP; trust reflects live API state and revocation', async (tc) => {
  const w = await world();
  tc.after(w.t.close);
  const { t } = w;
  const mod = await t.call(null, 'GET', '/dashboard/trust.js');
  assert.equal(mod.status, 200);
  assert.match(mod.headers.get('content-type'), /javascript/);
  assert.match(mod.headers.get('content-security-policy'), /default-src 'none'/);

  // Exactly the calls the dashboard makes for the admin agent detail view.
  const a = (await t.call(t.admin, 'GET', `/v1/agents/${w.agent.agent.id}`)).body;
  const op = (await t.call(t.admin, 'GET', `/v1/operators/${a.operatorId}`)).body;
  assert.equal((await w.verify(w.signed())).decision, 'ALLOW');
  const events = (await t.call(t.admin, 'GET', `/v1/verifications?agentId=${a.id}&limit=100`)).body.data;
  assert.equal(events.length, 1);
  const before = trustAssessment({ agent: a, operator: op, verifications: events });
  assert.notEqual(before.level, 'untrusted');
  assert.ok(before.score > 0);

  // Business lookup sees only the public operator profile but still gets a score.
  const bizAgent = (await t.call(w.business.key, 'GET', `/v1/agents/${a.id}`)).body;
  const bizOp = (await t.call(w.business.key, 'GET', `/v1/operators/${a.operatorId}`)).body;
  assert.equal(bizOp.contactEmail, undefined);
  assert.notEqual(trustAssessment({ agent: bizAgent, operator: bizOp }).level, 'untrusted');

  // Revoke via the same endpoint the dashboard uses; next read is untrusted and verify denies.
  const rev = await t.call(w.operator.key, 'POST', `/v1/agents/${a.id}/revoke`, { reason: 'key compromised' });
  assert.equal(rev.status, 200);
  const after = (await t.call(t.admin, 'GET', `/v1/agents/${a.id}`)).body;
  assert.deepEqual([trustAssessment({ agent: after, operator: op }).score, trustAssessment({ agent: after, operator: op }).level], [0, 'untrusted']);
  const denied = await w.verify(w.signed());
  assert.equal(denied.decision, 'DENY');
  assert.equal(denied.reasons[0].code, 'AGENT_REVOKED');

  // Audit log records both decisions and the DENY summary reflects it.
  const log = (await t.call(w.business.key, 'GET', '/v1/verifications?limit=50')).body.data;
  assert.deepEqual(denyCountsByReason(log), [{ code: 'AGENT_REVOKED', count: 1 }]);

  // Suspended operator => agents of that operator are untrusted.
  const other = await createOperator(t, { legalName: 'Other Ltd' });
  const other_agent = await registerAgent(t, other);
  await t.call(t.admin, 'POST', `/v1/operators/${other.op.id}/suspend`, { reason: 'investigation' });
  const susOp = (await t.call(t.admin, 'GET', `/v1/operators/${other.op.id}`)).body;
  assert.equal(trustAssessment({ agent: other_agent.agent, operator: susOp }).level, 'untrusted');
});

test('dashboard code: no persistent key storage, no innerHTML, only contract endpoints', () => {
  const raw = ['app.js', 'trust.js', 'investigations.js'].map((f) => readFileSync(new URL(`../dashboard/${f}`, import.meta.url), 'utf8')).join('\n');
  const src = raw.replace(/^\s*\/\/.*$/gm, ''); // ignore line comments (the security notes name the banned APIs)
  for (const banned of ['localStorage', 'sessionStorage', 'document.cookie', 'innerHTML', 'outerHTML', 'insertAdjacentHTML', 'eval(']) {
    assert.ok(!src.includes(banned), `dashboard must not use ${banned}`);
  }
  const openapi = readFileSync(new URL('../docs/contracts/openapi.yaml', import.meta.url), 'utf8');
  const paths = [...openapi.matchAll(/^ {2}(\/[^:\s]+):/gm)].map((m) => m[1]);
  const toRe = (p) => new RegExp(`^${p.replace(/\{id\}/g, '[^/]+')}$`);
  const used = [...src.matchAll(/['`](\/(?:v1|healthz)[^'`?]*)/g)].map((m) => m[1].replace(/\$\{[^}]+\}/g, 'X'));
  assert.ok(used.length > 10);
  for (const u of used) assert.ok(paths.some((p) => toRe(p).test(u)), `${u} is not in openapi.yaml`);
});

// ------------------------------------------------------------------ T16 investigations view + Continuous KYA strip

/** DOM-free element factory with the same (tag, attrs, ...children) contract as app.js `el`. */
function h(tag, attrs = {}, ...children) {
  const kids = children.flat(Infinity).filter((c) => c !== null && c !== undefined && c !== false);
  return { tag, attrs, children: attrs.text !== undefined ? [String(attrs.text), ...kids] : kids };
}
const walk = (n, out = []) => {
  if (n && typeof n === 'object') {
    out.push(n);
    n.children.forEach((c) => walk(c, out));
  }
  return out;
};
const textOf = (n) => (typeof n === 'string' ? n : n.children.map(textOf).join(''));

// Fixture investigation JSON (openapi Investigation) shaped like Demo 2's TreasuryBot takeover case.
const INVESTIGATION = {
  id: 'inv_demo2_treasurybot',
  trigger: 'api',
  status: 'AWAITING_REVIEW',
  agentId: 'agt_treasurybot',
  principalId: 'op_acme',
  businessId: 'biz_merchant',
  delegationId: 'grt_treasury',
  delegationVersion: 1,
  action: 'payments:create',
  transaction: { asset: 'USDC', amount: 49000000000, wallet: '0x1111111111111111111111111111111111111111', counterparty: { address: '0x2222222222222222222222222222222222222222', name: 'Unknown LLC' } },
  harnessVersion: 2,
  stages: [
    { name: 'identity', engine: 'code', status: 'passed', durationMs: 3 },
    { name: 'delegation', engine: 'find+code', status: 'passed', durationMs: 4 },
    { name: 'sanctions', engine: 'find+$search', status: 'passed', durationMs: 21 },
    { name: 'signals', engine: 'aggregate', status: 'flagged', durationMs: 9 },
    { name: 'memory', engine: '$vectorSearch', status: 'flagged', durationMs: 35 },
    { name: 'signing_key_history_check', engine: 'find+aggregate', status: 'flagged', durationMs: 6 },
    { name: 'policy', engine: 'code', status: 'flagged', durationMs: 1 },
  ],
  signals: ['SIGNING_KEY_CHANGED', 'NEW_COUNTERPARTY', 'NEAR_CEILING'],
  memory: {
    engine: '$vectorSearch',
    k: 3,
    minScorePpm: 750000,
    hits: [
      { memoryId: 'mem_INV-1042', title: 'Treasury agent account takeover', status: 'VERIFIED', outcome: 'CONFIRMED_ACCOUNT_TAKEOVER', score: 0.91234, scorePpm: 912340, signals: ['SIGNING_KEY_CHANGED'], recommendedSteps: ['signing_key_history_check'], usedAsPrecedent: true },
    ],
  },
  decision: 'ALLOW',
  riskDecision: 'REVIEW',
  reasons: [{ code: 'MEMORY_PRECEDENT_TAKEOVER', riskDecision: 'REVIEW', message: 'Matches a verified account-takeover precedent', stage: 'policy' }],
  outcome: null,
  passport: { id: 'pp_treasurybot', before: 'ACTIVE', after: 'REVIEW' },
  receiptId: 'rcp_demo2',
  receiptHash: 'a'.repeat(64),
  requestId: 'req_1',
  createdAt: '2026-09-26T12:00:00.000Z',
  decidedAt: '2026-09-26T12:00:01.000Z',
  confirmedAt: null,
};
const VERSIONS = [
  { version: 2, status: 'active', parentVersion: 1, policy: { steps: ['identity', 'delegation', 'sanctions', 'signals', 'memory', 'signing_key_history_check', 'policy'] } },
  { version: 1, status: 'superseded', parentVersion: null, policy: { steps: ['identity', 'delegation', 'sanctions', 'signals', 'memory', 'policy'] } },
];

test('investigations view: renders the four evidence panels from a fixture investigation', () => {
  const opened = [];
  const tree = renderInvestigation(h, INVESTIGATION, { versions: VERSIONS, onReceipt: (id) => opened.push(id) });
  const nodes = walk(tree);
  const headings = nodes.filter((n) => n.tag === 'h2').map(textOf);
  assert.deepEqual(headings, ['Current signals', 'MongoDB security memory (Vector Search)', 'Harness v2', 'Decision + receipt']);
  const all = textOf(tree);
  // Current signals
  for (const s of INVESTIGATION.signals) assert.ok(all.includes(s));
  // Security memory: id, title, outcome, retrieval path, score, VERIFIED badge
  for (const s of ['mem_INV-1042', 'Treasury agent account takeover', 'CONFIRMED_ACCOUNT_TAKEOVER', 'Retrieved through Vector Search', '0.9123']) assert.ok(all.includes(s), s);
  assert.ok(nodes.some((n) => n.attrs.class === 'badge verified' && textOf(n) === 'VERIFIED'));
  // Harness: added step highlighted + provenance note
  const addedRows = nodes.filter((n) => n.tag === 'tr' && n.attrs.class === 'added-step');
  assert.deepEqual(addedRows.map((r) => textOf(r.children[0])), ['signing_key_history_checkadded in v2']);
  assert.ok(all.includes(PROVENANCE_NOTE));
  // Decision + receipt link
  assert.ok(nodes.some((n) => n.attrs.class === 'stamp REVIEW' && textOf(n) === 'REVIEW'));
  for (const s of ['MEMORY_PRECEDENT_TAKEOVER', 'rcp_demo2', 'ACTIVE', 'REVIEW']) assert.ok(all.includes(s), s);
  const button = nodes.find((n) => n.tag === 'button');
  assert.equal(textOf(button), 'Open receipt');
  button.attrs.onclick();
  assert.deepEqual(opened, ['inv_demo2_treasurybot']);
});

test('investigations view: never claims more than the evidence shows', () => {
  const plain = { ...INVESTIGATION, harnessVersion: 1, memory: { engine: '$vectorSearch', k: 3, minScorePpm: 750000, hits: [] }, stages: INVESTIGATION.stages.filter((s) => s.name !== 'signing_key_history_check') };
  const all = textOf(renderInvestigation(h, plain, { versions: VERSIONS }));
  assert.ok(all.includes('Harness v1'));
  assert.ok(!all.includes(PROVENANCE_NOTE));
  assert.ok(all.includes('No verified prior incidents matched'));
  assert.ok(all.includes('No step added relative to the parent harness version.'));
  // Harness versions unavailable: added steps are reported unknown, not guessed.
  const unknown = renderInvestigation(h, INVESTIGATION, { versions: null });
  assert.ok(textOf(unknown).includes('added steps are unknown'));
  assert.ok(!textOf(unknown).includes(PROVENANCE_NOTE));
  // A non-VERIFIED hit (contract violation) is flagged, never badged VERIFIED.
  const bad = { ...INVESTIGATION, memory: { ...INVESTIGATION.memory, hits: [{ ...INVESTIGATION.memory.hits[0], status: 'UNVERIFIED' }] } };
  const badNodes = walk(renderInvestigation(h, bad, { versions: VERSIONS }));
  assert.ok(!badNodes.some((n) => n.attrs.class === 'badge verified'));
  assert.ok(!textOf(badNodes[0]).includes(PROVENANCE_NOTE));
  assert.deepEqual(addedSteps(VERSIONS, 2), ['signing_key_history_check']);
  assert.deepEqual(addedSteps(VERSIONS, 1), []);
});

test('investigations view: receipt payload maps onto the same four panels', () => {
  const receipt = {
    receiptVersion: 'kya-receipt-v1', receiptId: 'rcp_1', investigationId: 'inv_1', trigger: 'sanctions_change', issuedAt: '2026-09-26T12:00:00Z',
    decision: 'ALLOW', riskDecision: 'BLOCK', reasons: [{ code: 'SANCTIONS_EXACT_MATCH', riskDecision: 'BLOCK', stage: 'sanctions', invariantId: 'INV_SANCTIONS_EXACT_BLOCK' }],
    agent: { id: 'agt_1', keyThumbprint: null, wallet: null }, transaction: null, harnessVersion: 1, stages: [{ name: 'sanctions', engine: 'find+$search', status: 'failed', durationMs: 2 }],
    signals: [], memory: { checked: true, engine: '$vectorSearch', embeddingModel: null, k: 3, minScorePpm: 750000, hits: [{ memoryId: 'mem_INV-0977', status: 'VERIFIED', outcome: 'SANCTIONS_MATCH', scorePpm: 801000, usedAsPrecedent: false }] },
    passport: { id: 'pp_1', before: 'RE_SCREENING', after: 'SUSPENDED' }, receiptHash: 'b'.repeat(64),
  };
  const tree = renderInvestigation(h, fromReceipt(receipt), { versions: VERSIONS });
  assert.deepEqual(walk(tree).filter((n) => n.tag === 'h2').map(textOf), ['Current signals', 'MongoDB security memory (Vector Search)', 'Harness v1', 'Decision + receipt']);
  const all = textOf(tree);
  for (const s of ['mem_INV-0977', '0.8010', 'BLOCK', 'INV_SANCTIONS_EXACT_BLOCK', 'SUSPENDED', 'No behavioural signals']) assert.ok(all.includes(s), s);
});

test('continuous KYA strip: SSE frames drive change detected -> affected agent -> re-screen -> suspended', () => {
  let strip = kyaStripInit();
  const seen = [];
  const push = createSseParser((evt) => {
    seen.push(evt.type);
    strip = kyaStripApply(strip, evt);
  });
  const frame = (type, data) => `event: ${type}\ndata: ${JSON.stringify(data)}\n\n`;
  const text =
    'retry: 3000\n: connected\n\n' +
    frame('change_detected', { sanctionsId: 'sdn_X', datasetVersion: '2026-09-26', affectedAgentIds: ['agt_T'] }) +
    frame('affected_agent', { agentId: 'agt_T' }) +
    frame('rescreen_started', { agentId: 'agt_T' }) +
    frame('passport_suspended', { agentId: 'agt_T', reasonCode: 'SANCTIONS_EXACT_MATCH' }) +
    'event: bogus\ndata: {not json\n\n';
  // Delivered in arbitrary chunk boundaries.
  for (let i = 0; i < text.length; i += 7) push(text.slice(i, i + 7));
  assert.deepEqual(seen, ['change_detected', 'affected_agent', 'rescreen_started', 'passport_suspended']);
  assert.ok(strip.steps.every((s) => s.done));
  const nodes = walk(renderKyaStrip(h, strip));
  assert.deepEqual(nodes.filter((n) => n.attrs.class === 'kya-label').map(textOf), ['MongoDB Change Detected', 'Affected Agent Found', 'Re-screen Started', 'Passport Suspended']);
  assert.ok(textOf(nodes[0]).includes('sdn_X · dataset 2026-09-26 · 1 affected'));
  assert.ok(nodes.some((n) => /critical/.test(n.attrs.class ?? '')));
  // A new change resets the strip.
  strip = kyaStripApply(strip, { type: 'change_detected', data: { sanctionsId: 'sdn_Y', affectedAgentIds: [] } });
  assert.deepEqual(strip.steps.map((s) => s.done), [true, false, false, false]);
  assert.equal(kyaStripApply(strip, { type: 'harness.adapted', data: {} }), strip);
});

test('continuous KYA strip updates from the live /v1/events/stream endpoint', async (tc) => {
  const w = await world();
  tc.after(w.t.close);
  const { t } = w;
  const mod = await t.call(null, 'GET', '/dashboard/investigations.js');
  assert.equal(mod.status, 200);
  assert.match(mod.headers.get('content-security-policy'), /default-src 'none'/);

  const ac = new AbortController();
  tc.after(() => ac.abort());
  const res = await fetch(`${t.base}/v1/events/stream`, { headers: { Authorization: `Bearer ${t.admin}`, Accept: 'text/event-stream' }, signal: ac.signal });
  assert.equal(res.status, 200);
  let strip = kyaStripInit();
  const push = createSseParser((evt) => {
    strip = kyaStripApply(strip, evt);
  });
  const reader = res.body.pipeThrough(new TextDecoderStream()).getReader();
  const readUntil = async (pred) => {
    const deadline = Date.now() + 3000;
    while (!pred()) {
      assert.ok(Date.now() < deadline, 'timed out waiting for stream events');
      const r = await reader.read();
      assert.ok(!r.done, 'stream ended');
      push(r.value);
    }
  };
  assert.match((await reader.read()).value, /: connected/);
  t.app.events.publish('change_detected', { sanctionsId: 'sdn_X', datasetVersion: '2026-09-26', affectedAgentIds: ['agt_T'] });
  t.app.events.publish('affected_agent', { agentId: 'agt_T' });
  t.app.events.publish('rescreen_started', { agentId: 'agt_T' });
  t.app.events.publish('passport.status_changed', { passportId: 'pp_T', agentId: 'agt_T', from: 'RE_SCREENING', to: 'SUSPENDED', investigationId: 'inv_T' });
  await readUntil(() => strip.steps.every((s) => s.done));
  assert.equal(strip.agentId, 'agt_T');
});
