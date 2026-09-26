// REQ-015 dashboard: trust-score derivation, audit-log summary, static
// serving, and security invariants of the browser code.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
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
  const raw = readFileSync(new URL('../dashboard/app.js', import.meta.url), 'utf8') + readFileSync(new URL('../dashboard/trust.js', import.meta.url), 'utf8');
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
