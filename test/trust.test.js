// REQ-019: explainable, rule-based trust score per agent.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { TRUST_RULES_VERSION, scoreAgent } from '../src/services/trust.js';
import { createBusiness, createGrant, createOperator, registerAgent, world } from './helpers.js';

const NOW = new Date('2026-09-26T12:00:00Z');
const daysAgo = (d) => new Date(NOW.getTime() - d * 86400000);
const agent = { id: 'agt_1', operatorId: 'op_1', status: 'active', createdAt: daysAgo(120) };
const operator = { id: 'op_1', status: 'verified', verification: { method: 'mock', kycResult: 'pass', sanctionsResult: 'clear' } };
const grant = (actions, constraints = { maxAmount: 100 }) => ({ actions, constraints, expiresAt: daysAgo(-10) });
const factor = (r, code) => r.factors.find((f) => f.code === code);

test('trust rules: clean, aged agent of a fully verified operator scores 100/high', () => {
  const r = scoreAgent({ agent, operator, activeGrants: [grant(['payments:create'])], now: NOW });
  assert.equal(r.score, 100);
  assert.equal(r.level, 'high');
  assert.equal(r.rulesVersion, TRUST_RULES_VERSION);
  assert.deepEqual(r.gates, []);
  assert.deepEqual(r.factors.map((f) => f.code), ['operator_verification', 'agent_age', 'revocation_history', 'scope_breadth']);
  assert.equal(r.factors.reduce((s, f) => s + f.maxPoints, 0), 100);
  for (const f of r.factors) assert.ok(f.detail.length > 0 && f.label.length > 0);
});

test('trust rules: operator verification level', () => {
  const skipped = scoreAgent({ agent, operator: { ...operator, verification: { ...operator.verification, sanctionsResult: 'skipped' } }, now: NOW });
  assert.equal(factor(skipped, 'operator_verification').points, 20);
  assert.equal(skipped.score, 85);
  const noKyc = scoreAgent({ agent, operator: { ...operator, verification: null }, now: NOW });
  assert.equal(factor(noKyc, 'operator_verification').points, 0);
  for (const status of ['pending', 'rejected', 'suspended']) {
    const r = scoreAgent({ agent, operator: { ...operator, status }, now: NOW });
    assert.deepEqual([r.score, r.level], [0, 'untrusted']);
    assert.match(r.gates.join(), new RegExp(status));
  }
  const missing = scoreAgent({ agent, operator: null, now: NOW });
  assert.deepEqual([missing.score, missing.level], [0, 'untrusted']);
});

test('trust rules: agent age bands', () => {
  const pts = (d) => factor(scoreAgent({ agent: { ...agent, createdAt: daysAgo(d) }, operator, now: NOW }), 'agent_age').points;
  assert.deepEqual([0, 1, 7, 30, 90, 400].map(pts), [0, 5, 10, 15, 20, 20]);
  // Future/invalid timestamps never earn age points.
  assert.equal(pts(-5), 0);
  assert.equal(factor(scoreAgent({ agent: { ...agent, createdAt: 'garbage' }, operator, now: NOW }), 'agent_age').points, 0);
});

test('trust rules: revocation history penalties, floor at 0, fail-safe on truncation', () => {
  const r = scoreAgent({ agent, operator, revokedGrants: 1, revokedCredentials: 1, siblingRevokedOrSuspended: 1, now: NOW });
  assert.equal(factor(r, 'revocation_history').points, 25 - 8 - 5 - 5);
  assert.deepEqual(factor(r, 'revocation_history').inputs.revokedGrants, 1);
  assert.equal(factor(scoreAgent({ agent, operator, revokedGrants: 10, now: NOW }), 'revocation_history').points, 0);
  const trunc = scoreAgent({ agent, operator, truncated: { grants: false, history: true }, now: NOW });
  assert.equal(factor(trunc, 'revocation_history').points, 0);
  // A suspended agent is gated and its suspension also counts in history.
  const sus = scoreAgent({ agent: { ...agent, status: 'suspended' }, operator, now: NOW });
  assert.deepEqual([sus.score, sus.level], [0, 'untrusted']);
  assert.equal(factor(sus, 'revocation_history').points, 15);
});

test('trust rules: scope breadth penalises many patterns, wildcards and unconstrained grants', () => {
  const narrow = scoreAgent({ agent, operator, activeGrants: [], now: NOW });
  assert.equal(factor(narrow, 'scope_breadth').points, 20);
  const broad = scoreAgent({
    agent,
    operator,
    activeGrants: [grant(['orders:*', 'payments:create', 'refunds:create', 'invoices:read', 'invoices:write'], {}), grant(['payments:create'])],
    now: NOW,
  });
  const f = factor(broad, 'scope_breadth');
  assert.deepEqual(
    [f.inputs.activeGrants, f.inputs.distinctActionPatterns, f.inputs.wildcardPatterns, f.inputs.unconstrainedGrants],
    [2, 5, 1, 1],
  );
  assert.equal(f.points, 20 - 2 * 2 - 4 - 3);
  assert.equal(broad.level, 'high');
  const trunc = scoreAgent({ agent, operator, truncated: { grants: true, history: false }, now: NOW });
  assert.equal(factor(trunc, 'scope_breadth').points, 0);
  // Levels follow the thresholds.
  const low = scoreAgent({ agent: { ...agent, createdAt: NOW }, operator: { ...operator, verification: null }, revokedGrants: 5, now: NOW });
  assert.equal(low.level, 'low');
});

test('GET /v1/agents/{id}/trust-score: RBAC, live state, revocation history and scope', async (tc) => {
  const w = await world();
  tc.after(w.t.close);
  const { t, operator, business, agent } = w;
  const path = `/v1/agents/${agent.agent.id}/trust-score`;

  const unauth = await t.call(null, 'GET', path);
  assert.equal(unauth.status, 401);

  const fresh = await t.call(business.key, 'GET', path);
  assert.equal(fresh.status, 200, fresh.text);
  assert.equal(fresh.body.agentId, agent.agent.id);
  assert.equal(fresh.body.level, 'high'); // new agent: age 0, one constrained grant
  assert.equal(fresh.body.score, 35 + 0 + 25 + 20);
  assert.equal((await t.call(t.admin, 'GET', path)).body.score, fresh.body.score);
  assert.equal((await t.call(operator.key, 'GET', path)).status, 200);

  // Other operators cannot see it (no existence oracle); unknown agents are 404.
  const other = await createOperator(t, { legalName: 'Other Ops Ltd' });
  assert.equal((await t.call(other.key, 'GET', path)).status, 404);
  assert.equal((await t.call(business.key, 'GET', '/v1/agents/agt_01J8ZQ4Y5N3V6K2M7P9R0S1T2V/trust-score')).status, 404);
  assert.equal((await t.call(business.key, 'GET', `${path}?x=1`)).status, 400);

  // Age accrues from the clock.
  t.advance(31 * 86400);
  const aged = (await t.call(business.key, 'GET', path)).body;
  assert.equal(aged.score, 35 + 15 + 25 + 20); // grant from world() expired after 1 day
  assert.equal(aged.factors.find((f) => f.code === 'scope_breadth').inputs.activeGrants, 0);

  // Broad scope + a revoked grant from another business both lower the score; only counts leak.
  const biz2 = await createBusiness(t, 'Initech');
  await createGrant(t, biz2, agent.agent.id, { actions: ['orders:*'], constraints: {} });
  const g = await createGrant(t, business, agent.agent.id);
  assert.equal((await t.call(business.key, 'POST', `/v1/grants/${g.id}/revoke`, { reason: 'abuse' })).status, 200);
  const after = (await t.call(business.key, 'GET', path)).body;
  const hist = after.factors.find((f) => f.code === 'revocation_history');
  const scope = after.factors.find((f) => f.code === 'scope_breadth');
  assert.equal(hist.inputs.revokedGrants, 1);
  assert.equal(hist.points, 17);
  assert.equal(scope.points, 20 - 4 - 3);
  assert.ok(!JSON.stringify(after).includes(biz2.biz.id), 'no other tenant ids');
  assert.ok(!JSON.stringify(after).includes(g.id));

  // Sibling agent revocation counts against the operator's other agents.
  const sibling = await registerAgent(t, operator, 'Sibling Bot');
  await t.call(operator.key, 'POST', `/v1/agents/${sibling.agent.id}/revoke`, { reason: 'key leaked' });
  const sib = (await t.call(business.key, 'GET', path)).body;
  assert.equal(sib.factors.find((f) => f.code === 'revocation_history').inputs.siblingRevokedOrSuspended, 1);

  // Revoking the agent gates it immediately (no caching).
  await t.call(operator.key, 'POST', `/v1/agents/${agent.agent.id}/revoke`, { reason: 'retired' });
  const revoked = (await t.call(business.key, 'GET', path)).body;
  assert.deepEqual([revoked.score, revoked.level], [0, 'untrusted']);
  assert.match(revoked.gates[0], /revoked/);
});
