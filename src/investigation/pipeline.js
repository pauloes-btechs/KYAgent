// Investigation pipeline — T07 skeleton (investigation-pipeline.md; T14 adds sanctions, policy
// and adaptive steps). Stage order here: identity -> delegation -> signals -> memory -> decision.
//
// - identity runs in `state` mode (agent active, operator verified); DENY short-circuits every
//   later stage to `skipped` with BLOCK IDENTITY_DENIED.
// - delegation failures add BLOCK reasons but do not short-circuit (evidence completeness).
// - memory is Atlas `$vectorSearch` (src/memory/retrieve.js); only VERIFIED hits >= minScore are
//   kept. A kept CONFIRMED_ACCOUNT_TAKEOVER precedent can only add REVIEW (precedent, never proof).
// - fail closed: any stage throwing ⇒ that stage `error`, the rest `skipped`, BLOCK INTERNAL_ERROR.
// Nothing is persisted here; the investigations service (T08) stores the returned document.
import { holds, precedentMemories } from '../harness/invariants.js';
import { retrieveMemories } from '../memory/retrieve.js';
import { computeSignals } from './signals.js';

export const SKELETON_STAGES = Object.freeze(['identity', 'delegation', 'signals', 'memory', 'decision']);

export const DEFAULT_POLICY = Object.freeze({
  memoryRetrieval: Object.freeze({ k: 3, numCandidates: 100, minScorePpm: 780_000 }),
  escalation: Object.freeze([
    Object.freeze({
      id: 'precedent_takeover',
      when: Object.freeze({ precedentOutcomeIn: Object.freeze(['CONFIRMED_ACCOUNT_TAKEOVER']) }),
      then: Object.freeze({ riskDecision: 'REVIEW', reasonCode: 'MEMORY_PRECEDENT_TAKEOVER' }),
    }),
  ]),
});

const RANK = { ALLOW: 0, REVIEW: 1, BLOCK: 2 };
const MESSAGES = {
  CLEAR: 'No invariant breached and no escalation rule fired.',
  IDENTITY_DENIED: 'Agent identity could not be established.',
  DELEGATION_DENIED: 'No active delegation covers this payment.',
  DELEGATION_MAX_EXCEEDED: 'Amount exceeds the delegation maximum.',
  WALLET_NOT_APPROVED: 'Source wallet is not the delegation-approved wallet.',
  ASSET_NOT_PERMITTED: 'Asset is not permitted by the delegation.',
  MEMORY_PRECEDENT_TAKEOVER: 'A VERIFIED account-takeover precedent matches this case.',
  INTERNAL_ERROR: 'An investigation stage failed; failing closed.',
};

const reason = (code, riskDecision, stage, extra = {}) => ({ code, riskDecision, message: MESSAGES[code] ?? code, stage, ...extra });
const idOf = (d) => d?.id ?? d?._id ?? null;

function identityStage({ agent, operator, agentId }) {
  let reasonCode = 'ALLOWED';
  if (!agent) reasonCode = 'AGENT_NOT_FOUND';
  else if (agent.status === 'revoked') reasonCode = 'AGENT_REVOKED';
  else if (agent.status !== 'active') reasonCode = 'AGENT_SUSPENDED';
  else if (!operator) reasonCode = 'OPERATOR_NOT_VERIFIED';
  else if (operator.status === 'suspended') reasonCode = 'OPERATOR_SUSPENDED';
  else if (operator.status !== 'verified') reasonCode = 'OPERATOR_NOT_VERIFIED';
  const decision = reasonCode === 'ALLOWED' ? 'ALLOW' : 'DENY';
  return {
    status: decision === 'ALLOW' ? 'passed' : 'failed',
    result: {
      mode: 'state',
      decision,
      reasonCode,
      agentId,
      principalId: agent?.operatorId ?? null,
      keyThumbprint: agent?.keyThumbprint ?? null,
    },
    evidence: [
      {
        id: `identity:${agentId}`,
        kind: 'identity',
        source: 'agents',
        ref: agent ? agentId : null,
        summary: `agent ${agent?.status ?? 'missing'}, operator ${operator?.status ?? 'missing'}`,
        data: { agentStatus: agent?.status ?? null, operatorStatus: operator?.status ?? null, signature: 'not_applicable', nonce: 'not_applicable' },
      },
    ],
    reasons: decision === 'ALLOW' ? [] : [reason('IDENTITY_DENIED', 'BLOCK', 'identity', { identityReasonCode: reasonCode })],
  };
}

function delegationStage({ grant, agentId, tx, now }) {
  const wallet = tx.wallet;
  const asset = tx.asset ?? tx.currency ?? null;
  const active = Boolean(grant) && grant.agentId === agentId && grant.status === 'active' && new Date(grant.expiresAt) > now;
  const withinMax = active && holds('INV_DELEGATION_MAX', { constraints: grant.constraints, resource: tx.resource, context: { amount: tx.amount, currency: asset } });
  const walletApproved = active && (grant.approvedWallet == null || grant.approvedWallet === wallet);
  const assetPermitted = active && (grant.asset == null || grant.asset === asset);
  const reasons = [];
  let reasonCode = 'ALLOWED';
  if (!active) {
    reasonCode = !grant ? 'NO_GRANT' : grant.status === 'revoked' ? 'GRANT_REVOKED' : grant.status === 'active' && grant.agentId === agentId ? 'GRANT_EXPIRED' : 'NO_GRANT';
    reasons.push(reason('DELEGATION_DENIED', 'BLOCK', 'delegation', { identityReasonCode: reasonCode }));
  } else {
    if (!withinMax) {
      reasonCode = 'CONSTRAINT_VIOLATION';
      reasons.push(reason('DELEGATION_MAX_EXCEEDED', 'BLOCK', 'delegation', { invariantId: 'INV_DELEGATION_MAX', identityReasonCode: reasonCode }));
    }
    if (!walletApproved) reasons.push(reason('WALLET_NOT_APPROVED', 'BLOCK', 'delegation'));
    if (!assetPermitted) reasons.push(reason('ASSET_NOT_PERMITTED', 'BLOCK', 'delegation'));
  }
  return {
    status: reasons.length ? 'failed' : 'passed',
    result: {
      delegationId: idOf(grant),
      delegationVersion: grant?.version ?? null,
      asset: grant?.asset ?? null,
      approvedWallet: grant?.approvedWallet ?? null,
      maxTxAmount: grant?.maxTxAmount ?? grant?.constraints?.maxAmount ?? null,
      dailyLimit: grant?.dailyLimit ?? null,
      amount: tx.amount,
      withinMax,
      walletApproved,
      assetPermitted,
      reasonCode,
    },
    evidence: [
      {
        id: `delegation:${idOf(grant) ?? 'none'}`,
        kind: 'delegation',
        source: 'grants',
        ref: idOf(grant),
        summary: grant ? `delegation ${grant.status}, amount ${tx.amount} within max: ${withinMax}` : 'no delegation found',
        data: { status: grant?.status ?? null, withinMax, walletApproved, assetPermitted },
      },
      { id: 'invariant:INV_DELEGATION_MAX', kind: 'invariant', source: 'harness/invariants', ref: 'INV_DELEGATION_MAX', summary: `held: ${withinMax}`, data: { held: withinMax } },
    ],
    reasons,
  };
}

function decide(reasons) {
  if (reasons.length === 0) return { riskDecision: 'ALLOW', reasons: [reason('CLEAR', 'ALLOW', 'decision')] };
  const sorted = reasons
    .map((r, i) => [r, i])
    .sort(([a, i], [b, j]) => RANK[b.riskDecision] - RANK[a.riskDecision] || i - j)
    .map(([r]) => r);
  return { riskDecision: sorted[0].riskDecision, reasons: sorted };
}

/**
 * Run the skeleton investigation for one candidate payment.
 * `tx` = { amount (minor units), asset|currency, counterparty: { address, name? }, wallet?, signingKeyThumbprint, id? }.
 * `delegationId` selects the grant (defaults to `tx.delegationId`).
 * Returns `{ agentId, trigger, stages[], signals, memory, riskDecision, decision, reasons, evidence[] }`.
 */
export async function runInvestigation({ store, agentId, tx, delegationId = tx?.delegationId, policy = DEFAULT_POLICY, trigger = 'manual', now = new Date() }) {
  const stages = [];
  const ctx = { signals: [], memory: null, halted: false };

  const run = async (name, engine, fn) => {
    const startedAt = new Date();
    const t0 = performance.now();
    const base = { name, engine, startedAt: startedAt.toISOString() };
    if (ctx.halted) {
      stages.push({ ...base, status: 'skipped', durationMs: 0, result: {}, evidence: [], reasons: [] });
      return null;
    }
    try {
      const out = await fn();
      stages.push({ ...base, status: out.status, durationMs: Math.round(performance.now() - t0), result: out.result, evidence: out.evidence, reasons: out.reasons });
      return out;
    } catch (err) {
      ctx.halted = true;
      stages.push({
        ...base,
        status: 'error',
        durationMs: Math.round(performance.now() - t0),
        result: { error: err?.name ?? 'Error', code: err?.code ?? null },
        evidence: [],
        reasons: [reason('INTERNAL_ERROR', 'BLOCK', name)],
      });
      return null;
    }
  };

  let agent = null;
  let grant = null;
  const id = await run('identity', 'code', async () => {
    agent = await store.agents.findById(agentId);
    const operator = agent ? await store.operators.findById(agent.operatorId) : null;
    return identityStage({ agent, operator, agentId });
  });
  if (id && id.result.decision === 'DENY') ctx.halted = true;

  const payment = () => ({ ...tx, wallet: tx.wallet ?? agent?.wallets?.[0]?.address ?? null });

  await run('delegation', 'find', async () => {
    grant = delegationId ? await store.grants.findById(delegationId) : null;
    return delegationStage({ grant, agentId, tx: payment(), now });
  });

  await run('signals', store.db ? 'aggregate' : 'js', async () => {
    const r = await computeSignals({ store, agent, grant, tx: payment(), now });
    ctx.signals = r.signals;
    return { status: r.signals.length ? 'flagged' : 'passed', result: { signals: r.signals, stats: r.stats }, evidence: r.evidence, reasons: [] };
  });

  await run('memory', '$vectorSearch', async () => {
    const r = await retrieveMemories({ db: store.db, signals: ctx.signals, ...policy.memoryRetrieval });
    const { evidence, ...result } = r;
    ctx.memory = result;
    const precedents = precedentMemories(result.hits);
    const reasons = [];
    for (const rule of policy.escalation ?? []) {
      const outcomes = rule.when?.precedentOutcomeIn ?? [];
      const fired = precedents.filter((h) => outcomes.includes(h.outcome));
      if (fired.length && rule.then?.riskDecision === 'REVIEW') {
        reasons.push(reason(rule.then.reasonCode, 'REVIEW', 'memory', { evidenceRefs: fired.map((h) => h.memoryId) }));
      }
    }
    return { status: result.hits.length ? 'flagged' : 'passed', result, evidence, reasons };
  });

  const collected = stages.flatMap((s) => s.reasons);
  const verdict = decide(collected);
  stages.push({
    name: 'decision',
    engine: 'code',
    status: verdict.riskDecision === 'ALLOW' ? 'passed' : verdict.riskDecision === 'BLOCK' ? 'failed' : 'flagged',
    startedAt: new Date().toISOString(),
    durationMs: 0,
    result: { decision: verdict.riskDecision === 'ALLOW' ? 'ALLOW' : 'DENY', riskDecision: verdict.riskDecision, reasons: verdict.reasons },
    evidence: [],
    reasons: [],
  });

  return {
    agentId,
    trigger,
    stages,
    signals: ctx.signals,
    memory: ctx.memory,
    riskDecision: verdict.riskDecision,
    decision: verdict.riskDecision === 'ALLOW' ? 'ALLOW' : 'DENY',
    reasons: verdict.reasons,
    evidence: stages.flatMap((s) => s.evidence),
  };
}
