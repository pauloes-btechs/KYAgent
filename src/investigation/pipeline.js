// Investigation pipeline (investigation-pipeline.md, T14 final). Stage order:
// identity -> delegation -> sanctions -> signals -> memory ->
// [adaptive steps of the active harness policy, T13] -> policy -> decision.
//
// - identity runs in `state` mode (agent active, operator verified) or `signed` mode (trigger
//   `api`, the /v1/verify steps 1–8); DENY short-circuits every later stage to `skipped` with
//   BLOCK IDENTITY_DENIED.
// - delegation failures add BLOCK reasons but do not short-circuit (evidence completeness).
// - sanctions (src/sanctions/screen.js): exact wallet `find` ⇒ INV_SANCTIONS_EXACT_BLOCK ⇒ BLOCK
//   SANCTIONS_EXACT_MATCH (deterministic, independent of `$search`); the `$search` fuzzy/alias/
//   phonetic name screen adds evidence, and REVIEW SANCTIONS_FUZZY_MATCH only above the policy's
//   `sanctionsFuzzy.minScorePpm`. An exact hit survives a fuzzy-screen error (both reasons kept).
// - memory is Atlas `$vectorSearch` (src/memory/retrieve.js); only VERIFIED hits >= minScore are
//   kept (context and evidence only; the memory stage itself never decides).
// - policy (code): the invariant summary over the stage results, the passport status, the
//   adaptive escalation rules (REVIEW only: a kept VERIFIED CONFIRMED_ACCOUNT_TAKEOVER precedent
//   is precedent, never proof) and the active harness invariantsHash check.
// - decision: all stage reasons by precedence BLOCK > REVIEW > ALLOW (decision-vocabulary.md).
// - fail closed: any stage throwing ⇒ that stage `error`, the rest `skipped`, BLOCK INTERNAL_ERROR.
// - trigger `sanctions_change` (watcher re-screen, investigation-pipeline.md §2): there is no
//   candidate amount, so INV_DELEGATION_MAX, the amount-based signals and the memory lookup keyed
//   on them are recorded `not_applicable`. Gated on the trigger only: any other trigger with a
//   missing amount still fails the invariant and the signals stage. The passport's own
//   RE_SCREENING status is the state under evaluation there and is ignored by the policy stage.
// Nothing is persisted here; the investigations service / sanctions watcher store the result.
import { ADAPTIVE_STEPS, holds, INVARIANTS_HASH, precedentMemories } from '../harness/invariants.js';
import { policyHash } from '../harness/policy.js';
import { retrieveMemories } from '../memory/retrieve.js';
import { screenSanctions } from '../sanctions/screen.js';
import { ADAPTIVE_STEP_RUNNERS } from './adaptiveSteps.js';
import { computeSignals } from './signals.js';

/** Core stages in execution order (types.ts PIPELINE_STAGES); adaptive steps run between memory and policy. */
export const PIPELINE_STAGES = Object.freeze(['identity', 'delegation', 'sanctions', 'signals', 'memory', 'policy', 'decision']);
/** @deprecated T07 name, kept for importers; the final order includes `policy`. */
export const SKELETON_STAGES = PIPELINE_STAGES;

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
  SANCTIONS_EXACT_MATCH: 'A screened wallet exactly matches a sanctioned wallet address.',
  SANCTIONS_FUZZY_MATCH: 'A screened name resembles a sanctioned entity name or alias.',
  MEMORY_PRECEDENT_TAKEOVER: 'A VERIFIED account-takeover precedent matches this case.',
  PASSPORT_SUSPENDED: 'The agent passport is suspended.',
  PASSPORT_REVOKED: 'The agent passport is revoked.',
  PASSPORT_UNDER_REVIEW: 'The agent passport is under review.',
  PASSPORT_RE_SCREENING: 'The agent passport is being re-screened.',
  HARNESS_INVARIANTS_MISMATCH: 'The active harness version was created under different invariants.',
  INTERNAL_ERROR: 'An investigation stage failed; failing closed.',
};

const reason = (code, riskDecision, stage, extra = {}) => ({ code, riskDecision, message: MESSAGES[code] ?? code, stage, ...extra });
const idOf = (d) => d?.id ?? d?._id ?? null;

// `signed` (trigger `api`): the /v1/verify steps 1–8 outcome computed by the investigations
// service `{ reasonCode, signature, nonce }`; its reasonCode is authoritative (same check order).
function identityStage({ agent, operator, agentId, signed = null }) {
  let reasonCode = 'ALLOWED';
  if (!agent) reasonCode = 'AGENT_NOT_FOUND';
  else if (agent.status === 'revoked') reasonCode = 'AGENT_REVOKED';
  else if (agent.status !== 'active') reasonCode = 'AGENT_SUSPENDED';
  else if (!operator) reasonCode = 'OPERATOR_NOT_VERIFIED';
  else if (operator.status === 'suspended') reasonCode = 'OPERATOR_SUSPENDED';
  else if (operator.status !== 'verified') reasonCode = 'OPERATOR_NOT_VERIFIED';
  if (signed) reasonCode = signed.reasonCode;
  const decision = reasonCode === 'ALLOWED' ? 'ALLOW' : 'DENY';
  return {
    status: decision === 'ALLOW' ? 'passed' : 'failed',
    result: {
      mode: signed ? 'signed' : 'state',
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
        data: {
          agentStatus: agent?.status ?? null,
          operatorStatus: operator?.status ?? null,
          signature: signed?.signature ?? 'not_applicable',
          nonce: signed?.nonce ?? 'not_applicable',
        },
      },
    ],
    reasons: decision === 'ALLOW' ? [] : [reason('IDENTITY_DENIED', 'BLOCK', 'identity', { identityReasonCode: reasonCode })],
  };
}

function delegationStage({ grant, agentId, tx, now, amountApplicable = true }) {
  const wallet = tx.wallet;
  const asset = tx.asset ?? tx.currency ?? null;
  const active = Boolean(grant) && grant.agentId === agentId && grant.status === 'active' && new Date(grant.expiresAt) > now;
  const withinMax = !amountApplicable ? 'not_applicable' : active && holds('INV_DELEGATION_MAX', { constraints: grant.constraints, resource: tx.resource, context: { amount: tx.amount, currency: asset } });
  const walletApproved = active && (grant.approvedWallet == null || grant.approvedWallet === wallet);
  const assetPermitted = active && (grant.asset == null || grant.asset === asset);
  const reasons = [];
  let reasonCode = 'ALLOWED';
  if (!active) {
    reasonCode = !grant ? 'NO_GRANT' : grant.status === 'revoked' ? 'GRANT_REVOKED' : grant.status === 'active' && grant.agentId === agentId ? 'GRANT_EXPIRED' : 'NO_GRANT';
    reasons.push(reason('DELEGATION_DENIED', 'BLOCK', 'delegation', { identityReasonCode: reasonCode }));
  } else {
    if (withinMax === false) {
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
      amount: tx.amount ?? null,
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

const PASSPORT_REASONS = Object.freeze({
  SUSPENDED: ['PASSPORT_SUSPENDED', 'BLOCK'],
  REVOKED: ['PASSPORT_REVOKED', 'BLOCK'],
  REVIEW: ['PASSPORT_UNDER_REVIEW', 'REVIEW'],
  RE_SCREENING: ['PASSPORT_RE_SCREENING', 'REVIEW'],
});

const stageResult = (stages, name) => stages.find((s) => s.name === name) ?? null;

/**
 * Policy stage (investigation-pipeline.md §4 row 6). Summarises the invariants over the earlier
 * stage results (they were enforced where they apply; this stage never relaxes them), applies the
 * passport status and the adaptive escalation rules (REVIEW only) and checks the harness hash.
 */
async function policyStage({ store, agentId, policy, trigger, harness, invariantsMatch, stages, ctx }) {
  const reasons = [];
  const evidence = [];

  const sanctions = stageResult(stages, 'sanctions');
  const delegation = stageResult(stages, 'delegation');
  const memory = stageResult(stages, 'memory');
  const ran = (s) => Boolean(s) && s.status !== 'skipped' && s.status !== 'error';
  const withinMax = delegation?.result?.withinMax;
  const invariants = [
    { id: 'INV_SANCTIONS_EXACT_BLOCK', applicable: ran(sanctions), held: ran(sanctions) ? !(sanctions.result.exactHits?.length > 0) : null },
    { id: 'INV_DELEGATION_MAX', applicable: ran(delegation) && typeof withinMax === 'boolean', held: typeof withinMax === 'boolean' ? withinMax : null },
    // No rolling 24 h spend is computed by the delegation stage yet: recorded as not evaluated.
    { id: 'INV_DAILY_LIMIT', applicable: false, held: null },
    {
      id: 'INV_UNVERIFIED_MEMORY_NOT_PRECEDENT',
      applicable: ran(memory) && !memory.result?.notApplicable,
      held: ran(memory) && !memory.result?.notApplicable ? precedentMemories(ctx.memory?.hits).length === (ctx.memory?.hits?.length ?? 0) : null,
      droppedUnverified: ctx.memory?.droppedUnverified ?? 0,
    },
  ];
  for (const i of invariants) {
    evidence.push({ id: `policy:invariant:${i.id}`, kind: 'invariant', source: 'harness/invariants', ref: i.id, summary: i.applicable ? `held: ${i.held}` : 'not applicable', data: { ...i } });
  }

  const passport = agentId ? ((await store.passports.find({ agentId }, { limit: 1 }))[0] ?? null) : null;
  const passportStatus = passport?.status ?? null;
  const pr = passportStatus && Object.hasOwn(PASSPORT_REASONS, passportStatus) ? PASSPORT_REASONS[passportStatus] : null;
  // RE_SCREENING is the state under evaluation for a sanctions_change re-screen (§4).
  if (pr && !(passportStatus === 'RE_SCREENING' && trigger === 'sanctions_change')) {
    reasons.push(reason(pr[0], pr[1], 'policy', { evidenceRefs: [passport.id] }));
  }
  evidence.push({
    id: `passport:${passport?.id ?? 'none'}`,
    kind: 'passport',
    source: 'passports',
    ref: passport?.id ?? null,
    summary: passport ? `passport ${passportStatus}` : 'no passport',
    data: { status: passportStatus },
  });

  const precedents = precedentMemories(ctx.memory?.hits);
  const escalationsFired = [];
  for (const rule of policy.escalation ?? []) {
    const outcomes = rule.when?.precedentOutcomeIn ?? [];
    const fired = precedents.filter((h) => outcomes.includes(h.outcome));
    // Adaptive rules can only add REVIEW (decision-vocabulary.md §2).
    if (fired.length && rule.then?.riskDecision === 'REVIEW') {
      escalationsFired.push(rule.id);
      reasons.push(reason(rule.then.reasonCode, 'REVIEW', 'policy', { evidenceRefs: fired.map((h) => h.memoryId) }));
      evidence.push({ id: `policy:escalation:${rule.id}`, kind: 'policy', source: 'harness_versions', ref: rule.id, summary: `escalation ${rule.id} fired on ${fired.map((h) => h.memoryId).join(', ')}`, data: { ruleId: rule.id, memoryIds: fired.map((h) => h.memoryId) } });
    }
  }

  if (!invariantsMatch) reasons.push(reason('HARNESS_INVARIANTS_MISMATCH', 'BLOCK', 'policy'));

  const blocked = reasons.some((r) => r.riskDecision === 'BLOCK');
  return {
    status: blocked ? 'failed' : reasons.length ? 'flagged' : 'passed',
    result: {
      harnessVersion: harness?.version ?? null,
      invariantsHash: INVARIANTS_HASH,
      harnessInvariantsHash: harness?.invariantsHash ?? null,
      policyHash: harness?.policyHash ?? policyHash(policy),
      invariants,
      passportStatus,
      escalationsFired,
    },
    evidence,
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
 * Run the investigation for one candidate payment.
 * `tx` = { amount (minor units), asset|currency, counterparty: { address, name? }, counterparties?: [{ address, name? }],
 *          wallet?, signingKeyThumbprint, id? }.
 * `delegationId` selects the grant (defaults to `tx.delegationId`). `harness` = the loaded active
 * harness `{ version, policyHash, invariantsHash }` (recorded by the policy stage).
 * Returns `{ agentId, trigger, stages[], signals, memory, sanctions, riskDecision, decision, reasons, evidence[] }`.
 */
export async function runInvestigation({
  store,
  agentId,
  tx,
  delegationId = tx?.delegationId,
  policy = DEFAULT_POLICY,
  trigger = 'manual',
  now = new Date(),
  signedIdentity = null,
  invariantsMatch = true,
  harness = null,
}) {
  const stages = [];
  const ctx = { signals: [], memory: null, sanctions: null, halted: false };
  // Keyed on the trigger, never on a missing amount (see the header comment).
  const rescreen = trigger === 'sanctions_change';
  const notApplicable = (why) => ({ status: 'skipped', result: { notApplicable: true, reason: why }, evidence: [], reasons: [] });

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
      // A stage may attach what it had already established (e.g. an exact sanctions hit).
      const partial = err?.stagePartial ?? null;
      stages.push({
        ...base,
        status: 'error',
        durationMs: Math.round(performance.now() - t0),
        result: { ...(partial?.result ?? {}), error: err?.name ?? 'Error', code: err?.code ?? null },
        evidence: partial?.evidence ?? [],
        reasons: [...(partial?.reasons ?? []), reason('INTERNAL_ERROR', 'BLOCK', name)],
      });
      return null;
    }
  };

  let agent = null;
  let grant = null;
  const id = await run('identity', 'code', async () => {
    agent = await store.agents.findById(agentId);
    const operator = agent ? await store.operators.findById(agent.operatorId) : null;
    return identityStage({ agent, operator, agentId, signed: signedIdentity });
  });
  if (id && id.result.decision === 'DENY') ctx.halted = true;

  const payment = () => ({ ...tx, wallet: tx.wallet ?? agent?.wallets?.[0]?.address ?? null });

  await run('delegation', 'find', async () => {
    grant = delegationId ? await store.grants.findById(delegationId) : null;
    return delegationStage({ grant, agentId, tx: payment(), now, amountApplicable: !rescreen });
  });

  await run('sanctions', store.db ? '$search' : 'find', async () => {
    const p = payment();
    const screened = [
      { role: 'wallet', address: p.wallet, name: null },
      { role: 'counterparty', address: p.counterparty?.address ?? null, name: p.counterparty?.name ?? null },
      // sanctions_change: every distinct recent counterparty of the agent (investigation-pipeline.md §2).
      ...(p.counterparties ?? []).map((c) => ({ role: 'counterparty', address: c?.address ?? null, name: c?.name ?? null })),
    ];
    const exactReasons = (hits) =>
      hits.length
        ? [reason('SANCTIONS_EXACT_MATCH', 'BLOCK', 'sanctions', { invariantId: 'INV_SANCTIONS_EXACT_BLOCK', evidenceRefs: [...new Set(hits.map((h) => h.sanctionsId))] })]
        : [];
    let r;
    try {
      r = await screenSanctions({ store, screened, fuzzy: policy.sanctionsFuzzy });
    } catch (err) {
      if (err?.stagePartial) err.stagePartial.reasons = exactReasons(err.stagePartial.result.exactHits);
      throw err;
    }
    const reasons = exactReasons(r.result.exactHits);
    if (r.fuzzyFlagged.length) {
      reasons.push(reason('SANCTIONS_FUZZY_MATCH', 'REVIEW', 'sanctions', { evidenceRefs: [...new Set(r.fuzzyFlagged.map((h) => h.sanctionsId))] }));
    }
    ctx.sanctions = r.result;
    return { status: r.exactHit ? 'failed' : reasons.length ? 'flagged' : 'passed', result: r.result, evidence: r.evidence, reasons };
  });

  await run('signals', store.db ? 'aggregate' : 'js', async () => {
    if (rescreen) return notApplicable('sanctions_change re-screen has no candidate payment');
    const r = await computeSignals({ store, agent, grant, tx: payment(), now });
    ctx.signals = r.signals;
    return { status: r.signals.length ? 'flagged' : 'passed', result: { signals: r.signals, stats: r.stats }, evidence: r.evidence, reasons: [] };
  });

  await run('memory', '$vectorSearch', async () => {
    if (rescreen) return notApplicable('sanctions_change re-screen has no behavioral signals to match');
    const { k, numCandidates, minScorePpm } = policy.memoryRetrieval;
    const r = await retrieveMemories({ db: store.db, signals: ctx.signals, k, numCandidates, minScorePpm });
    const { evidence, ...result } = r;
    ctx.memory = result;
    return { status: result.hits.length ? 'flagged' : 'passed', result, evidence, reasons: [] };
  });

  // Adaptive steps (harness.md §3.3): only registered steps, in policy order, between memory and
  // policy. They add evidence only (runners return no reasons).
  for (const step of (policy.steps ?? []).filter((x) => ADAPTIVE_STEPS.includes(x))) {
    const runner = Object.hasOwn(ADAPTIVE_STEP_RUNNERS, step) ? ADAPTIVE_STEP_RUNNERS[step] : null;
    await run(step, runner?.engine ?? 'code', async () => {
      if (!runner) throw new Error(`adaptive step ${step} has no runner`);
      return runner.run({ store, agent, agentId, now, signals: ctx.signals, memory: ctx.memory });
    });
  }

  let policyRan = false;
  await run('policy', 'code', async () => {
    policyRan = true;
    return policyStage({ store, agentId, policy, trigger, harness, invariantsMatch, stages, ctx });
  });

  const collected = stages.flatMap((s) => s.reasons);
  // The policy stage owns the harness check; if it could not run (short-circuit or an earlier
  // error) the mismatch is still reported.
  if (!policyRan && !invariantsMatch) collected.push(reason('HARNESS_INVARIANTS_MISMATCH', 'BLOCK', 'decision'));
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
    sanctions: ctx.sanctions,
    riskDecision: verdict.riskDecision,
    decision: verdict.riskDecision === 'ALLOW' ? 'ALLOW' : 'DENY',
    reasons: verdict.reasons,
    evidence: stages.flatMap((s) => s.evidence),
  };
}
