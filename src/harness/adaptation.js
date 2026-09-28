// Harness adaptation proposals (docs/contracts/harness.md §2, §6). A proposal is an RFC 6902
// JSON Patch over the ADAPTIVE policy only. It is data, never trusted: every proposal (template
// or LLM) goes through the same checks — allowed paths, patch application, validatePolicy(),
// the §2 "may not" rules — before investigations#confirm can persist it with a human approval.
// Nothing here can reach src/harness/invariants.js state: the invariants are frozen code and a
// policy document containing an invariant-touching key is rejected by validatePolicy().
import { holds } from './invariants.js';
import { CORE_STAGES, validatePolicy } from './policy.js';

export const SIGNING_KEY_HISTORY_STEP = 'signing_key_history_check';
export const TAKEOVER_TEMPLATE = Object.freeze({ step: SIGNING_KEY_HISTORY_STEP, k: 5 });
export const LLM_MODES = Object.freeze(['fixture', 'live']);

// harness.md §2 "May": paths a patch may touch. `/memoryRetrieval/filter` and `/sanctionsFuzzy`
// are deliberately absent; so is the document root.
const ALLOWED_PATH_RE = [
  /^\/steps(\/(\d+|-))?$/,
  /^\/memoryRetrieval\/(k|numCandidates|minScorePpm)$/,
  /^\/contextAssembly\/(maxMemories|includeSignalStats|includeSanctionsEvidence)$/,
  /^\/evidenceRequests\/(\d+|-)$/,
  /^\/escalation\/(\d+|-)$/,
];
const OPS = ['add', 'remove', 'replace'];
const MAX_OPS = 20;

export class AdaptationError extends Error {
  constructor(message, code = 'ADAPTATION_INVALID', details = []) {
    super(message);
    this.name = 'AdaptationError';
    this.code = code;
    this.details = details;
  }
}

const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);

function parsePointer(path) {
  if (typeof path !== 'string' || !path.startsWith('/')) throw new AdaptationError(`invalid JSON pointer ${JSON.stringify(path)}`);
  const tokens = path
    .slice(1)
    .split('/')
    .map((t) => t.replace(/~1/g, '/').replace(/~0/g, '~'));
  if (tokens.some((t) => t === '__proto__' || t === 'constructor' || t === 'prototype')) {
    throw new AdaptationError(`forbidden token in JSON pointer ${JSON.stringify(path)}`);
  }
  return tokens;
}

/** Structural + path checks of a patch. Returns [{ path, message }]. */
export function checkPatchShape(diff) {
  const errors = [];
  if (!Array.isArray(diff)) return [{ path: '/diff', message: 'must be an array of JSON Patch operations' }];
  if (diff.length === 0) errors.push({ path: '/diff', message: 'must not be empty' });
  if (diff.length > MAX_OPS) errors.push({ path: '/diff', message: `must have at most ${MAX_OPS} operations` });
  diff.forEach((op, i) => {
    if (!isObj(op)) return errors.push({ path: `/diff/${i}`, message: 'must be an object' });
    const extra = Object.keys(op).filter((k) => !['op', 'path', 'value'].includes(k));
    if (extra.length) errors.push({ path: `/diff/${i}`, message: `unexpected keys ${extra.join(', ')}` });
    if (!OPS.includes(op.op)) errors.push({ path: `/diff/${i}/op`, message: `must be one of ${OPS.join(', ')}` });
    if (typeof op.path !== 'string' || !ALLOWED_PATH_RE.some((re) => re.test(op.path))) {
      errors.push({ path: `/diff/${i}/path`, message: 'is outside the adaptive policy paths an adaptation may change' });
    }
    if (op.op !== 'remove' && !Object.hasOwn(op, 'value')) errors.push({ path: `/diff/${i}/value`, message: 'is required' });
  });
  return errors;
}

/** Apply a JSON Patch (add/remove/replace) to a deep copy of `doc`. Throws AdaptationError. */
export function applyPatch(doc, diff) {
  const out = structuredClone(doc);
  for (const op of diff) {
    const tokens = parsePointer(op.path);
    const last = tokens.pop();
    let parent = out;
    for (const t of tokens) {
      if ((!isObj(parent) && !Array.isArray(parent)) || !Object.hasOwn(parent, t)) throw new AdaptationError(`path ${op.path} does not exist`);
      parent = parent[t];
    }
    const value = op.op === 'remove' ? undefined : structuredClone(op.value);
    if (Array.isArray(parent)) {
      const idx = last === '-' ? parent.length : /^\d+$/.test(last) ? Number(last) : NaN;
      if (!Number.isInteger(idx)) throw new AdaptationError(`bad array index in ${op.path}`);
      if (op.op === 'add') {
        if (idx > parent.length) throw new AdaptationError(`index out of range in ${op.path}`);
        parent.splice(idx, 0, value);
      } else {
        if (idx >= parent.length) throw new AdaptationError(`index out of range in ${op.path}`);
        if (op.op === 'remove') parent.splice(idx, 1);
        else parent[idx] = value;
      }
    } else if (isObj(parent)) {
      if (op.op !== 'add' && !Object.hasOwn(parent, last)) throw new AdaptationError(`path ${op.path} does not exist`);
      if (op.op === 'remove') delete parent[last];
      else parent[last] = value;
    } else {
      throw new AdaptationError(`path ${op.path} does not exist`);
    }
  }
  return out;
}

/** harness.md §2 "may not" rules that the schema alone cannot express (old vs new). */
export function checkAdaptationRules(oldPolicy, newPolicy) {
  const errors = [];
  const core = (p) => (p.steps ?? []).filter((s) => CORE_STAGES.includes(s));
  if (JSON.stringify(core(newPolicy)) !== JSON.stringify(core(oldPolicy))) {
    errors.push({ path: '/steps', message: 'core stages may not be removed or reordered' });
  }
  for (const s of oldPolicy.steps ?? []) {
    if (!(newPolicy.steps ?? []).includes(s)) errors.push({ path: '/steps', message: `step ${s} may not be removed` });
  }
  if ((newPolicy.memoryRetrieval?.minScorePpm ?? 0) < (oldPolicy.memoryRetrieval?.minScorePpm ?? 0)) {
    errors.push({ path: '/memoryRetrieval/minScorePpm', message: "may not be lowered below the parent version's value" });
  }
  if (JSON.stringify(newPolicy.memoryRetrieval?.filter) !== JSON.stringify({ status: 'VERIFIED' })) {
    errors.push({ path: '/memoryRetrieval/filter', message: "must remain { status: 'VERIFIED' }" });
  }
  const newRuleIds = new Set((newPolicy.escalation ?? []).map((r) => r.id));
  for (const r of oldPolicy.escalation ?? []) {
    if (!newRuleIds.has(r.id)) errors.push({ path: '/escalation', message: `escalation rule ${r.id} may not be removed` });
  }
  if (JSON.stringify(newPolicy.sanctionsFuzzy ?? null) !== JSON.stringify(oldPolicy.sanctionsFuzzy ?? null)) {
    errors.push({ path: '/sanctionsFuzzy', message: 'may not be changed by an adaptation' });
  }
  return errors;
}

/**
 * Validate a proposal against the active policy. Returns `{ ok, newPolicy, errors }`; never throws
 * for a bad proposal (a rejected proposal is recorded, not an exception).
 */
export function evaluateProposal(oldPolicy, diff) {
  const shape = checkPatchShape(diff);
  if (shape.length) return { ok: false, newPolicy: null, errors: shape };
  let newPolicy;
  try {
    newPolicy = applyPatch(oldPolicy, diff);
  } catch (err) {
    return { ok: false, newPolicy: null, errors: [{ path: '/diff', message: err.message }] };
  }
  const errors = [...validatePolicy(newPolicy)];
  if (!errors.length) errors.push(...checkAdaptationRules(oldPolicy, newPolicy));
  return errors.length ? { ok: false, newPolicy: null, errors } : { ok: true, newPolicy, errors: [] };
}

/** Deterministic template (LLM_MODE=fixture). harness.md §6.3. */
export function templateDiff(outcome, policy) {
  if (outcome !== 'CONFIRMED_ACCOUNT_TAKEOVER') return [];
  const diff = [];
  const steps = policy.steps ?? [];
  if (!steps.includes(TAKEOVER_TEMPLATE.step)) {
    // Adaptive steps live between `memory` and `policy` (harness.md §3.1): insert right after memory.
    diff.push({ op: 'add', path: `/steps/${steps.indexOf('memory') + 1}`, value: TAKEOVER_TEMPLATE.step });
  }
  if (policy.memoryRetrieval?.k !== TAKEOVER_TEMPLATE.k) {
    diff.push({ op: 'replace', path: '/memoryRetrieval/k', value: TAKEOVER_TEMPLATE.k });
  }
  return diff;
}

/** The only information an LLM proposer sees: the adaptive policy and the case evidence. */
export function llmPrompt({ policy, investigation, memory }) {
  return JSON.stringify({
    task:
      'Propose an RFC 6902 JSON Patch over the adaptive investigation policy that would help detect cases like this one. ' +
      'Respond with JSON only: {"diff":[...]}. Allowed ops: add, remove, replace. Allowed paths: /steps, /memoryRetrieval/k, ' +
      '/memoryRetrieval/numCandidates, /memoryRetrieval/minScorePpm, /contextAssembly/*, /evidenceRequests/*, /escalation/*. ' +
      `Registered adaptive steps: ${SIGNING_KEY_HISTORY_STEP}. Escalations may only produce REVIEW.`,
    policy,
    evidence: {
      investigationId: investigation.id,
      outcome: memory.outcome,
      signals: investigation.signals ?? [],
      riskDecision: investigation.riskDecision,
      memoryId: memory.id,
    },
  });
}

function parseLlmDiff(text) {
  let parsed;
  try {
    parsed = JSON.parse(typeof text === 'string' ? text : '');
  } catch {
    throw new AdaptationError('LLM output is not JSON', 'LLM_OUTPUT_INVALID');
  }
  const diff = Array.isArray(parsed) ? parsed : parsed?.diff;
  if (!Array.isArray(diff)) throw new AdaptationError('LLM output has no diff array', 'LLM_OUTPUT_INVALID');
  return diff;
}

/**
 * Propose a harness adaptation from a human-confirmed outcome.
 * `memory` must be the promoted (VERIFIED) case memory: unverified memory never drives adaptation.
 * Options: `policy` (active adaptive policy, required), `mode` ('fixture' | 'live', default fixture),
 * `llm` ({ model, complete(prompt) => Promise<string> }, live mode only; injected by the caller —
 * there is no built-in network client).
 * Returns `null` (nothing to propose) or `{ proposer: { kind, llmMode, model }, diff, error? }`.
 * An LLM failure returns a proposal with `error` so the caller records `adaptation.rejected`.
 */
export async function proposeFromOutcome(investigation, memory, { policy, mode = 'fixture', llm = null } = {}) {
  if (!isObj(policy)) throw new AdaptationError('active policy is required', 'ADAPTATION_NO_POLICY');
  if (!LLM_MODES.includes(mode)) throw new AdaptationError(`LLM mode must be one of ${LLM_MODES.join('|')}`, 'CONFIG');
  if (!isObj(investigation) || !isObj(memory)) return null;
  if (!holds('INV_UNVERIFIED_MEMORY_NOT_PRECEDENT', { memory })) return null;

  if (mode === 'fixture') {
    const diff = templateDiff(memory.outcome, policy);
    return diff.length ? { proposer: { kind: 'template', llmMode: 'fixture', model: null }, diff } : null;
  }

  const proposer = { kind: 'llm', llmMode: 'live', model: llm?.model ?? null };
  if (!llm || typeof llm.complete !== 'function') {
    return { proposer, diff: [], error: { code: 'LLM_UNAVAILABLE', message: 'LLM_MODE=live but no LLM client is configured' } };
  }
  try {
    const diff = parseLlmDiff(await llm.complete(llmPrompt({ policy, investigation, memory })));
    return diff.length ? { proposer, diff } : null;
  } catch (err) {
    return { proposer, diff: [], error: { code: err?.code ?? 'LLM_FAILED', message: err instanceof AdaptationError ? err.message : 'LLM call failed' } };
  }
}
