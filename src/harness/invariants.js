// Immutable invariants (docs/contracts/harness.md §1). Binding boundary:
// - No configuration, environment variable or document decides whether an invariant applies.
// - Changing anything here is a reviewed code change + test change + harness.md change;
//   never a DB write, an API call, an adaptation or an LLM output.
// Every `check(input)` is pure and returns true when the invariant HOLDS; any malformed
// input fails closed (returns false).
import { readFileSync } from 'node:fs';
import { canonicalJson } from '../crypto/canonical.js';
import { sha256hex } from '../crypto/ed25519.js';
import { constraintsSatisfied } from '../services/authz.js';

const lower = (s) => (typeof s === 'string' ? s.toLowerCase() : null);
const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);

function sanctionsExactClear({ addresses, sanctionedAddresses } = {}) {
  if (!Array.isArray(addresses) || !sanctionedAddresses || typeof sanctionedAddresses[Symbol.iterator] !== 'function') return false;
  const listed = new Set();
  for (const a of sanctionedAddresses) {
    const l = lower(a);
    if (l) listed.add(l);
  }
  return !addresses.some((a) => a != null && (typeof a !== 'string' || listed.has(a.toLowerCase())));
}

function delegationWithinMax({ constraints, resource, context } = {}) {
  return constraintsSatisfied(constraints, resource, context);
}

function dailyLimitHolds({ dailyLimit, spent24h, amount } = {}) {
  if (dailyLimit === undefined || dailyLimit === null) return true; // no daily limit on this delegation
  if (![dailyLimit, spent24h, amount].every((n) => Number.isSafeInteger(n) && n >= 0)) return false;
  return spent24h + amount <= dailyLimit;
}

// `approver.keyLineage` = [approver apiKeyId, parent, …, root]; `subject.conflictKeyIds` = the
// lineage of the initiator's key plus the lineages of every key owned by a case party (resolved by
// the caller from api_keys, see services/apiKeys.js keyLineage). Missing lineage fails closed.
function notSelfApproval({ approver, subject } = {}) {
  if (!isObj(approver) || !isObj(subject)) return false;
  if (approver.role !== 'admin' || typeof approver.apiKeyId !== 'string' || !approver.apiKeyId) return false;
  const lineage = approver.keyLineage;
  const conflicts = subject.conflictKeyIds;
  if (!Array.isArray(lineage) || lineage[0] !== approver.apiKeyId || !Array.isArray(conflicts)) return false;
  const initiatorKey = subject.initiatedBy?.apiKeyId ?? null;
  if (initiatorKey !== null && (approver.apiKeyId === initiatorKey || !conflicts.includes(initiatorKey))) return false;
  if (lineage.some((k) => typeof k !== 'string' || conflicts.includes(k))) return false;
  const parties = [subject.agentId, subject.principalId, subject.businessId].filter((p) => p != null);
  return approver.ownerId == null || !parties.includes(approver.ownerId);
}

function passportActorAllowed({ actor } = {}) {
  return isObj(actor) && (actor.role === 'system' || actor.role === 'admin');
}

function memoryIsPrecedent({ memory } = {}) {
  return isObj(memory) && memory.status === 'VERIFIED';
}

const inv = (def) => Object.freeze(def);

export const INVARIANTS = Object.freeze([
  inv({
    id: 'INV_SANCTIONS_EXACT_BLOCK',
    version: 1,
    rule: 'agent source wallet or counterparty equal (lowercased) to any sanctions.wallets.address is blocked',
    reasonCode: 'SANCTIONS_EXACT_MATCH',
    enforcedAt: 'sanctions',
    check: sanctionsExactClear,
  }),
  inv({
    id: 'INV_DELEGATION_MAX',
    version: 1,
    rule: 'amount <= delegation.maxTxAmount (constraints.maxAmount) via authz.constraintsSatisfied',
    reasonCode: 'DELEGATION_MAX_EXCEEDED',
    enforcedAt: 'delegation',
    check: delegationWithinMax,
  }),
  inv({
    id: 'INV_DAILY_LIMIT',
    version: 1,
    rule: 'spent24h + amount <= delegation.dailyLimit (rolling 24 h, settled transactions)',
    reasonCode: 'DAILY_LIMIT_EXCEEDED',
    enforcedAt: 'delegation',
    check: dailyLimitHolds,
  }),
  inv({
    id: 'INV_NO_SELF_APPROVAL',
    version: 2,
    rule: "confirmer is an admin whose ownerId is not the agent, principal or business of the case and whose API-key lineage (the key and every minting ancestor) shares no key with the initiator's key lineage or with the lineage of any key owned by a case party",
    reasonCode: 'FORBIDDEN',
    enforcedAt: 'confirm',
    check: notSelfApproval,
  }),
  inv({
    id: 'INV_NO_SELF_PASSPORT_MODIFICATION',
    version: 1,
    rule: 'only the system actor or an admin may transition a passport',
    reasonCode: 'FORBIDDEN',
    enforcedAt: 'passports.transition',
    check: passportActorAllowed,
  }),
  inv({
    id: 'INV_UNVERIFIED_MEMORY_NOT_PRECEDENT',
    version: 1,
    rule: "only memories with status == 'VERIFIED' may enter context or fire an escalation",
    reasonCode: 'MEMORY_NOT_VERIFIED',
    enforcedAt: 'memory+policy',
    check: memoryIsPrecedent,
  }),
]);

const byId = Object.freeze(Object.fromEntries(INVARIANTS.map((i) => [i.id, i])));

/** Look up a frozen invariant by id; unknown ids throw (no silent pass). */
export function invariant(id) {
  if (!Object.hasOwn(byId, id)) throw new Error(`unknown invariant ${id}`);
  return byId[id];
}

/** True when the invariant holds for `input`. Exceptions fail closed. */
export function holds(id, input) {
  const i = invariant(id);
  try {
    return i.check(input) === true;
  } catch {
    return false;
  }
}

/** Post-filter for memory hits (the second enforcement of INV_UNVERIFIED_MEMORY_NOT_PRECEDENT). */
export function precedentMemories(hits) {
  return Array.isArray(hits) ? hits.filter((memory) => holds('INV_UNVERIFIED_MEMORY_NOT_PRECEDENT', { memory })) : [];
}

// harness.md §1 INVARIANTS_HASH: canonical JSON of the invariant metadata.
export const INVARIANTS_HASH = sha256hex(
  Buffer.from(
    canonicalJson(
      INVARIANTS.map((i) => ({ id: i.id, version: i.version, rule: i.rule, reasonCode: i.reasonCode, enforcedAt: i.enforcedAt })),
    ),
    'utf8',
  ),
);

// sha256 of this module's source: any edit to the enforcement code (not just metadata) is detectable.
export const INVARIANTS_SOURCE_SHA256 = sha256hex(readFileSync(new URL(import.meta.url)));

// ------------------------------------------------------------ adaptive policy boundary
// validatePolicy() implements the harness.md §3.1 schema plus its code-level checks.
// A policy document can never reference invariants: every object is additionalProperties:false,
// and FORBIDDEN_POLICY_KEYS are rejected at any depth.

export const FORBIDDEN_POLICY_KEYS = Object.freeze(['invariants', 'skipInvariants', 'overrides', 'allow', 'block']);
export const CORE_STAGES = Object.freeze(['identity', 'delegation', 'sanctions', 'signals', 'memory', 'policy']);
export const ADAPTIVE_STEPS = Object.freeze(['signing_key_history_check']);
const SIGNALS = ['NEW_WALLET', 'NEW_COUNTERPARTY', 'SIGNING_KEY_CHANGED', 'AMOUNT_ANOMALY', 'VELOCITY', 'NEAR_CEILING'];
const OUTCOMES = ['CONFIRMED_ACCOUNT_TAKEOVER', 'SANCTIONS_MATCH', 'FALSE_POSITIVE', 'CLEAN'];
const ESCALATION_REASONS = ['MEMORY_PRECEDENT_TAKEOVER', 'BEHAVIOR_ESCALATION', 'SANCTIONS_FUZZY_MATCH'];
const SLUG_RE = /^[a-z0-9_]{1,64}$/;

const typeOf = (v) => (v === null ? 'null' : Array.isArray(v) ? 'array' : typeof v);
const INT = (min, max) => ({ t: 'integer', min, max });
const ENUM = (values) => ({ t: 'enum', values });
const ARR = (items, o = {}) => ({ t: 'array', items, ...o });
const OBJ = (props, required = [], o = {}) => ({ t: 'object', props, required, ...o });
const signalArr = ARR(ENUM(SIGNALS), { min: 1, unique: true });

const POLICY_SCHEMA = OBJ(
  {
    steps: ARR(ENUM([...CORE_STAGES, ...ADAPTIVE_STEPS]), { min: 6, max: 12, unique: true }),
    memoryRetrieval: OBJ(
      {
        k: INT(1, 10),
        numCandidates: INT(10, 200),
        minScorePpm: INT(1, 1000000),
        filter: OBJ({ status: { t: 'const', value: 'VERIFIED' } }, ['status']),
      },
      ['k', 'numCandidates', 'minScorePpm', 'filter'],
    ),
    sanctionsFuzzy: OBJ({ minScorePpm: INT(1, Number.MAX_SAFE_INTEGER), limit: INT(1, 10) }, ['minScorePpm', 'limit']),
    contextAssembly: OBJ(
      { maxMemories: INT(0, 10), includeSignalStats: { t: 'boolean' }, includeSanctionsEvidence: { t: 'boolean' } },
      ['maxMemories', 'includeSignalStats', 'includeSanctionsEvidence'],
    ),
    evidenceRequests: ARR(
      OBJ({ id: { t: 'string', re: SLUG_RE }, stage: { t: 'string', re: SLUG_RE }, description: { t: 'string', maxLen: 300 } }, [
        'id',
        'stage',
        'description',
      ]),
      { max: 10 },
    ),
    escalation: ARR(
      OBJ(
        {
          id: { t: 'string', re: SLUG_RE },
          when: OBJ(
            {
              precedentOutcomeIn: ARR(ENUM(OUTCOMES), { min: 1, unique: true }),
              signalsAll: signalArr,
              signalsAnyMin: OBJ({ of: signalArr, min: INT(1, Number.MAX_SAFE_INTEGER) }, ['of', 'min']),
              sanctionsFuzzyHit: { t: 'const', value: true },
            },
            [],
            { minProps: 1 },
          ),
          then: OBJ({ riskDecision: { t: 'const', value: 'REVIEW' }, reasonCode: ENUM(ESCALATION_REASONS) }, ['riskDecision', 'reasonCode']),
        },
        ['id', 'when', 'then'],
      ),
      { max: 20 },
    ),
  },
  ['steps', 'memoryRetrieval', 'contextAssembly', 'evidenceRequests', 'escalation'],
);

function checkNode(s, v, path, errors) {
  const t = typeOf(v);
  switch (s.t) {
    case 'object': {
      if (t !== 'object') return errors.push({ path, message: 'must be an object' });
      for (const key of s.required) if (!Object.hasOwn(v, key)) errors.push({ path: `${path}/${key}`, message: 'is required' });
      const keys = Object.keys(v);
      if (s.minProps && keys.length < s.minProps) errors.push({ path, message: `must have at least ${s.minProps} properties` });
      for (const key of keys) {
        if (!Object.hasOwn(s.props, key)) errors.push({ path: `${path}/${key}`, message: 'is not allowed' });
        else checkNode(s.props[key], v[key], `${path}/${key}`, errors);
      }
      return;
    }
    case 'array': {
      if (t !== 'array') return errors.push({ path, message: 'must be an array' });
      if (s.min !== undefined && v.length < s.min) errors.push({ path, message: `must have at least ${s.min} items` });
      if (s.max !== undefined && v.length > s.max) return errors.push({ path, message: `must have at most ${s.max} items` });
      if (s.unique && new Set(v.map((x) => JSON.stringify(x))).size !== v.length) errors.push({ path, message: 'must not contain duplicate items' });
      v.forEach((item, i) => checkNode(s.items, item, `${path}/${i}`, errors));
      return;
    }
    case 'enum':
      if (!s.values.includes(v)) errors.push({ path, message: `must be one of ${s.values.join(', ')}` });
      return;
    case 'const':
      if (v !== s.value) errors.push({ path, message: `must be ${JSON.stringify(s.value)}` });
      return;
    case 'integer':
      if (!Number.isSafeInteger(v)) return errors.push({ path, message: 'must be an integer' });
      if (v < s.min) errors.push({ path, message: `must be >= ${s.min}` });
      if (v > s.max) errors.push({ path, message: `must be <= ${s.max}` });
      return;
    case 'boolean':
      if (t !== 'boolean') errors.push({ path, message: 'must be a boolean' });
      return;
    case 'string':
      if (t !== 'string') return errors.push({ path, message: 'must be a string' });
      if (s.maxLen !== undefined && v.length > s.maxLen) errors.push({ path, message: `must be at most ${s.maxLen} characters` });
      if (s.re && !s.re.test(v)) errors.push({ path, message: 'has an invalid format' });
      return;
    default:
      throw new Error(`unsupported schema node ${s.t}`);
  }
}

function findForbiddenKeys(v, path, errors, depth = 0) {
  if (depth > 32) return errors.push({ path, message: 'is nested too deeply' });
  if (Array.isArray(v)) return v.forEach((x, i) => findForbiddenKeys(x, `${path}/${i}`, errors, depth + 1));
  if (!isObj(v)) return;
  for (const key of Object.keys(v)) {
    if (FORBIDDEN_POLICY_KEYS.includes(key)) errors.push({ path: `${path}/${key}`, message: 'policy documents may not reference invariants' });
    findForbiddenKeys(v[key], `${path}/${key}`, errors, depth + 1);
  }
}

/** Validate an adaptive policy document. Returns [{ path, message }]; empty = valid. */
export function validatePolicy(policy) {
  const errors = [];
  findForbiddenKeys(policy, '', errors);
  checkNode(POLICY_SCHEMA, policy, '', errors);
  const steps = isObj(policy) && Array.isArray(policy.steps) ? policy.steps : null;
  if (steps) {
    const core = steps.filter((s) => CORE_STAGES.includes(s));
    if (core.length !== CORE_STAGES.length || core.some((s, i) => s !== CORE_STAGES[i])) {
      errors.push({ path: '/steps', message: `must contain the core stages in order ${CORE_STAGES.join(', ')}` });
    } else {
      const mem = steps.indexOf('memory');
      const pol = steps.indexOf('policy');
      steps.forEach((s, i) => {
        if (ADAPTIVE_STEPS.includes(s) && !(i > mem && i < pol)) {
          errors.push({ path: `/steps/${i}`, message: "adaptive steps must appear between 'memory' and 'policy'" });
        }
      });
    }
  }
  return errors;
}
