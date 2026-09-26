// REQ-019: explainable, rule-based trust score per agent. Advisory only — the
// authoritative decision is always POST /v1/verify (deny by default, §3).
//
// `scoreAgent` is a pure function over store documents so the rules are
// unit-testable; `trustService` loads the inputs with tenant scoping.
import { decodeCursor } from '../store/pagination.js';
import { notFound } from './util.js';

export const TRUST_RULES_VERSION = 'kya-trust-v1';

const DAY_MS = 24 * 3600 * 1000;
/** Upper bound on documents scanned per input query (keeps the endpoint cheap). */
export const TRUST_SCAN_LIMIT = 1000;

const MAX = { operator_verification: 35, agent_age: 20, revocation_history: 25, scope_breadth: 20 };

/** Age bands: [minimum age in days, points]. First match wins. */
const AGE_BANDS = [
  [90, 20],
  [30, 15],
  [7, 10],
  [1, 5],
  [0, 0],
];

const PENALTY = {
  revokedGrant: 8,
  revokedCredential: 5,
  siblingRevokedOrSuspended: 5,
  agentSuspended: 10,
  patternAboveFree: 2, // per distinct action pattern beyond FREE_PATTERNS
  wildcardPattern: 4,
  unconstrainedGrant: 3,
};
const FREE_PATTERNS = 3;

const clamp = (n, max) => Math.max(0, Math.min(max, n));

function levelFor(score, gated) {
  if (gated) return 'untrusted';
  if (score >= 80) return 'high';
  if (score >= 50) return 'medium';
  return 'low';
}

function operatorFactor(operator) {
  const max = MAX.operator_verification;
  const v = operator?.verification ?? null;
  const inputs = {
    operatorStatus: operator?.status ?? null,
    kycResult: v?.kycResult ?? null,
    sanctionsResult: v?.sanctionsResult ?? null,
    method: v?.method ?? null,
  };
  let points = 0;
  let detail;
  if (!operator) detail = 'Operator record not found.';
  else if (operator.status !== 'verified') detail = `Operator is ${operator.status}; agents of unverified operators are denied.`;
  else if (v?.kycResult !== 'pass') detail = 'Operator verified but no passing KYC result is recorded.';
  else if (v.sanctionsResult === 'clear') {
    points = max;
    detail = `Operator verified: KYC pass (${v.method}), sanctions screen clear.`;
  } else {
    points = 20;
    detail = `Operator verified: KYC pass (${v.method}), sanctions screen ${v.sanctionsResult ?? 'missing'}.`;
  }
  return { code: 'operator_verification', label: 'Operator verification level', points, maxPoints: max, detail, inputs };
}

function ageFactor(agent, now) {
  const created = agent.createdAt instanceof Date ? agent.createdAt.getTime() : Date.parse(agent.createdAt);
  const ageMs = Number.isFinite(created) ? Math.max(0, now.getTime() - created) : 0;
  const ageDays = Math.floor(ageMs / DAY_MS);
  const points = AGE_BANDS.find(([minDays]) => ageDays >= minDays)[1];
  return {
    code: 'agent_age',
    label: 'Agent age',
    points,
    maxPoints: MAX.agent_age,
    detail: `Registered ${ageDays} day(s) ago (full points at 90 days).`,
    inputs: { ageDays },
  };
}

function revocationFactor({ agent, revokedGrants, revokedCredentials, siblingRevokedOrSuspended, truncated }) {
  const max = MAX.revocation_history;
  const inputs = { revokedGrants, revokedCredentials, siblingRevokedOrSuspended, agentSuspended: agent.status === 'suspended', truncated };
  if (truncated) {
    // Fail safe: an incomplete history must not look clean.
    return { code: 'revocation_history', label: 'Revocation history', points: 0, maxPoints: max, detail: 'History exceeds the scan limit; scored as 0.', inputs };
  }
  const penalty =
    revokedGrants * PENALTY.revokedGrant +
    revokedCredentials * PENALTY.revokedCredential +
    siblingRevokedOrSuspended * PENALTY.siblingRevokedOrSuspended +
    (inputs.agentSuspended ? PENALTY.agentSuspended : 0);
  const points = clamp(max - penalty, max);
  const detail =
    penalty === 0
      ? 'No revoked grants or credentials; no revoked/suspended sibling agents.'
      : `${revokedGrants} revoked grant(s), ${revokedCredentials} revoked credential(s), ` +
        `${siblingRevokedOrSuspended} revoked/suspended sibling agent(s)${inputs.agentSuspended ? ', agent currently suspended' : ''}.`;
  return { code: 'revocation_history', label: 'Revocation history', points, maxPoints: max, detail, inputs };
}

function scopeFactor({ activeGrants, truncated }) {
  const max = MAX.scope_breadth;
  const patterns = new Set(activeGrants.flatMap((g) => g.actions ?? []));
  const wildcardPatterns = [...patterns].filter((p) => p.endsWith(':*')).length;
  const unconstrainedGrants = activeGrants.filter((g) => Object.keys(g.constraints ?? {}).length === 0).length;
  const inputs = { activeGrants: activeGrants.length, distinctActionPatterns: patterns.size, wildcardPatterns, unconstrainedGrants, truncated };
  if (truncated) {
    return { code: 'scope_breadth', label: 'Scope breadth', points: 0, maxPoints: max, detail: 'Active grants exceed the scan limit; scored as 0.', inputs };
  }
  const penalty =
    Math.max(0, patterns.size - FREE_PATTERNS) * PENALTY.patternAboveFree +
    wildcardPatterns * PENALTY.wildcardPattern +
    unconstrainedGrants * PENALTY.unconstrainedGrant;
  const points = clamp(max - penalty, max);
  const detail =
    activeGrants.length === 0
      ? 'No active grants (narrowest possible scope).'
      : `${activeGrants.length} active grant(s), ${patterns.size} distinct action pattern(s), ` +
        `${wildcardPatterns} wildcard(s), ${unconstrainedGrants} grant(s) without constraints.`;
  return { code: 'scope_breadth', label: 'Scope breadth', points, maxPoints: max, detail, inputs };
}

/** Passport statuses that hard-gate the score (blocked / terminal, passport.md §2). */
const PASSPORT_GATING = new Set(['SUSPENDED', 'REVOKED']);

/**
 * Sanctions exposure from the agent's passport (the continuously re-screened trust state).
 * Carries no points (the four scored factors keep maxScore 100); a SUSPENDED or REVOKED
 * passport is a hard gate, REVIEW / RE_SCREENING are reported but not scored.
 */
function sanctionsExposureFactor(passport) {
  const inputs = {
    passportId: passport.id ?? null,
    passportStatus: passport.status ?? null,
    statusReason: passport.statusReason ?? null,
    sanctionsDatasetVersion: passport.sanctionsDatasetVersion ?? null,
    lastInvestigationId: passport.lastInvestigationId ?? null,
  };
  const detail =
    passport.status === 'ACTIVE'
      ? `Passport ACTIVE; last sanctions screen against dataset ${inputs.sanctionsDatasetVersion ?? 'unknown'}.`
      : `Passport ${passport.status}${inputs.statusReason ? ` (${inputs.statusReason})` : ''}; dataset ${inputs.sanctionsDatasetVersion ?? 'unknown'}.`;
  return { code: 'sanctions_exposure', label: 'Sanctions exposure (passport)', points: 0, maxPoints: 0, detail, inputs };
}

/**
 * Pure scoring. Inputs are store documents (Dates) plus pre-counted history.
 * Hard gates mirror verify checks 4–5: a non-active agent or non-verified operator
 * is `untrusted` with score 0 regardless of the other factors.
 */
export function scoreAgent({
  agent,
  operator,
  activeGrants = [],
  revokedGrants = 0,
  revokedCredentials = 0,
  siblingRevokedOrSuspended = 0,
  truncated = { grants: false, history: false },
  passport = null,
  now,
}) {
  const factors = [
    operatorFactor(operator),
    ageFactor(agent, now),
    revocationFactor({ agent, revokedGrants, revokedCredentials, siblingRevokedOrSuspended, truncated: truncated.history }),
    scopeFactor({ activeGrants, truncated: truncated.grants }),
  ];
  if (passport) factors.push(sanctionsExposureFactor(passport));
  const gates = [];
  if (agent.status !== 'active') gates.push(`Agent is ${agent.status}.`);
  if (!operator || operator.status !== 'verified') gates.push(`Operator is ${operator?.status ?? 'missing'}.`);
  if (passport && PASSPORT_GATING.has(passport.status)) gates.push(`Passport is ${passport.status}.`);
  const gated = gates.length > 0;
  const raw = factors.reduce((sum, f) => sum + f.points, 0);
  const score = gated ? 0 : raw;
  return {
    agentId: agent.id,
    operatorId: agent.operatorId,
    rulesVersion: TRUST_RULES_VERSION,
    score,
    maxScore: 100,
    level: levelFor(score, gated),
    gates,
    factors,
    computedAt: now.toISOString(),
    advisory: 'Informational only. Authorization decisions come from POST /v1/verify.',
  };
}

/** Collect up to `limit` documents matching `filter`; `truncated` if more exist. */
async function collect(collection, filter, limit = TRUST_SCAN_LIMIT) {
  const out = [];
  let cursor = null;
  do {
    const page = await collection.list({ filter, limit: Math.min(200, limit - out.length + 1), cursor });
    out.push(...page.data);
    cursor = page.nextCursor ? decodeCursor(page.nextCursor) : null;
  } while (cursor && out.length <= limit);
  return { docs: out.slice(0, limit), truncated: out.length > limit };
}

export function trustService({ store, clock }) {
  return {
    /** Admin: any agent. Operator: own agents only. Business: any agent (public lookup, aggregate counts only). */
    async score(principal, id) {
      const agent = await store.agents.findById(id);
      if (!agent) throw notFound();
      if (principal.role === 'operator' && agent.operatorId !== principal.operatorId) throw notFound();
      const operator = await store.operators.findById(agent.operatorId);
      const now = clock.now();

      const [active, revGrants, revCreds, revSiblings, susSiblings] = await Promise.all([
        collect(store.grants, { agentId: agent.id, status: 'active' }),
        collect(store.grants, { agentId: agent.id, status: 'revoked' }),
        collect(store.credentials, { agentId: agent.id, status: 'revoked' }),
        collect(store.agents, { operatorId: agent.operatorId, status: 'revoked' }),
        collect(store.agents, { operatorId: agent.operatorId, status: 'suspended' }),
      ]);
      const passport = store.passports ? ((await store.passports.find({ agentId: agent.id }, { limit: 1 }))[0] ?? null) : null;
      const siblings = [...revSiblings.docs, ...susSiblings.docs].filter((a) => a.id !== agent.id).length;
      return scoreAgent({
        agent,
        operator,
        activeGrants: active.docs.filter((g) => g.expiresAt > now),
        revokedGrants: revGrants.docs.length,
        revokedCredentials: revCreds.docs.length,
        siblingRevokedOrSuspended: siblings,
        truncated: {
          grants: active.truncated,
          history: revGrants.truncated || revCreds.truncated || revSiblings.truncated || susSiblings.truncated,
        },
        passport,
        now,
      });
    },
  };
}
