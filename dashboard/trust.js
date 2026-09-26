// Trust score — an informational, deterministic summary derived ONLY from
// contract fields the caller can already read (agent, operator, and the
// verification audit log). It is not an authorization decision: the
// authoritative answer is always POST /v1/verify (deny by default).
//
// Pure module (no DOM, no network) so it runs in the browser and under node:test.

/** DENY reasons that indicate a possible attack or key compromise, not a mere scoping gap. */
export const SECURITY_SIGNAL_CODES = new Set([
  'SIGNATURE_INVALID',
  'NONCE_REPLAYED',
  'CREDENTIAL_INVALID',
  'CREDENTIAL_KEY_MISMATCH',
  'CREDENTIAL_SUBJECT_MISMATCH',
  'CREDENTIAL_REVOKED',
  'AUDIENCE_MISMATCH',
  'CREDENTIAL_AUDIENCE_MISMATCH',
]);

const DAY_MS = 24 * 60 * 60 * 1000;

/**
 * @param {{ agent: object, operator?: object|null, verifications?: object[]|null, now?: Date }} input
 * @returns {{ score: number, level: 'high'|'medium'|'low'|'untrusted', verdict: string, factors: {label: string, impact: number, detail: string}[] }}
 */
export function trustAssessment({ agent, operator = null, verifications = null, now = new Date() }) {
  const factors = [];
  const untrusted = (verdict, label, detail) => ({ score: 0, level: 'untrusted', verdict, factors: [{ label, impact: -100, detail }] });

  // Hard gates mirror verification checks 3–5: any failure means verify would DENY.
  if (!agent || typeof agent !== 'object') return untrusted('Not trusted — agent not visible', 'Agent', 'No agent record is visible to you.');
  if (agent.status !== 'active') {
    return untrusted(`Not trusted — agent ${safeWord(agent.status)}`, 'Agent status', `Agent is ${safeWord(agent.status)}; every verification is denied.`);
  }
  if (!operator || typeof operator !== 'object') {
    return untrusted('Not trusted — operator unknown', 'Operator', 'The accountable operator could not be loaded.');
  }
  if (operator.id !== undefined && agent.operatorId !== undefined && operator.id !== agent.operatorId) {
    return untrusted('Not trusted — operator mismatch', 'Operator', 'Operator record does not match the agent binding.');
  }
  if (operator.status !== 'verified') {
    return untrusted(`Not trusted — operator ${safeWord(operator.status)}`, 'Operator status', `Operator is ${safeWord(operator.status)}; every verification is denied.`);
  }

  let score = 100;
  factors.push({ label: 'Identity', impact: 0, detail: 'Agent active; operator verified.' });

  // Operator verification detail (admin / own operator only; business sees the public profile).
  const v = operator.verification;
  if (v && typeof v === 'object') {
    if (v.sanctionsResult === 'skipped') {
      score -= 15;
      factors.push({ label: 'Sanctions screening', impact: -15, detail: 'Screening was skipped (SANCTIONS_MODE=off).' });
    } else if (v.sanctionsResult === 'clear') {
      factors.push({ label: 'Sanctions screening', impact: 0, detail: 'Clear.' });
    }
    if (v.method === 'mock') factors.push({ label: 'KYC', impact: 0, detail: 'Mock KYC (MVP) — not a real identity check.' });
  } else {
    factors.push({ label: 'Operator verification', impact: 0, detail: 'Verification detail not visible to your role.' });
  }

  // Key age: a freshly registered key has no track record.
  const created = Date.parse(agent.createdAt);
  if (Number.isFinite(created) && now.getTime() - created < DAY_MS) {
    score -= 10;
    factors.push({ label: 'Key age', impact: -10, detail: 'Registered less than 24 hours ago.' });
  }

  // Decision history from the audit log (only rows for this agent are considered).
  if (Array.isArray(verifications)) {
    const rows = verifications.filter((e) => e && e.agentId === agent.id);
    if (rows.length === 0) {
      factors.push({ label: 'Decision history', impact: 0, detail: 'No recorded verifications.' });
    } else {
      const denies = rows.filter((e) => e.decision !== 'ALLOW');
      const signals = denies.filter((e) => SECURITY_SIGNAL_CODES.has(e.reasons?.[0]?.code));
      const denyPenalty = Math.round((denies.length / rows.length) * 20);
      if (denyPenalty > 0) {
        score -= denyPenalty;
        factors.push({ label: 'Deny rate', impact: -denyPenalty, detail: `${denies.length} of ${rows.length} recent decisions were DENY.` });
      } else {
        factors.push({ label: 'Deny rate', impact: 0, detail: `All ${rows.length} recent decisions were ALLOW.` });
      }
      const signalPenalty = Math.min(40, signals.length * 10);
      if (signalPenalty > 0) {
        score -= signalPenalty;
        const codes = [...new Set(signals.map((e) => e.reasons[0].code))].sort().join(', ');
        factors.push({ label: 'Security signals', impact: -signalPenalty, detail: `${signals.length} DENY with ${codes}.` });
      }
    }
  }

  score = Math.max(1, Math.min(100, score));
  const level = score >= 80 ? 'high' : score >= 50 ? 'medium' : 'low';
  const verdict = level === 'high' ? 'Identity verified — agent active, operator verified' : `Identity verified — ${level} trust, review factors`;
  return { score, level, verdict, factors };
}

/** Count DENY decisions by reason code (for the audit-log summary table). Sorted by count desc, then code. */
export function denyCountsByReason(verifications) {
  const counts = new Map();
  for (const e of verifications || []) {
    if (!e || e.decision === 'ALLOW') continue;
    const code = e.reasons?.[0]?.code || 'UNKNOWN';
    counts.set(code, (counts.get(code) || 0) + 1);
  }
  return [...counts.entries()].map(([code, count]) => ({ code, count })).sort((a, b) => b.count - a.count || a.code.localeCompare(b.code));
}

// Status values come from the server; only echo well-formed words into UI copy.
function safeWord(s) {
  return typeof s === 'string' && /^[a-z_]{1,32}$/.test(s) ? s : 'in an unknown state';
}
