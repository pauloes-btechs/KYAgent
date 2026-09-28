// Adaptive policy layer (docs/contracts/harness.md §2–§4). Reads the active `harness_versions`
// document and validates it; it never decides whether an invariant applies (that is
// src/harness/invariants.js, frozen code). Writers of harness_versions: investigations#confirm only.
import { canonicalJson } from '../crypto/canonical.js';
import { sha256hex } from '../crypto/ed25519.js';
import { ADAPTIVE_STEPS, CORE_STAGES, INVARIANTS_HASH, validatePolicy } from './invariants.js';

export { ADAPTIVE_STEPS, CORE_STAGES, validatePolicy };

/** Seed v1 policy (harness.md §3.2). Used when no harness_versions document exists (unit tests). */
export const HARNESS_V1_POLICY = Object.freeze({
  steps: Object.freeze([...CORE_STAGES]),
  memoryRetrieval: Object.freeze({ k: 3, numCandidates: 100, minScorePpm: 780_000, filter: Object.freeze({ status: 'VERIFIED' }) }),
  contextAssembly: Object.freeze({ maxMemories: 3, includeSignalStats: true, includeSanctionsEvidence: true }),
  evidenceRequests: Object.freeze([]),
  escalation: Object.freeze([
    Object.freeze({
      id: 'precedent_takeover',
      when: Object.freeze({ precedentOutcomeIn: Object.freeze(['CONFIRMED_ACCOUNT_TAKEOVER']) }),
      then: Object.freeze({ riskDecision: 'REVIEW', reasonCode: 'MEMORY_PRECEDENT_TAKEOVER' }),
    }),
  ]),
});

export class HarnessPolicyError extends Error {
  constructor(message, code = 'HARNESS_POLICY_INVALID', details = []) {
    super(message);
    this.name = 'HarnessPolicyError';
    this.code = code;
    this.details = details;
  }
}

export const policyHash = (policy) => sha256hex(Buffer.from(canonicalJson(policy), 'utf8'));

/** Adaptive steps of a policy, in execution order (between `memory` and `policy`). */
export const adaptiveSteps = (policy) => (Array.isArray(policy?.steps) ? policy.steps.filter((s) => ADAPTIVE_STEPS.includes(s)) : []);

/**
 * Load the active harness version. Returns
 * `{ version, policy, policyHash, invariantsHash, invariantsMatch, persisted, doc }`.
 * - No document at all ⇒ the v1 seed policy (`persisted: false`); adaptation requires a persisted version.
 * - An invalid stored policy throws HarnessPolicyError (callers fail closed).
 * - `invariantsMatch` is false when the stored invariantsHash differs from the runtime INVARIANTS_HASH
 *   (the pipeline BLOCKs with HARNESS_INVARIANTS_MISMATCH).
 */
export async function loadActiveHarness(store) {
  const active = await store.harnessVersions.find({ status: 'active' }, { limit: 2 });
  if (active.length > 1) throw new HarnessPolicyError('more than one active harness version', 'HARNESS_MULTIPLE_ACTIVE');
  const [doc] = active;
  if (!doc) {
    const policy = structuredClone(HARNESS_V1_POLICY);
    return { version: 1, policy, policyHash: policyHash(policy), invariantsHash: INVARIANTS_HASH, invariantsMatch: true, persisted: false, doc: null };
  }
  const errors = validatePolicy(doc.policy);
  if (errors.length) throw new HarnessPolicyError(`harness v${doc.version} policy is invalid`, 'HARNESS_POLICY_INVALID', errors);
  const version = doc.version ?? doc.id;
  if (!Number.isSafeInteger(version) || version < 1) throw new HarnessPolicyError('harness version is not a positive integer');
  return {
    version,
    policy: doc.policy,
    policyHash: policyHash(doc.policy),
    invariantsHash: doc.invariantsHash,
    invariantsMatch: doc.invariantsHash === INVARIANTS_HASH,
    persisted: true,
    doc,
  };
}

/** All versions, newest first (GET /v1/harness/versions). */
export async function listHarnessVersions(store) {
  const docs = await store.harnessVersions.find({}, { sort: { _id: -1 }, limit: 1000 });
  return docs.sort((a, b) => b.version - a.version);
}

/** API view of a harness_versions document (openapi HarnessVersion). */
export function harnessVersionOut(d) {
  const iso = (v) => (v instanceof Date ? v.toISOString() : v ?? null);
  return {
    version: d.version,
    status: d.status,
    parentVersion: d.parentVersion ?? null,
    invariantsHash: d.invariantsHash,
    policy: d.policy,
    policyHash: d.policyHash,
    createdAt: iso(d.createdAt),
    approvedBy: d.approvedBy,
    sourceEventId: d.sourceEventId ?? null,
  };
}
