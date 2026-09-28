// POST /v1/investigations (investigation-pipeline.md §2 trigger `api`, DELIVERY_PLAN T08).
// The request is a VerifyRequest whose signed `context` is a PaymentContext. The identity
// stage runs the /v1/verify steps 1–8 in signed mode (same signing string, same nonce store:
// the nonce is consumed exactly once, only after the signature verified); the rest of the
// pipeline (delegation -> signals -> memory -> decision) is src/investigation/pipeline.js.
// Transaction data comes only from the signed context. /v1/verify itself is untouched.
//
// This service is the only writer of `investigations`. Fail closed: a stage error is persisted
// as BLOCK / INTERNAL_ERROR and returned with HTTP 500; an unauditable decision becomes BLOCK /
// INTERNAL_ERROR; if the document cannot be written the standard 500 error envelope is returned.
import { ACTION_RE } from '../contracts.js';
import { buildSigningString, canonicalJson, CanonicalJsonError } from '../crypto/canonical.js';
import { parsePublicKey, sha256hex, verifySignature } from '../crypto/ed25519.js';
import { ApiError, validationError } from '../errors.js';
import { evaluateProposal, proposeFromOutcome } from '../harness/adaptation.js';
import { holds, INVARIANTS_HASH } from '../harness/invariants.js';
import { harnessVersionOut, listHarnessVersions, loadActiveHarness, policyHash } from '../harness/policy.js';
import { newId } from '../ids.js';
import { runInvestigation } from '../investigation/pipeline.js';
import { embedWithMeta } from '../memory/embeddings.js';
import { normalizeSignals, signalsText } from '../memory/signalsText.js';
import { schemas, validate } from '../validate.js';
import { actorOf } from './audit.js';
import { actionMatches } from './authz.js';

export const HARNESS_ID_RE = /^[a-z]{2,4}_[A-Za-z0-9_-]{1,64}$/;
const EVM_ADDRESS_RE = /^0x[0-9a-f]{40}$/;
const MAX_CONTEXT_BYTES = 8 * 1024;
const PAYMENT_CURRENCIES = ['USDC'];

/** Step 1 (MALFORMED_REQUEST) + PaymentContext shape. Throws 400 VALIDATION_ERROR. */
function parseRequest(body) {
  const details = validate(schemas.verifyRequest, body);
  if (details.length) throw validationError(details, 'Investigation request is invalid');
  const bad = (path, message) => {
    throw validationError([{ path, message }], 'Investigation request is invalid');
  };
  const sr = body.signedRequest;
  const resource = body.resource ?? '';
  const ctx = body.context;
  if (!ctx || typeof ctx !== 'object' || Array.isArray(ctx)) bad('/context', 'must be a PaymentContext object');
  if (!Number.isSafeInteger(ctx.amount) || ctx.amount < 1) bad('/context/amount', 'must be a positive integer (minor units)');
  if (!PAYMENT_CURRENCIES.includes(ctx.currency)) bad('/context/currency', `must be one of ${PAYMENT_CURRENCIES.join(', ')}`);
  if (typeof ctx.counterparty !== 'string' || !EVM_ADDRESS_RE.test(ctx.counterparty)) bad('/context/counterparty', 'must be a lowercased EVM address');
  if (ctx.wallet !== undefined && (typeof ctx.wallet !== 'string' || !EVM_ADDRESS_RE.test(ctx.wallet))) bad('/context/wallet', 'must be a lowercased EVM address');
  if (ctx.counterpartyName !== undefined && (typeof ctx.counterpartyName !== 'string' || ctx.counterpartyName.length > 200)) {
    bad('/context/counterpartyName', 'must be a string of at most 200 characters');
  }
  let canonical;
  try {
    canonical = canonicalJson(ctx);
  } catch (err) {
    if (err instanceof CanonicalJsonError) bad('/context', 'must be canonical-JSON safe');
    throw err;
  }
  if (Buffer.byteLength(canonical, 'utf8') > MAX_CONTEXT_BYTES) bad('/context', `must be at most ${MAX_CONTEXT_BYTES} bytes`);
  if (
    sr.agentId !== body.agentId ||
    sr.action !== body.action ||
    sr.resource !== resource ||
    sr.contextSha256 !== sha256hex(Buffer.from(canonical, 'utf8'))
  ) {
    bad('/signedRequest', 'does not match agentId, action, resource and context');
  }
  if (!ACTION_RE.test(body.action)) bad('/action', 'is invalid');
  return { agentId: body.agentId, action: body.action, resource, context: ctx, sr };
}

const investigationOut = ({ _id, id, ...rest }) => ({ id: id ?? _id, ...rest });

export const OUTCOMES = Object.freeze(['CLEAN', 'CONFIRMED_ACCOUNT_TAKEOVER', 'FALSE_POSITIVE', 'SANCTIONS_MATCH']);
const CONFIRMABLE = ['DECIDED', 'AWAITING_REVIEW'];
/** Case memory id (mongo-collections.md security_memories: `mem_<sourceInvestigationId>`). */
export const caseMemoryId = (investigationId) => `mem_${investigationId}`;

/** ConfirmInvestigationRequest (openapi): { outcome, approveAdaptation, note? }, no other keys. */
function parseConfirm(body) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    throw validationError([{ path: '', message: 'must be an object' }], 'Confirmation request is invalid');
  }
  const details = [];
  for (const k of Object.keys(body)) {
    if (!['outcome', 'approveAdaptation', 'note'].includes(k)) details.push({ path: `/${k}`, message: 'is not allowed' });
  }
  if (!OUTCOMES.includes(body.outcome)) details.push({ path: '/outcome', message: `must be one of ${OUTCOMES.join(', ')}` });
  if (typeof body.approveAdaptation !== 'boolean') details.push({ path: '/approveAdaptation', message: 'must be a boolean' });
  if (body.note !== undefined && (typeof body.note !== 'string' || body.note.length > 1000)) {
    details.push({ path: '/note', message: 'must be a string of at most 1000 characters' });
  }
  if (details.length) throw validationError(details, 'Confirmation request is invalid');
  return { outcome: body.outcome, approveAdaptation: body.approveAdaptation, note: body.note ?? null };
}

const iso = (v) => (v instanceof Date ? v.toISOString() : v ?? null);
const harnessEventOut = ({ _id, id, ...rest }) => ({ id: id ?? _id, ...rest, approvedAt: iso(rest.approvedAt), at: iso(rest.at) });

export function investigationService({ store, clock, config, audit, llm = null }) {
  /** /v1/verify steps 2–8 in order; returns the first failing reason code (or ALLOWED). */
  async function signedIdentity(principal, req, now) {
    const out = { reasonCode: 'ALLOWED', signature: 'not_checked', nonce: 'not_checked', businessId: null, agent: null };
    // 2. audience: the calling business, or (admin) an existing business named by the agent
    if (principal.role === 'business') out.businessId = principal.businessId;
    else if (HARNESS_ID_RE.test(req.sr.audience)) out.businessId = (await store.businesses.findById(req.sr.audience))?.id ?? null;
    if (!out.businessId || req.sr.audience !== out.businessId) return { ...out, reasonCode: 'AUDIENCE_MISMATCH' };
    // 3–5. agent and operator state
    const agent = HARNESS_ID_RE.test(req.agentId) ? await store.agents.findById(req.agentId) : null;
    out.agent = agent;
    if (!agent) return { ...out, reasonCode: 'AGENT_NOT_FOUND' };
    if (agent.status === 'suspended') return { ...out, reasonCode: 'AGENT_SUSPENDED' };
    if (agent.status !== 'active') return { ...out, reasonCode: 'AGENT_REVOKED' };
    const operator = await store.operators.findById(agent.operatorId);
    if (operator?.status === 'suspended') return { ...out, reasonCode: 'OPERATOR_SUSPENDED' };
    if (!operator || operator.status !== 'verified') return { ...out, reasonCode: 'OPERATOR_NOT_VERIFIED' };
    // 6. timestamp window
    const nowSec = Math.floor(now.getTime() / 1000);
    if (Math.abs(nowSec - req.sr.timestamp) > config.maxSkewSeconds) return { ...out, reasonCode: 'TIMESTAMP_OUT_OF_WINDOW' };
    // 7. signature with the registered key
    if (!verifySignature(parsePublicKey(agent.publicKey), buildSigningString(req.sr), req.sr.signature)) {
      return { ...out, signature: 'invalid', reasonCode: 'SIGNATURE_INVALID' };
    }
    out.signature = 'valid';
    // 8. nonce, recorded only after the signature verified (shared with /v1/verify)
    const nonceExpires = new Date((req.sr.timestamp + 2 * config.maxSkewSeconds) * 1000);
    if (!(await store.nonces.insertOnce(agent.id, req.sr.nonce, nonceExpires, now))) return { ...out, nonce: 'replayed', reasonCode: 'NONCE_REPLAYED' };
    return { ...out, nonce: 'fresh' };
  }

  /**
   * UNVERIFIED case memory for an investigation (never retrievable until a human verifies it).
   * The embedding comes from the same adapter as retrieval: embed(signalsText(signals)).
   */
  async function buildCaseMemory(inv, now) {
    const signals = normalizeSignals(inv.signals ?? []);
    const text = signalsText(signals);
    const { embedding, embeddingModel, embeddingTextSha256 } = await embedWithMeta(text);
    return {
      id: caseMemoryId(inv.id),
      title: `Case ${inv.id}: ${signals.length ? signals.join(', ') : 'no behavioral signals'}`,
      summary: `Candidate memory from investigation ${inv.id} (${inv.riskDecision} ${inv.reasons?.[0]?.code ?? ''}).`,
      status: 'UNVERIFIED',
      outcome: null,
      signals,
      signalsText: text,
      embedding,
      embeddingModel,
      embeddingTextSha256,
      recommendedSteps: [],
      sourceInvestigationId: inv.id,
      agentId: inv.agentId ?? null,
      principalId: inv.principalId ?? null,
      verifiedBy: null,
      verifiedAt: null,
      createdAt: now,
    };
  }

  /**
   * Validate and (when approved) apply an adaptation proposal (harness.md §6.4–6.5).
   * Applied: supersede vN, insert vN+1, audit `harness.adapted`, harness_events `adaptation.applied`.
   * Otherwise: audit `harness.adaptation_rejected`, harness_events `adaptation.rejected`, no version change.
   */
  async function recordAdaptation({ principal, approver, inv, mem, harness, proposal, approve, now }) {
    const fromVersion = harness.version;
    const errors = [];
    if (proposal.error) errors.push({ path: '/proposal', message: `${proposal.error.code}: ${proposal.error.message}` });
    if (!harness.persisted) errors.push({ path: '/harness', message: 'no persisted active harness version' });
    if (!harness.invariantsMatch) errors.push({ path: '/harness/invariantsHash', message: 'active version invariantsHash differs from runtime' });
    const evaluated = errors.length ? { ok: false, newPolicy: null, errors: [] } : evaluateProposal(harness.policy, proposal.diff);
    errors.push(...evaluated.errors);
    if (!errors.length && !approve) errors.push({ path: '/approveAdaptation', message: 'adaptation not approved by the confirming admin' });

    const eventId = newId('hev');
    const base = {
      id: eventId,
      fromVersion,
      diff: proposal.diff,
      oldPolicy: harness.policy,
      oldPolicyHash: harness.policyHash,
      invariantsHash: INVARIANTS_HASH,
      evidence: [
        { type: 'investigation', id: inv.id },
        { type: 'memory', id: mem.id },
      ],
      proposer: proposal.proposer,
      approvedBy: { role: 'admin', apiKeyId: approver.apiKeyId, ownerId: approver.ownerId ?? null },
      approvedAt: now,
      at: now,
    };

    if (errors.length) {
      const rejection = errors.slice(0, 20);
      const aud = await audit.record(principal, 'harness.adaptation_rejected', { type: 'harness_event', id: eventId }, {
        fromVersion,
        investigationId: inv.id,
        memoryId: mem.id,
        errors: rejection.map((e) => `${e.path} ${e.message}`),
      });
      await store.harnessEvents.insert({ ...base, type: 'adaptation.rejected', toVersion: null, newPolicy: null, newPolicyHash: null, rejection, auditEventId: aud.id });
      return { applied: false, eventId, toVersion: null };
    }

    const toVersion = fromVersion + 1;
    const { newPolicy } = evaluated;
    const newPolicyHash = policyHash(newPolicy);
    // Supersede vN first, then insert vN+1 (unique partial index: at most one active version).
    const superseded = await store.harnessVersions.updateIf(fromVersion, ['active'], { status: 'superseded' });
    if (!superseded) throw new ApiError('INVALID_STATE', 'The active harness version changed concurrently');
    const reactivate = () => store.harnessVersions.updateIf(fromVersion, ['superseded'], { status: 'active' });
    try {
      await store.harnessVersions.insert({
        id: toVersion,
        version: toVersion,
        status: 'active',
        parentVersion: fromVersion,
        invariantsHash: INVARIANTS_HASH,
        policy: newPolicy,
        policyHash: newPolicyHash,
        createdAt: now,
        approvedBy: base.approvedBy,
        sourceEventId: eventId,
      });
    } catch {
      await reactivate().catch(() => {});
      throw new ApiError('INTERNAL_ERROR');
    }
    // An unaudited adaptation must not stay active.
    const aud = await audit.recordOrCompensate(
      principal,
      'harness.adapted',
      { type: 'harness_event', id: eventId },
      { fromVersion, toVersion, oldPolicyHash: harness.policyHash, newPolicyHash, invariantsHash: INVARIANTS_HASH, investigationId: inv.id, memoryId: mem.id, diff: proposal.diff },
      async () => {
        await store.harnessVersions.updateIf(toVersion, ['active'], { status: 'superseded' });
        await reactivate();
      },
    );
    await store.harnessEvents.insert({ ...base, type: 'adaptation.applied', toVersion, newPolicy, newPolicyHash, auditEventId: aud.id });
    return { applied: true, eventId, toVersion };
  }

  /** Delegation under test: first active grant (createdAt asc) from the business that covers the action. */
  async function delegationFor(agentId, businessId, action, now) {
    if (!businessId) return null;
    const grants = await store.grants.findActiveFor(agentId, businessId, now);
    return grants.find((g) => g.actions.some((p) => actionMatches(p, action))) ?? grants[0] ?? null;
  }

  return {
    /** @returns { status: 201 | 500, body: Investigation } */
    async create(principal, body, requestId) {
      const req = parseRequest(body);
      const now = clock.now();
      const id = newId('inv');
      const signed = await signedIdentity(principal, req, now);
      const agent = signed.agent;
      const grant = signed.reasonCode === 'ALLOWED' ? await delegationFor(agent.id, signed.businessId, req.action, now) : null;
      const harness = await loadActiveHarness(store);
      const ctx = req.context;
      const transaction = {
        asset: ctx.currency,
        amount: ctx.amount,
        wallet: ctx.wallet ?? agent?.wallets?.[0]?.address ?? null,
        counterparty: { address: ctx.counterparty, name: ctx.counterpartyName ?? null },
      };

      const r = await runInvestigation({
        store,
        agentId: req.agentId,
        delegationId: grant?.id ?? null,
        policy: harness.policy,
        trigger: 'api',
        now,
        invariantsMatch: harness.invariantsMatch,
        signedIdentity: { reasonCode: signed.reasonCode, signature: signed.signature, nonce: signed.nonce },
        tx: { id, ...transaction, resource: req.resource, signingKeyThumbprint: agent?.keyThumbprint ?? null },
      });

      const precedentIds = new Set(r.reasons.flatMap((x) => x.evidenceRefs ?? []));
      const memory = r.memory
        ? { ...r.memory, hits: r.memory.hits.map((h) => ({ ...h, usedAsPrecedent: precedentIds.has(h.memoryId) })) }
        : { engine: '$vectorSearch', k: harness.policy.memoryRetrieval.k, minScorePpm: harness.policy.memoryRetrieval.minScorePpm, hits: [] };
      const failed = r.stages.some((s) => s.status === 'error');
      const doc = {
        id,
        trigger: 'api',
        triggerRef: null,
        initiatedBy: { role: principal.role, apiKeyId: principal.apiKeyId ?? null, ownerId: principal.businessId ?? principal.operatorId ?? null },
        agentId: req.agentId,
        principalId: agent?.operatorId ?? null,
        businessId: signed.businessId,
        delegationId: grant?.id ?? null,
        delegationVersion: grant?.version ?? null,
        action: req.action,
        transaction,
        harnessVersion: harness.version,
        stages: r.stages,
        signals: r.signals,
        memory,
        decision: r.decision,
        riskDecision: r.riskDecision,
        reasons: r.reasons,
        status: r.riskDecision === 'REVIEW' ? 'AWAITING_REVIEW' : 'DECIDED',
        outcome: null,
        confirmedBy: null,
        confirmedAt: null,
        passport: null,
        receiptId: null,
        receiptHash: null,
        requestId: requestId ?? null,
        createdAt: now,
        decidedAt: clock.now(),
      };

      let status = failed ? 500 : 201;
      // An unauditable decision must not stand: fail closed.
      try {
        await audit.record(principal, 'investigation.decided', { type: 'investigation', id }, {
          agentId: doc.agentId,
          trigger: doc.trigger,
          riskDecision: doc.riskDecision,
          reasonCode: doc.reasons[0]?.code ?? null,
          businessId: doc.businessId,
          delegationId: doc.delegationId,
          memoryHits: doc.memory.hits.map((h) => h.memoryId),
        });
      } catch {
        doc.decision = 'DENY';
        doc.riskDecision = 'BLOCK';
        doc.status = 'DECIDED';
        doc.reasons = [{ code: 'INTERNAL_ERROR', riskDecision: 'BLOCK', message: 'The decision could not be audited; failing closed.', stage: 'decision' }];
        status = 500;
      }
      try {
        await store.investigations.insert(doc);
      } catch {
        throw new ApiError('INTERNAL_ERROR');
      }
      return { status, body: investigationOut(doc) };
    },
  };
}
